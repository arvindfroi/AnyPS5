#include "Bridge.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <exception>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <stdexcept>
#include <string_view>
#include <sys/mman.h>

// The argument and result registers of a native call, laid out as Trampolines.S reads them.
struct Aps5NativeArguments {
    std::uint64_t gpr[8];
    std::uint8_t vector[8][16];
    const std::uint64_t* stack;
    std::uint64_t stackSlots;
};
static_assert(offsetof(Aps5NativeArguments, vector) == 64 && offsetof(Aps5NativeArguments, stack) == 192 &&
              offsetof(Aps5NativeArguments, stackSlots) == 200);

struct Aps5NativeResult {
    std::uint64_t gpr[2];
    std::uint8_t vector[2][16];
};
static_assert(offsetof(Aps5NativeResult, vector) == 16);

extern "C" void Aps5NativeCall(const void* target, const Aps5NativeArguments* arguments, Aps5NativeResult* result);

namespace Aps5Fex {

namespace {

// The block the trampoline stores on the guest stack: rdi, rsi, rdx, rcx, r8 and r9, then xmm0 to
// xmm7, which is the layout of a System V register save area. The results replace rdi and rsi (rax,
// rdx) and xmm0 and xmm1. The caller's stack arguments follow the block and the stub's return address.
constexpr std::size_t BlockSize = 0xb8;
constexpr std::size_t BlockVectors = 0x30;

// The guest stack words after the seventh and eighth integer arguments that are passed on, as an
// AAPCS64 callee expects them for 8-byte arguments.
constexpr std::uint64_t StackArgumentSlots = 8;

// A System V x86-64 va_list.
#pragma pack(push, 1)
struct VaList {
    std::uint32_t gpOffset;
    std::uint32_t fpOffset;
    void* overflowArea;
    void* registerSaveArea;
};
#pragma pack(pop)
static_assert(sizeof(VaList) == 24);

struct VariadicExport {
    std::string_view name;
    std::uint8_t kind;
    std::uint8_t fixed;
};

constexpr std::uint8_t GuestList = 1;
constexpr std::uint8_t Integers = 2;
constexpr std::uint8_t Unsupported = 3;

// The libraries' variadic functions by their names before NID patching, and their fixed integer
// arguments.
constexpr VariadicExport VariadicExports[] = {
    {"asprintf_nid_postfix", GuestList, 2},
    {"fprintf_nid_postfix", GuestList, 2},
    {"fscanf_nid_postfix", GuestList, 2},
    {"libc_printf_nid_postfix", GuestList, 1},
    {"printf_nid_postfix", GuestList, 1},
    {"printf_s_nid_postfix", GuestList, 1},
    {"snprintf_nid_postfix", GuestList, 3},
    {"snprintf_s_nid_postfix", GuestList, 3},
    {"snwprintf_s_nid_postfix", GuestList, 3},
    {"sprintf_nid_postfix", GuestList, 2},
    {"sprintf_s_nid_postfix", GuestList, 3},
    {"sscanf_nid_postfix", GuestList, 2},
    {"sscanf_s_nid_postfix", GuestList, 2},
    {"wprintf_nid_postfix", GuestList, 1},
    {"_open_nid_postfix", Integers, 2},
    {"fcntl_nid_postfix", Integers, 2},
    // Formats the host's 32-bit wchar_t from the host's arguments.
    {"swprintf_nid_postfix", Unsupported, 3},
};

// The libraries' functions that return the guest's long double, as x87 bits in x0 and x1.
constexpr std::string_view X87Results[] = {"strtold_nid_postfix", "wcstold_nid_postfix"};

// sub rsp, 0xb8; store the argument registers; mov rdi, rsp; syscall; load the result registers;
// add rsp, 0xb8; ret
constexpr std::uint8_t Trampoline[] = {
    0x48, 0x81, 0xec, 0xb8, 0x00, 0x00, 0x00,
    0x48, 0x89, 0x3c, 0x24,
    0x48, 0x89, 0x74, 0x24, 0x08,
    0x48, 0x89, 0x54, 0x24, 0x10,
    0x48, 0x89, 0x4c, 0x24, 0x18,
    0x4c, 0x89, 0x44, 0x24, 0x20,
    0x4c, 0x89, 0x4c, 0x24, 0x28,
    0xf3, 0x0f, 0x7f, 0x44, 0x24, 0x30,
    0xf3, 0x0f, 0x7f, 0x4c, 0x24, 0x40,
    0xf3, 0x0f, 0x7f, 0x54, 0x24, 0x50,
    0xf3, 0x0f, 0x7f, 0x5c, 0x24, 0x60,
    0xf3, 0x0f, 0x7f, 0x64, 0x24, 0x70,
    0xf3, 0x0f, 0x7f, 0xac, 0x24, 0x80, 0x00, 0x00, 0x00,
    0xf3, 0x0f, 0x7f, 0xb4, 0x24, 0x90, 0x00, 0x00, 0x00,
    0xf3, 0x0f, 0x7f, 0xbc, 0x24, 0xa0, 0x00, 0x00, 0x00,
    0x48, 0x89, 0xe7,
    0x0f, 0x05,
    // Where the x87 variant, which loads st(0) instead, differs.
    0x48, 0x8b, 0x04, 0x24,
    0x48, 0x8b, 0x54, 0x24, 0x08,
    0xf3, 0x0f, 0x6f, 0x44, 0x24, 0x30,
    0xf3, 0x0f, 0x6f, 0x4c, 0x24, 0x40,
    0x48, 0x81, 0xc4, 0xb8, 0x00, 0x00, 0x00,
    0xc3,
};

constexpr std::size_t TrampolineCall = 98;

// fld tword [rsp]; add rsp, 0xb8; ret
constexpr std::uint8_t X87Epilogue[] = {0xdb, 0x2c, 0x24, 0x48, 0x81, 0xc4, 0xb8, 0x00, 0x00, 0x00, 0xc3};

}

Bridge::Bridge(std::filesystem::path libraries) : directory(std::move(libraries)), trace(std::getenv("APS5_FEX_TRACE") != nullptr) {
    void* memory = mmap(nullptr, StubSize(), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (memory == MAP_FAILED) throw std::runtime_error("cannot allocate the import stubs");
    stubs = static_cast<std::uint8_t*>(memory);
    static_assert(Trampoline[TrampolineCall - 2] == 0x0f && Trampoline[TrampolineCall - 1] == 0x05);
    static_assert(TrampolineOffset + sizeof(Trampoline) <= X87TrampolineOffset);
    static_assert(X87TrampolineOffset + TrampolineCall + sizeof(X87Epilogue) <= FirstStubOffset);
    std::memset(stubs, 0xcc, FirstStubOffset);
    stubs[0] = 0x0f;
    stubs[1] = 0x3e;
    std::memcpy(stubs + TrampolineOffset, Trampoline, sizeof(Trampoline));
    std::memcpy(stubs + X87TrampolineOffset, Trampoline, TrampolineCall);
    std::memcpy(stubs + X87TrampolineOffset + TrampolineCall, X87Epilogue, sizeof(X87Epilogue));
}

Bridge::~Bridge() {
    munmap(stubs, StubSize());
}

void Bridge::Open(const std::string& name) {
    const auto path = directory / name;
    std::error_code error;
    const auto canonical = std::filesystem::canonical(path, error);
    if (error) throw std::runtime_error("missing library " + path.string());
    void* handle = dlopen(canonical.c_str(), RTLD_NOW | RTLD_GLOBAL);
    if (handle == nullptr) throw std::runtime_error(std::string("cannot load ") + canonical.string() + ": " + dlerror());
    if (std::find(handles.begin(), handles.end(), handle) != handles.end()) return;
    handles.push_back(handle);
    for (std::uint32_t i = 0; i < _dyld_image_count(); ++i) {
        const char* image = _dyld_get_image_name(i);
        std::error_code ignored;
        if (image != nullptr && std::filesystem::equivalent(image, canonical, ignored))
            images.push_back(reinterpret_cast<const mach_header_64*>(_dyld_get_image_header(i)));
    }
}

std::uint64_t Bridge::AddStub(void* address, const std::string& name, Variadic variadic, std::uint8_t fixed, bool x87Result) {
    if (FirstStubOffset + (functions.size() + 1) * StubBytes > StubSize()) throw std::runtime_error("too many imported functions");
    const auto number = static_cast<std::uint32_t>(FirstStub + functions.size());
    std::uint8_t* stub = stubs + FirstStubOffset + functions.size() * StubBytes;
    // mov eax, number; jmp trampoline
    const auto target = static_cast<std::int32_t>(x87Result ? X87TrampolineOffset : TrampolineOffset);
    const auto jump = target - static_cast<std::int32_t>(stub + 10 - stubs);
    const std::uint8_t code[] = {0xb8, static_cast<std::uint8_t>(number), static_cast<std::uint8_t>(number >> 8), static_cast<std::uint8_t>(number >> 16),
        static_cast<std::uint8_t>(number >> 24), 0xe9, static_cast<std::uint8_t>(jump), static_cast<std::uint8_t>(jump >> 8),
        static_cast<std::uint8_t>(jump >> 16), static_cast<std::uint8_t>(jump >> 24)};
    std::memset(stub, 0xcc, StubBytes);
    std::memcpy(stub, code, sizeof(code));
    functions.push_back({address, name, variadic, fixed, x87Result});
    return reinterpret_cast<std::uint64_t>(stub);
}

std::uint64_t Bridge::Resolve(const std::string& name, bool weak) {
    if (const auto found = resolved.find(name); found != resolved.end()) return found->second;
    for (void* handle : handles) {
        void* address = dlsym(handle, name.c_str());
        Dl_info info;
        if (address == nullptr || dladdr(address, &info) == 0) continue;
        const auto* image = static_cast<const mach_header_64*>(info.dli_fbase);
        if (std::find(images.begin(), images.end(), image) == images.end()) continue;
        unsigned long textSize = 0;
        const auto* text = getsectiondata(image, "__TEXT", "__text", &textSize);
        const auto* byte = static_cast<const std::uint8_t*>(address);
        const bool function = text != nullptr && byte >= text && byte < text + textSize;
        std::uint64_t guest = reinterpret_cast<std::uint64_t>(address);
        if (function) {
            Variadic variadic = Variadic::None;
            std::uint8_t fixed = 0;
            for (const auto& entry : VariadicExports) {
                if (info.dli_sname != nullptr && entry.name == info.dli_sname && info.dli_saddr == address) {
                    variadic = static_cast<Variadic>(entry.kind);
                    fixed = entry.fixed;
                }
            }
            if (variadic == Variadic::GuestList && setBridgeVaList == nullptr) {
                for (void* library : handles)
                    if (auto* setter = dlsym(library, "Aps5SetBridgeVaList_nid_no_patch")) setBridgeVaList = reinterpret_cast<void (*)(void*)>(setter);
                if (setBridgeVaList == nullptr) throw std::runtime_error("libc has no Aps5SetBridgeVaList_nid_no_patch");
            }
            const bool x87Result = info.dli_sname != nullptr && info.dli_saddr == address &&
                std::find(std::begin(X87Results), std::end(X87Results), info.dli_sname) != std::end(X87Results);
            guest = AddStub(address, name, variadic, fixed, x87Result);
        }
        resolved.emplace(name, guest);
        return guest;
    }
    if (weak) return 0;
    missing.push_back(name);
    const std::uint64_t guest = AddStub(nullptr, name);
    resolved.emplace(name, guest);
    return guest;
}

std::uint64_t Bridge::Call(std::uint64_t number, std::uint64_t block, std::uint64_t rip) {
    if (number < FirstStub || number - FirstStub >= functions.size()) {
        std::fprintf(stderr, "[aps5-fex] guest syscall %llu at %#llx is not supported\n", static_cast<unsigned long long>(number),
                     static_cast<unsigned long long>(rip));
        return static_cast<std::uint64_t>(-ENOSYS);
    }
    const Function& function = functions[number - FirstStub];
    if (function.address == nullptr) {
        std::fprintf(stderr, "[aps5-fex] the guest called %s, which no library exports\n", function.name.c_str());
        std::abort();
    }
    auto* registers = reinterpret_cast<std::uint64_t*>(block);
    const auto* stack = reinterpret_cast<const std::uint64_t*>(block + BlockSize + 8);
    if (trace) {
        std::fprintf(stderr, "[aps5-fex] %s(%#llx, %#llx, %#llx, %#llx, %#llx, %#llx)\n", function.name.c_str(),
                     static_cast<unsigned long long>(registers[0]), static_cast<unsigned long long>(registers[1]),
                     static_cast<unsigned long long>(registers[2]), static_cast<unsigned long long>(registers[3]),
                     static_cast<unsigned long long>(registers[4]), static_cast<unsigned long long>(registers[5]));
    }
    Aps5NativeArguments arguments {
        {registers[0], registers[1], registers[2], registers[3], registers[4], registers[5], stack[0], stack[1]},
        {},
        stack + 2,
        StackArgumentSlots,
    };
    std::memcpy(arguments.vector, reinterpret_cast<const void*>(block + BlockVectors), sizeof(arguments.vector));
    // The guest's variadic arguments, for a function that takes them as a guest list: the integer ones
    // after the fixed ones in the block, the vector ones from xmm0, then the caller's stack arguments.
    VaList list {static_cast<std::uint32_t>(8 * function.fixed), 48, const_cast<std::uint64_t*>(stack), registers};
    // For a function that takes them as integers: the integer registers after the fixed ones, then the
    // caller's stack arguments, each in a stack slot.
    std::uint64_t slots[6 + StackArgumentSlots];
    switch (function.variadic) {
    case Variadic::None: break;
    case Variadic::GuestList: setBridgeVaList(&list); break;
    case Variadic::Integers:
        std::memcpy(slots, registers + function.fixed, (6 - function.fixed) * sizeof(std::uint64_t));
        std::memcpy(slots + 6 - function.fixed, stack, StackArgumentSlots * sizeof(std::uint64_t));
        arguments.stack = slots;
        arguments.stackSlots = 6 - function.fixed + StackArgumentSlots;
        break;
    case Variadic::Unsupported:
        std::fprintf(stderr, "[aps5-fex] %s: its variadic arguments cannot be bridged\n", function.name.c_str());
        std::abort();
    }
    Aps5NativeResult result {};
    try {
        Aps5NativeCall(function.address, &arguments, &result);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "[aps5-fex] %s: %s\n", function.name.c_str(), error.what());
        std::abort();
    }
    if (function.variadic == Variadic::GuestList) setBridgeVaList(nullptr);
    registers[0] = result.gpr[0];
    registers[1] = result.gpr[1];
    std::memcpy(reinterpret_cast<void*>(block + BlockVectors), result.vector, sizeof(result.vector));
    return result.gpr[0];
}

}
