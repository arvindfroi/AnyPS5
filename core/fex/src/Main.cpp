// Runs a relinked PS5 executable (the relinker's Linux output) on arm64 macOS: FEXCore translates
// the guest's x86-64 code, and its imports call the HLE libraries in libs/ next to it natively.
//
//     aps5-fex <executable> [arguments...]

#include "Bridge.hpp"
#include "GuestCpu.hpp"
#include "GuestImage.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <string>
#include <sys/mman.h>
#include <vector>

namespace {

using namespace Aps5Fex;

constexpr std::size_t GuestStackSize = std::size_t {8} << 20;

std::uint64_t AlignUp(std::uint64_t value, std::uint64_t alignment) {
    return (value + alignment - 1) / alignment * alignment;
}

// The main thread's thread pointer: the executable's TLS block directly below a control block whose
// first word points at itself and whose word at 0x28 is the stack guard, as the guest's code expects
// from FS.
std::uint64_t CreateThreadPointer(const GuestImage& image) {
    constexpr std::size_t ControlBlock = 0x100;
    const GuestTlsTemplate& tls = image.Tls();
    const std::size_t alignment = std::max<std::size_t>(tls.alignment, 64);
    const std::size_t block = AlignUp(tls.memorySize, alignment);
    void* memory = nullptr;
    if (posix_memalign(&memory, alignment, block + ControlBlock) != 0) throw std::bad_alloc();
    std::memset(memory, 0, block + ControlBlock);
    auto* pointer = static_cast<std::uint8_t*>(memory) + block;
    if (tls.fileSize != 0) std::memcpy(pointer - block, reinterpret_cast<const void*>(image.Base() + tls.address), tls.fileSize);
    const auto self = reinterpret_cast<std::uint64_t>(pointer);
    std::memcpy(pointer, &self, sizeof(self));
    std::uint64_t guard = 0;
    arc4random_buf(&guard, sizeof(guard));
    std::memcpy(pointer + 0x28, &guard, sizeof(guard));
    return self;
}

// A stack whose top holds argc, the argument pointers, an empty environment and an empty auxiliary
// vector, which is what the entry stub hands the guest's _start.
std::uint64_t CreateProcessStack(const std::vector<std::string>& arguments) {
    void* memory = mmap(nullptr, GuestStackSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (memory == MAP_FAILED) throw std::runtime_error("cannot allocate the guest stack");
    auto top = reinterpret_cast<std::uint64_t>(memory) + GuestStackSize;
    std::vector<std::uint64_t> pointers;
    for (const auto& argument : arguments) {
        top -= argument.size() + 1;
        std::memcpy(reinterpret_cast<void*>(top), argument.c_str(), argument.size() + 1);
        pointers.push_back(top);
    }
    std::vector<std::uint64_t> words {arguments.size()};
    words.insert(words.end(), pointers.begin(), pointers.end());
    words.insert(words.end(), {0, 0, 0, 0});
    top = (top - words.size() * sizeof(std::uint64_t)) & ~std::uint64_t {15};
    std::memcpy(reinterpret_cast<void*>(top), words.data(), words.size() * sizeof(std::uint64_t));
    return top;
}

}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <relinked executable> [arguments...]\n", argv[0]);
        return 2;
    }
    try {
        const auto executable = std::filesystem::absolute(argv[1]);
        GuestImage image(executable);
        Bridge bridge(executable.parent_path() / "libs");
        bridge.Open("libkernel.prx");
        bridge.Open("libc.prx");
        for (const auto& name : image.Needed()) bridge.Open(name);
        image.Relocate([&bridge](const std::string& name, bool weak) { return bridge.Resolve(name, weak); });
        if (!bridge.Missing().empty()) {
            for (const auto& name : bridge.Missing()) std::fprintf(stderr, "[aps5-fex] no library exports %s\n", name.c_str());
        }
        const std::uint64_t fs = CreateThreadPointer(image);
        const std::uint64_t rsp = CreateProcessStack(std::vector<std::string>(argv + 1, argv + argc));
        GuestCpu cpu(bridge, image);
        const std::uint64_t rax = cpu.Run(image.Entry(), rsp, fs);
        std::fprintf(stderr, "[aps5-fex] the guest halted with RAX %#llx\n", static_cast<unsigned long long>(rax));
        return 1;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "[aps5-fex] %s\n", error.what());
        return 1;
    }
}
