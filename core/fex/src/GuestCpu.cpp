#include "GuestCpu.hpp"

#include "Bridge.hpp"
#include "GuestImage.hpp"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/HostFeatures.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Utils/AllocatorHooks.h>
#include <FEXCore/Utils/DualMap.h>
#include <FEXCore/Utils/LogManager.h>

#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdexcept>
#include <string>
#include <sys/mman.h>
#include <sys/sysctl.h>

namespace Aps5Fex {

namespace {

// macOS refuses memory that is writable and executable at once, so FEXCore writes its code through
// a writable alias of an executable pool.
constexpr std::size_t PoolSize = std::size_t {1} << 30;
std::uint8_t* poolCode = nullptr;
std::atomic<std::size_t> poolUsed {0};

void CreateCodePool() {
    mach_vm_address_t writable = 0;
    mach_vm_address_t executable = 0;
    if (mach_vm_allocate(mach_task_self(), &writable, PoolSize, VM_FLAGS_ANYWHERE) != KERN_SUCCESS)
        throw std::runtime_error("cannot allocate the JIT pool");
    vm_prot_t current {};
    vm_prot_t maximum {};
    if (mach_vm_remap(mach_task_self(), &executable, PoolSize, 0, VM_FLAGS_ANYWHERE, mach_task_self(), writable, FALSE, &current, &maximum,
                      VM_INHERIT_NONE) != KERN_SUCCESS ||
        mprotect(reinterpret_cast<void*>(executable), PoolSize, PROT_READ | PROT_EXEC) != 0)
        throw std::runtime_error("cannot map the JIT pool executable");
    poolCode = reinterpret_cast<std::uint8_t*>(executable);
    FEXCore::DualMap::WriteOffset = static_cast<std::int64_t>(writable) - static_cast<std::int64_t>(executable);
}

void* PoolMmap(void* address, std::size_t length, int protection, int flags, int file, off_t offset) {
    if ((protection & PROT_EXEC) == 0 || address != nullptr) return ::mmap(address, length, protection, flags, file, offset);
    const std::size_t aligned = (length + 0x3fff) & ~std::size_t {0x3fff};
    const std::size_t start = poolUsed.fetch_add(aligned);
    if (start + aligned > PoolSize) return MAP_FAILED;
    return poolCode + start;
}

int PoolMunmap(void* address, std::size_t length) {
    const auto* byte = static_cast<const std::uint8_t*>(address);
    if (poolCode != nullptr && byte >= poolCode && byte < poolCode + PoolSize) return 0;
    return ::munmap(address, length);
}

bool HasFeature(const char* name) {
    int value = 0;
    std::size_t size = sizeof(value);
    return sysctlbyname((std::string("hw.optional.arm.") + name).c_str(), &value, &size, nullptr, 0) == 0 && value != 0;
}

FEXCore::HostFeatures HostFeatures() {
    FEXCore::HostFeatures features {};
    features.DCacheLineSize = 64;
    features.ICacheLineSize = 64;
    features.SupportsAES = HasFeature("FEAT_AES");
    features.SupportsCRC = HasFeature("FEAT_CRC32");
    features.SupportsSHA = HasFeature("FEAT_SHA1") && HasFeature("FEAT_SHA256");
    features.SupportsAtomics = HasFeature("FEAT_LSE");
    features.SupportsRAND = HasFeature("FEAT_RNG");
    features.SupportsAFP = HasFeature("FEAT_AFP");
    features.SupportsRCPC = HasFeature("FEAT_LRCPC");
    features.SupportsTSOImm9 = HasFeature("FEAT_LRCPC2");
    features.SupportsPMULL_128Bit = HasFeature("FEAT_PMULL");
    features.SupportsCSSC = HasFeature("FEAT_CSSC");
    features.SupportsFCMA = HasFeature("FEAT_FCMA");
    features.SupportsFlagM = HasFeature("FEAT_FlagM");
    features.SupportsFlagM2 = HasFeature("FEAT_FlagM2");
    features.SupportsFRINTTS = HasFeature("FEAT_FRINTTS");
    features.SupportsRPRES = HasFeature("FEAT_RPRES");
    features.SupportsECV = HasFeature("FEAT_ECV");
    features.SupportsWFXT = HasFeature("FEAT_WFxT");
    features.SupportsMOPS = HasFeature("FEAT_MOPS");
    // AVX runs as pairs of 128-bit operations without SVE.
    features.SupportsAVX = true;
    features.SupportsAES256 = features.SupportsAES;
    return features;
}

void LogMessage(LogMan::DebugLevels level, const char* message) {
    if (level <= LogMan::ERROR) std::fprintf(stderr, "[FEXCore] %s\n", message);
}

void LogAssertion(const char* message) {
    std::fprintf(stderr, "[FEXCore] %s\n", message);
    std::abort();
}

class BridgeSyscalls final : public FEXCore::HLE::SyscallHandler {
public:
    BridgeSyscalls(Bridge& bridge, const GuestImage& image) : bridge(bridge), image(image) {
        // The Linux ABI hands the handler rax and rdi as its first arguments.
        OSABI = FEXCore::HLE::SyscallOSABI::OS_LINUX64;
    }

    std::uint64_t HandleSyscall(FEXCore::Core::CpuStateFrame* frame, FEXCore::HLE::SyscallArguments* arguments) override {
        return bridge.Call(arguments->Argument[0], arguments->Argument[1], frame->State.rip);
    }

    FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(FEXCore::Core::InternalThreadState*, std::uint64_t address) override {
        if (bridge.OwnsStub(address)) return {bridge.StubBase(), bridge.StubSize(), false};
        return {image.Start(), image.Size(), false};
    }

    std::optional<FEXCore::ExecutableFileSectionInfo> LookupExecutableFileSection(FEXCore::Core::InternalThreadState*, std::uint64_t) override {
        return std::nullopt;
    }

private:
    Bridge& bridge;
    const GuestImage& image;
};

class CallbackReturns final : public FEXCore::SignalDelegator {
public:
    explicit CallbackReturns(const Bridge& bridge) : bridge(bridge) {}

    std::uintptr_t GetThunkCallbackRET() const override { return bridge.CallbackReturn(); }

private:
    const Bridge& bridge;
};

}

struct GuestCpu::State {
    BridgeSyscalls syscalls;
    CallbackReturns returns;
    fextl::unique_ptr<FEXCore::Context::Context> context;
};

namespace {

struct GuestCode {
    std::uint64_t imageStart;
    std::uint64_t imageEnd;
    const Bridge* bridge;
};

GuestCode guestCode {};
thread_local FEXCore::Core::InternalThreadState* currentThread = nullptr;

bool IsGuestCode(std::uint64_t address) {
    return guestCode.bridge != nullptr &&
           ((address >= guestCode.imageStart && address < guestCode.imageEnd) || guestCode.bridge->OwnsStub(address));
}

}

}

extern "C" void Aps5GuestCallEntry();

// The registers a host call to a guest function was made with, as Aps5GuestCallEntry saves them;
// the result registers replace the first ones.
struct Aps5GuestCallFrame {
    std::uint64_t gpr[8];
    std::uint8_t vector[8][16];
};

// Runs the guest function at target on the arguments of a host call, on the calling thread's guest
// state, which is in the middle of the bridge call that led here.
extern "C" void Aps5RunGuestCall(std::uint64_t target, Aps5GuestCallFrame* frame) {
    using namespace FEXCore::X86State;
    auto* thread = Aps5Fex::currentThread;
    if (thread == nullptr) {
        std::fprintf(stderr, "[aps5-fex] a thread without guest state called guest code at %#llx\n", static_cast<unsigned long long>(target));
        std::abort();
    }
    auto& state = thread->CurrentFrame->State;
    const std::uint64_t rip = state.rip;
    std::uint64_t gregs[16];
    std::memcpy(gregs, state.gregs, sizeof(gregs));
    std::uint64_t xmm[16][2];
    std::memcpy(xmm, state.xmm.sse.data, sizeof(xmm));

    // The seventh and eighth integer arguments go on the guest stack, above the return address the
    // callback adds, with the stack aligned as after a call.
    const std::uint64_t top = ((state.gregs[REG_RSP] - 32) & ~std::uint64_t {15}) + 8;
    std::memcpy(reinterpret_cast<void*>(top - 8), &frame->gpr[6], 16);
    state.gregs[REG_RSP] = top;
    state.gregs[REG_RDI] = frame->gpr[0];
    state.gregs[REG_RSI] = frame->gpr[1];
    state.gregs[REG_RDX] = frame->gpr[2];
    state.gregs[REG_RCX] = frame->gpr[3];
    state.gregs[REG_R8] = frame->gpr[4];
    state.gregs[REG_R9] = frame->gpr[5];
    std::memcpy(state.xmm.sse.data, frame->vector, sizeof(frame->vector));
    thread->CTX->HandleCallback(thread, target);
    frame->gpr[0] = state.gregs[REG_RAX];
    frame->gpr[1] = state.gregs[REG_RDX];
    std::memcpy(frame->vector, state.xmm.sse.data, 2 * sizeof(frame->vector[0]));

    std::memcpy(state.gregs, gregs, sizeof(gregs));
    std::memcpy(state.xmm.sse.data, xmm, sizeof(xmm));
    state.rip = rip;
}

namespace Aps5Fex {

namespace {

// Guest code is never host executable, so a host call to a guest function faults on its first
// instruction; the call continues in Aps5GuestCallEntry instead.
void OnFault(int signal, siginfo_t* info, void* context) {
    auto* machine = static_cast<ucontext_t*>(context)->uc_mcontext;
    const std::uint64_t pc = arm_thread_state64_get_pc(machine->__ss);
    if (IsGuestCode(pc) && reinterpret_cast<std::uint64_t>(info->si_addr) == pc) {
        machine->__ss.__x[16] = pc;
        arm_thread_state64_set_pc_fptr(machine->__ss, &Aps5GuestCallEntry);
        return;
    }
    std::signal(signal, SIG_DFL);
}

void InstallFaultHandler() {
    struct sigaction action {};
    action.sa_sigaction = OnFault;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    sigaction(SIGBUS, &action, nullptr);
    sigaction(SIGSEGV, &action, nullptr);
}

}

GuestCpu::GuestCpu(Bridge& bridge, const GuestImage& image) {
    LogMan::Msg::InstallHandler(LogMessage);
    LogMan::Throw::InstallHandler(LogAssertion);
    CreateCodePool();
    FEXCore::Allocator::mmap = PoolMmap;
    FEXCore::Allocator::munmap = PoolMunmap;
    FEXCore::Config::Initialize();
    FEXCore::Config::Load();
    FEXCore::Config::ReloadMetaLayer();
    // After the reload, which rebuilds the layer this sets.
    FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, "1");

    state.reset(new State {BridgeSyscalls(bridge, image), CallbackReturns(bridge), FEXCore::Context::Context::CreateNewContext(HostFeatures())});
    state->context->SetSyscallHandler(&state->syscalls);
    state->context->SetSignalDelegator(&state->returns);
    state->context->EnableExitOnHLT();
    if (!state->context->InitCore()) throw std::runtime_error("FEXCore failed to initialise");
    guestCode = {image.Start(), image.Start() + image.Size(), &bridge};
    InstallFaultHandler();
}

GuestCpu::~GuestCpu() {
    guestCode = {};
}

std::uint64_t GuestCpu::Run(std::uint64_t rip, std::uint64_t rsp, std::uint64_t fs) {
    using ThreadState = FEXCore::Core::InternalThreadState;
    using CPUState = FEXCore::Core::CPUState;
    ThreadState* thread = state->context->CreateThread(rip, rsp);

    constexpr std::size_t Page = 0x4000;
    auto* callRet = static_cast<std::uint8_t*>(mmap(nullptr, ThreadState::CALLRET_STACK_SIZE + 2 * Page, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0));
    if (callRet == MAP_FAILED) throw std::runtime_error("cannot allocate the call-return stack");
    thread->CallRetStackBase = callRet + Page;
    mprotect(thread->CallRetStackBase, ThreadState::CALLRET_STACK_SIZE, PROT_READ | PROT_WRITE);
    auto& guest = thread->CurrentFrame->State;
    guest.callret_sp = reinterpret_cast<std::uint64_t>(thread->CallRetStackBase) + ThreadState::CALLRET_DEFAULT_OFFSET;
    guest.callret_sp_base = reinterpret_cast<std::uint64_t>(thread->CallRetStackBase);

    // A flat 64-bit code segment, as a Linux process has.
    auto* gdt = new CPUState::gdt_segment[32] {};
    guest.segment_arrays[CPUState::SEGMENT_ARRAY_INDEX_GDT] = gdt;
    guest.segment_arrays[CPUState::SEGMENT_ARRAY_INDEX_LDT] = gdt;
    guest.cs_idx = CPUState::DEFAULT_USER_CS << 3;
    auto* code = CPUState::GetSegmentFromIndex(guest, guest.cs_idx);
    CPUState::SetGDTBase(code, 0);
    CPUState::SetGDTLimit(code, 0xfffffU);
    code->L = 1;
    code->D = 0;
    guest.cs_cached = CPUState::CalculateGDTBase(*code);
    guest.fs_cached = fs;

    currentThread = thread;
    state->context->ExecuteThread(thread);
    currentThread = nullptr;
    return thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RAX];
}

}
