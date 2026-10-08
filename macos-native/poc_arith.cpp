#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/HostFeatures.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Utils/AllocatorHooks.h>
#include <FEXCore/Utils/DualMap.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>

namespace {

class NoSyscalls final : public FEXCore::HLE::SyscallHandler {
public:
  NoSyscalls() { OSABI = FEXCore::HLE::SyscallOSABI::OS_LINUX64; }
  uint64_t HandleSyscall(FEXCore::Core::CpuStateFrame*, FEXCore::HLE::SyscallArguments*) override { return static_cast<uint64_t>(-38); }
  FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(FEXCore::Core::InternalThreadState*, uint64_t) override {
    return {Base, Size, false};
  }
  std::optional<FEXCore::ExecutableFileSectionInfo> LookupExecutableFileSection(FEXCore::Core::InternalThreadState*, uint64_t) override {
    return std::nullopt;
  }
  uint64_t Base {};
  uint64_t Size {};
};

class Signals final : public FEXCore::SignalDelegator {};

constexpr size_t kPoolSize = size_t{1} << 30;
uint8_t* gPoolRx {};
std::atomic<size_t> gPoolUsed {};

bool CreateJitPool() {
  mach_vm_address_t rw = 0, rx = 0;
  if (mach_vm_allocate(mach_task_self(), &rw, kPoolSize, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) return false;
  vm_prot_t cur {}, max {};
  if (mach_vm_remap(mach_task_self(), &rx, kPoolSize, 0, VM_FLAGS_ANYWHERE, mach_task_self(), rw, FALSE, &cur, &max, VM_INHERIT_NONE) != KERN_SUCCESS) return false;
  if (mprotect(reinterpret_cast<void*>(rx), kPoolSize, PROT_READ | PROT_EXEC) != 0) return false;
  gPoolRx = reinterpret_cast<uint8_t*>(rx);
  FEXCore::DualMap::WriteOffset = static_cast<int64_t>(rw) - static_cast<int64_t>(rx);
  return true;
}

bool InPool(const void* address) {
  const auto* p = static_cast<const uint8_t*>(address);
  return gPoolRx && p >= gPoolRx && p < gPoolRx + kPoolSize;
}

void* PoolMmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset) {
  if ((prot & PROT_EXEC) == 0 || addr != nullptr) return ::mmap(addr, length, prot, flags, fd, offset);
  const size_t aligned = (length + 0x3FFF) & ~size_t{0x3FFF};
  const size_t start = gPoolUsed.fetch_add(aligned);
  if (start + aligned > kPoolSize) return MAP_FAILED;
  return gPoolRx + start;
}

int PoolMunmap(void* addr, size_t length) {
  if (InPool(addr)) return 0;
  return ::munmap(addr, length);
}

}

int main() {
  const unsigned char code[] = {
    0xB8, 0x2A, 0x00, 0x00, 0x00,             // mov eax, 42
    0x83, 0xC0, 0x10,                         // add eax, 16
    0x6B, 0xC0, 0x03,                         // imul eax, eax, 3      -> 174
    0x48, 0xC7, 0xC1, 0x0A, 0x00, 0x00, 0x00, // mov rcx, 10
    0x48, 0x01, 0xC8,                         // loop: add rax, rcx
    0x48, 0xFF, 0xC9,                         // dec rcx
    0x75, 0xF8,                               // jnz loop             -> 174 + 55 = 229
    0xF4,                                     // hlt
  };

  if (!CreateJitPool()) { std::puts("JIT pool setup failed"); return 1; }
  FEXCore::Allocator::mmap = PoolMmap;
  FEXCore::Allocator::munmap = PoolMunmap;

  FEXCore::Config::Initialize();
  FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, "1");
  FEXCore::Config::Load();
  FEXCore::Config::ReloadMetaLayer();

  FEXCore::HostFeatures features {};
  features.DCacheLineSize = 64;
  features.ICacheLineSize = 64;
  features.SupportsAtomics = true;
  features.SupportsRCPC = true;
  features.SupportsTSOImm9 = true;
  features.SupportsFlagM = true;
  features.SupportsFlagM2 = true;
  features.SupportsAES = true;
  features.SupportsPMULL_128Bit = true;
  features.SupportsFRINTTS = true;
  features.SupportsFCMA = true;
  features.SupportsAFP = true;
  features.SupportsCRC = true;

  auto ctx = FEXCore::Context::Context::CreateNewContext(features);
  NoSyscalls syscalls;
  Signals signals;
  ctx->SetSyscallHandler(&syscalls);
  ctx->SetSignalDelegator(&signals);
  ctx->EnableExitOnHLT();
  if (!ctx->InitCore()) { std::puts("InitCore failed"); return 1; }

  auto* guest = static_cast<unsigned char*>(mmap(nullptr, 0x10000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));
  std::memcpy(guest, code, sizeof(code));
  auto* stack = static_cast<unsigned char*>(mmap(nullptr, 0x100000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));
  syscalls.Base = reinterpret_cast<uint64_t>(guest);
  syscalls.Size = 0x10000;

  auto* thread = ctx->CreateThread(reinterpret_cast<uint64_t>(guest), reinterpret_cast<uint64_t>(stack) + 0x100000 - 64);
  using ThreadState = FEXCore::Core::InternalThreadState;
  constexpr size_t page = 0x4000;
  auto* callRet = static_cast<uint8_t*>(mmap(nullptr, ThreadState::CALLRET_STACK_SIZE + 2 * page, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0));
  thread->CallRetStackBase = callRet + page;
  mprotect(thread->CallRetStackBase, ThreadState::CALLRET_STACK_SIZE, PROT_READ | PROT_WRITE);
  thread->CurrentFrame->State.callret_sp = reinterpret_cast<uint64_t>(thread->CallRetStackBase) + ThreadState::CALLRET_DEFAULT_OFFSET;
  thread->CurrentFrame->State.callret_sp_base = reinterpret_cast<uint64_t>(thread->CallRetStackBase);

  using CPUState = FEXCore::Core::CPUState;
  static CPUState::gdt_segment gdt[32] {};
  auto& state = thread->CurrentFrame->State;
  state.segment_arrays[CPUState::SEGMENT_ARRAY_INDEX_GDT] = gdt;
  state.segment_arrays[CPUState::SEGMENT_ARRAY_INDEX_LDT] = gdt;
  state.cs_idx = CPUState::DEFAULT_USER_CS << 3;
  auto* cs = CPUState::GetSegmentFromIndex(state, state.cs_idx);
  CPUState::SetGDTBase(cs, 0);
  CPUState::SetGDTLimit(cs, 0xF'FFFFU);
  cs->L = 1;
  cs->D = 0;
  state.cs_cached = CPUState::CalculateGDTBase(*cs);

  ctx->ExecuteThread(thread);
  const auto rax = thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RAX];
  std::printf("x86-64 guest finished on the host CPU: RAX = %llu (expected 229)\n", static_cast<unsigned long long>(rax));
  return rax == 229 ? 0 : 2;
}
