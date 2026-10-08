#ifndef CORE_FEX_SRC_BRIDGE_HPP
#define CORE_FEX_SRC_BRIDGE_HPP

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>

struct mach_header_64;

namespace FEXCore::Core {
struct CPUState;
}

namespace Aps5Fex {

// The HLE libraries, arm64 Mach-O images named *.prx, and the x86-64 stubs through which guest code
// calls their functions. A stub loads its number into eax and jumps to a common trampoline, which
// stores the argument registers in a block on the guest stack and executes syscall with the block in
// rdi; Call() runs the library function with the System V arguments moved to their AAPCS64 places and
// leaves the result registers in the block, from which the trampoline loads them. The registers go
// through memory because FEXCore does not always write registers that the syscall's own block set to
// the guest state before it calls the handler.
class Bridge {
public:
    explicit Bridge(std::filesystem::path libraries);
    Bridge(const Bridge&) = delete;
    Bridge& operator=(const Bridge&) = delete;
    ~Bridge();

    void Open(const std::string& name);

    // The address guest code uses for an imported name: a library variable itself, or the stub of a
    // library function. A name no library exports gets a stub that stops the program when called;
    // it is listed in Missing(). Returns 0 for such a name when weak.
    std::uint64_t Resolve(const std::string& name, bool weak);
    const std::vector<std::string>& Missing() const { return missing; }

    // Where guest code returns to the host after a call the host made: FEXCore's reserved callback
    // return instruction, at the start of the stubs.
    std::uint64_t CallbackReturn() const { return StubBase(); }

    std::uint64_t StubBase() const { return reinterpret_cast<std::uint64_t>(stubs); }
    std::size_t StubSize() const { return StubCapacity * StubBytes; }
    bool OwnsStub(std::uint64_t address) const { return address >= StubBase() && address < StubBase() + StubSize(); }

    // Handles the syscall a guest thread made at rip, with rax number and rdi block, and returns its
    // RAX.
    std::uint64_t Call(std::uint64_t number, std::uint64_t block, std::uint64_t rip);

private:
    struct Function {
        void* address;
        std::string name;
    };

    static constexpr std::size_t StubBytes = 16;
    static constexpr std::size_t StubCapacity = 0x10000;
    static constexpr std::size_t TrampolineOffset = 0x10;
    static constexpr std::size_t FirstStubOffset = 0x100;
    static constexpr std::uint32_t FirstStub = 0x41500000;

    std::uint64_t AddStub(void* address, const std::string& name);

    std::filesystem::path directory;
    std::vector<void*> handles;
    std::vector<const mach_header_64*> images;
    std::vector<Function> functions;
    std::unordered_map<std::string, std::uint64_t> resolved;
    std::vector<std::string> missing;
    std::uint8_t* stubs = nullptr;
    bool trace = false;
};

}

#endif
