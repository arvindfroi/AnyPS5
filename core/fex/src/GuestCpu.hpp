#ifndef CORE_FEX_SRC_GUESTCPU_HPP
#define CORE_FEX_SRC_GUESTCPU_HPP

#include <cstdint>
#include <memory>
#include <vector>

namespace Aps5Fex {

class Bridge;
class GuestProgram;

// Calls a function the guest gave a library, such as a qsort comparator, with six integer arguments and
// gives its integer result: guest code runs on the calling thread's guest state without the fault that
// a host call to it takes, and a host function is called directly.
std::uint64_t CallGuestFunction(std::uint64_t target, const std::uint64_t* arguments);

// FEXCore set up to run the guest's x86-64 code on this arm64 host, with the bridge as its syscall
// handler. Every host thread that runs guest code has its own guest state, stack and TLS block; a
// thread the guest did not start here, such as one a library created, gets them when it first calls
// guest code, and gives them back when it ends.
class GuestCpu {
public:
    GuestCpu(Bridge& bridge, const GuestProgram& program);
    GuestCpu(const GuestCpu&) = delete;
    GuestCpu& operator=(const GuestCpu&) = delete;
    ~GuestCpu();

    // Runs the initializers, then guest code from rip with the given stack, on the calling thread
    // until it halts, and returns its RAX.
    std::uint64_t Run(std::uint64_t rip, std::uint64_t rsp, const std::vector<std::uint64_t>& initializers);

    // Starts the program on a thread of its own through libkernel's Aps5StartGuest, which keeps this
    // one, the main thread, in its run loop for AppKit: the initializers run there, then start(block,
    // 0). The guest ends the process with exit().
    [[noreturn]] void Start(Bridge& bridge, std::uint64_t start, std::uint64_t block, std::vector<std::uint64_t> initializers);

private:
    struct State;
    std::unique_ptr<State> state;
};

}

#endif
