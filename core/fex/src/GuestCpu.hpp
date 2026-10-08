#ifndef CORE_FEX_SRC_GUESTCPU_HPP
#define CORE_FEX_SRC_GUESTCPU_HPP

#include <cstdint>
#include <memory>

namespace Aps5Fex {

class Bridge;
class GuestImage;

// FEXCore set up to run the guest's x86-64 code on this arm64 host, with the bridge as its syscall
// handler. Every host thread that runs guest code has its own guest state, stack and TLS block; a
// thread the guest did not start here, such as one a library created, gets them when it first calls
// guest code, and gives them back when it ends.
class GuestCpu {
public:
    GuestCpu(Bridge& bridge, const GuestImage& image);
    GuestCpu(const GuestCpu&) = delete;
    GuestCpu& operator=(const GuestCpu&) = delete;
    ~GuestCpu();

    // Runs guest code from rip with the given stack on the calling thread until it halts, and returns
    // its RAX.
    std::uint64_t Run(std::uint64_t rip, std::uint64_t rsp);

private:
    struct State;
    std::unique_ptr<State> state;
};

}

#endif
