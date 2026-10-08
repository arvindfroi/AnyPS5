#ifndef CORE_FEX_SRC_GUESTCPU_HPP
#define CORE_FEX_SRC_GUESTCPU_HPP

#include <cstdint>
#include <memory>

namespace Aps5Fex {

class Bridge;
class GuestImage;

// FEXCore set up to run the guest's x86-64 code on this arm64 host, with the bridge as its syscall
// handler.
class GuestCpu {
public:
    GuestCpu(Bridge& bridge, const GuestImage& image);
    GuestCpu(const GuestCpu&) = delete;
    GuestCpu& operator=(const GuestCpu&) = delete;
    ~GuestCpu();

    // Runs guest code from rip with the given stack and thread pointer (the FS base) on the calling
    // thread until it halts, and returns its RAX.
    std::uint64_t Run(std::uint64_t rip, std::uint64_t rsp, std::uint64_t fs);

private:
    struct State;
    std::unique_ptr<State> state;
};

}

#endif
