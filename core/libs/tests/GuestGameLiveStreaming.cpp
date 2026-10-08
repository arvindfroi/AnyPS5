#include "prx/libc/include/general/VabiMacros.hpp"
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
int APS5_VABI sceGameLiveStreamingGetCurrentStatus2(void* status);
}

namespace {

void Require(bool value) { if (!value) std::abort(); }

constexpr int kErrInvalidParam = static_cast<int>(0x80A00002);

}

int main() {
    std::uint8_t status[80];
    std::memset(status, 0x5a, sizeof(status));
    Require(sceGameLiveStreamingGetCurrentStatus2(status) == 0);
    std::int32_t userId = 0;
    std::memcpy(&userId, status, sizeof(userId));
    Require(userId == -1);
    for (std::size_t index = 4; index < sizeof(status); ++index) Require(status[index] == (index < 72 ? 0 : 0x5a));
    Require(sceGameLiveStreamingGetCurrentStatus2(nullptr) == kErrInvalidParam);
}
