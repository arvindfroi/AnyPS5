#include <cstdint>
#include <cstddef>
#include <cstring>
#include "SceTypes.hpp"
#include "prx/libc/include/General.hpp"

namespace {

constexpr int SCE_GAME_LIVE_STREAMING_ERROR_INVALID_PARAM = static_cast<int>(0x80A00002);
constexpr std::int32_t USER_ID_INVALID = -1;

}

struct GameLiveStreamingStatus2 {
    std::int32_t user_id;
    bool is_on_air;
    std::uint32_t spectator_count;
    std::uint32_t text_message_count;
    std::uint32_t command_message_count;
    std::uint32_t broadcast_video_resolution;
    std::uint8_t reserved[48];
};
static_assert(sizeof(GameLiveStreamingStatus2) == 72);

extern "C" {

int APS5_VABI sceGameLiveStreamingInitialize(size_t heap_size) {
    if (heap_size == 0) APS5_INVALID_ARG_EX;
    return 0;
}

int APS5_VABI sceGameLiveStreamingTerminate(void) {
    return 0;
}

int APS5_VABI sceGameLiveStreamingGetCurrentStatus2(GameLiveStreamingStatus2* status) {
    if (status == nullptr) return SCE_GAME_LIVE_STREAMING_ERROR_INVALID_PARAM;
    std::memset(status, 0, sizeof(*status));
    status->user_id = USER_ID_INVALID;
    return 0;
}

int APS5_VABI sceGameLiveStreamingGetProgramInfo() {
    NotImplemented_nid_no_patch(__func__);
    return 0;
}

}
