#include <atomic>
#include <cstdint>
#include <stdexcept>
#include <string>
#include "prx/libc/include/General.hpp"

namespace {

constexpr std::int32_t SCE_NP_PARTNER_ERROR_NOT_INITIALIZED = static_cast<std::int32_t>(0x819D0001);

std::atomic<bool> g_eaAccessInitialized{false};

}

extern "C" {

std::int32_t APS5_VABI sceNpEAAccessInitialize(void) {
    bool expected = false;
    if (!g_eaAccessInitialized.compare_exchange_strong(expected, true)) throw std::logic_error(std::string(__func__) + ": already initialized");
    return 0;
}

std::int32_t APS5_VABI sceNpEAAccessTerminate(void) {
    bool expected = true;
    if (!g_eaAccessInitialized.compare_exchange_strong(expected, false)) return SCE_NP_PARTNER_ERROR_NOT_INITIALIZED;
    return 0;
}

}
