#include "prx/libc/include/general/VabiMacros.hpp"
#include <cstdint>
#include <cstdlib>

extern "C" {
std::int32_t APS5_VABI sceNpEAAccessInitialize(void);
std::int32_t APS5_VABI sceNpEAAccessTerminate(void);
}

namespace {

void Require(bool value) { if (!value) std::abort(); }

constexpr std::int32_t kErrNotInitialized = static_cast<std::int32_t>(0x819D0001);

}

int main() {
    Require(sceNpEAAccessTerminate() == kErrNotInitialized);
    Require(sceNpEAAccessInitialize() == 0);
    Require(sceNpEAAccessTerminate() == 0);
    Require(sceNpEAAccessTerminate() == kErrNotInitialized);
    Require(sceNpEAAccessInitialize() == 0);
    Require(sceNpEAAccessTerminate() == 0);
}
