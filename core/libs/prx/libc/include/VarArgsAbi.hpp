#ifndef CORE_LIBS_PRX_LIBC_INCLUDE_EXCEPTIONS_VARARGSABI_HPP
#define CORE_LIBS_PRX_LIBC_INCLUDE_EXCEPTIONS_VARARGSABI_HPP

#include <cstdarg>
#include <cstdint>
#include "SceTypes.hpp"

namespace LibcDetail {

#if defined(__aarch64__) && defined(__APPLE__)
// Apple's arm64 ABI passes every variadic argument on the stack in its own 8-byte slot,
// the layout of the System V overflow area, so a guest list with no register arguments
// left reads them in place.
inline VaList GuestVaList(std::va_list host) {
    return VaList{6u * 8u, 6u * 8u + 8u * 16u, host, nullptr};
}
#endif

}

// The guest's va_list is the System V x86-64 one. Only on x86-64 outside Windows is it
// also the host's, so that the host's formatting functions can read a guest list.
#if defined(__x86_64__) && !defined(_WIN32)
#define APS5_GUEST_VA_LIST_IS_HOST 1
#else
#define APS5_GUEST_VA_LIST_IS_HOST 0
#endif

// Starts args, a guest va_list over the variadic arguments that follow last.
#if defined(_WIN32)
#define APS5_VA_BEGIN(last) __builtin_sysv_va_list args; __builtin_sysv_va_start(args, last)
#define APS5_VA_END() __builtin_sysv_va_end(args)
#elif defined(__aarch64__) && defined(__APPLE__)
#define APS5_VA_BEGIN(last) std::va_list hostArgs; va_start(hostArgs, last); \
    VaList guestArgs = LibcDetail::GuestVaList(hostArgs); VaList* args = &guestArgs
#define APS5_VA_END() va_end(hostArgs)
#else
#define APS5_VA_BEGIN(last) std::va_list args; va_start(args, last)
#define APS5_VA_END() va_end(args)
#endif

#endif
