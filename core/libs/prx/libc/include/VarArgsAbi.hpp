#ifndef CORE_LIBS_PRX_LIBC_INCLUDE_EXCEPTIONS_VARARGSABI_HPP
#define CORE_LIBS_PRX_LIBC_INCLUDE_EXCEPTIONS_VARARGSABI_HPP

#include <cstdarg>
#include <cstdint>
#include "SceTypes.hpp"

#if defined(__aarch64__) && defined(__APPLE__)
// Where guest code runs through FEXCore, its call to a variadic function arrives with the arguments
// still in a guest list, which the bridge sets for the calling thread just before the call. Returns
// that list, once, or host when there is none.
extern "C" VaList* Aps5TakeBridgeVaList_nid_no_patch(VaList* host);
#endif

namespace LibcDetail {

#if defined(__aarch64__) && defined(__APPLE__)
inline VaList GuestVaList(std::va_list host) {
    return VaList{6u * 8u, 6u * 8u + 8u * 16u, host, nullptr};
}
#endif

}

#if defined(__x86_64__) && !defined(_WIN32)
#define APS5_GUEST_VA_LIST_IS_HOST 1
#else
#define APS5_GUEST_VA_LIST_IS_HOST 0
#endif

#if defined(_WIN32)
#define APS5_VA_BEGIN(last) __builtin_sysv_va_list args; __builtin_sysv_va_start(args, last)
#define APS5_VA_END() __builtin_sysv_va_end(args)
#elif defined(__aarch64__) && defined(__APPLE__)
#define APS5_VA_BEGIN(last) std::va_list hostArgs; va_start(hostArgs, last); \
    VaList guestArgs = LibcDetail::GuestVaList(hostArgs); VaList* args = Aps5TakeBridgeVaList_nid_no_patch(&guestArgs)
#define APS5_VA_END() va_end(hostArgs)
#else
#define APS5_VA_BEGIN(last) std::va_list args; va_start(args, last)
#define APS5_VA_END() va_end(args)
#endif

#endif
