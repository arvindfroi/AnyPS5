#ifndef CORE_LIBS_PRX_LIBC_INCLUDE_PROGRAMCALL_HPP
#define CORE_LIBS_PRX_LIBC_INCLUDE_PROGRAMCALL_HPP

#include <cstdint>
#include <type_traits>

#if defined(__APPLE__) && defined(__aarch64__)
bool LibcGuestBridged();
std::uint64_t LibcCallGuest(const void* function, const std::uint64_t* arguments);
#endif

template <typename TValue>
std::uint64_t ProgramCallInteger(TValue value) {
    static_assert(std::is_pointer_v<TValue> || std::is_integral_v<TValue>, "a program call takes integers and pointers");
    if constexpr (std::is_pointer_v<TValue>) return reinterpret_cast<std::uintptr_t>(value);
    else return static_cast<std::uint64_t>(value);
}

// Calls a function the program gave libc, such as an allocator it registered or a qsort comparator.
// Under FEXCore that is guest code, which a host call reaches only through a fault that costs
// microseconds, so the call goes through the bridge instead.
template <typename TFunction, typename... TArguments>
std::invoke_result_t<TFunction, TArguments...> CallProgram(TFunction function, TArguments... arguments) {
    using Result = std::invoke_result_t<TFunction, TArguments...>;
#if defined(__APPLE__) && defined(__aarch64__)
    static_assert(sizeof...(TArguments) <= 6, "a program call takes at most six arguments");
    if (LibcGuestBridged()) {
        const std::uint64_t integers[6] = {ProgramCallInteger(arguments)...};
        const std::uint64_t result = LibcCallGuest(reinterpret_cast<const void*>(function), integers);
        if constexpr (std::is_void_v<Result>) return;
        else if constexpr (std::is_pointer_v<Result>) return reinterpret_cast<Result>(result);
        else return static_cast<Result>(result);
    }
#endif
    return function(arguments...);
}

#endif
