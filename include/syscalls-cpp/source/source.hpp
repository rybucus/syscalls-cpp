#ifndef SYSCALL_SOURCE_SOURCE_HPP
#define SYSCALL_SOURCE_SOURCE_HPP

#include <concepts>

#include "../types.hpp"

namespace syscall
{
    template<typename T>
    concept IsModuleSourcePolicy = requires(SyscallKey_t moduleKey, ModuleInfo_t & info)
    {
        { T::resolve(moduleKey, info) } -> std::convertible_to<bool>;
        { T::release(info) } -> std::same_as<void>;
    };
}

#endif
