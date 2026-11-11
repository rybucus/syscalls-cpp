#ifndef SYSCALL_SOURCE_LOADED_IN_MEMORY_HPP
#define SYSCALL_SOURCE_LOADED_IN_MEMORY_HPP

#include "../native_api.hpp"
#include "../shared.hpp"
#include "../types.hpp"
#include "source.hpp"

namespace syscall::policies::module_source
{
    struct LoadedInMemory
    {
        static bool resolve(SyscallKey_t moduleKey, ModuleInfo_t& info)
        {
            HMODULE hModule = native::getModuleBase(moduleKey);
            if (!hModule)
                return false;

            info.m_pModuleBase = reinterpret_cast<uint8_t*>(hModule);

            auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(info.m_pModuleBase);
            if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
                return false;

            info.m_pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(info.m_pModuleBase + pDosHeader->e_lfanew);
            if (info.m_pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
                return false;

            auto uExportRva = info.m_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            if (!uExportRva)
                return false;

            info.m_pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(info.m_pModuleBase + uExportRva);

            return true;
        }

        static void release(ModuleInfo_t& /*info*/)
        {
        }
    };
}

#endif
