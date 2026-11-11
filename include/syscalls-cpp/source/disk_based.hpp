#ifndef SYSCALL_SOURCE_DISK_BASED_HPP
#define SYSCALL_SOURCE_DISK_BASED_HPP

#include <cstdint>

#include "../hash.hpp"
#include "../native_api.hpp"
#include "../shared.hpp"
#include "../types.hpp"
#include "loaded_in_memory.hpp"
#include "source.hpp"

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif

#ifndef FILE_READ_DATA
#define FILE_READ_DATA 0x00000001
#endif

#ifndef SEC_IMAGE_NO_EXECUTE
#define SEC_IMAGE_NO_EXECUTE 0x11000000
#endif

namespace syscall::native
{
    using NtOpenFile_t = NTSTATUS(NTAPI*)(
        PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
        PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions
        );
}

namespace syscall::policies::module_source
{
    struct DiskBased
    {
    private:
        static constexpr wchar_t k_wzNtdllPath[] = L"\\SystemRoot\\System32\\ntdll.dll";

        static bool resolveNtdll(SyscallKey_t moduleKey, ModuleInfo_t& info)
        {
            if (moduleKey != SYSCALL_ID("ntdll.dll"))
                return false;

            HMODULE hNtDll = native::getModuleBase(SYSCALL_ID("ntdll.dll"));
            if (!hNtDll)
                return false;

            auto fNtOpenFile = reinterpret_cast<native::NtOpenFile_t>(native::getExportAddress(hNtDll, SYSCALL_ID("NtOpenFile")));
            auto fNtCreateSection = reinterpret_cast<native::NtCreateSection_t>(native::getExportAddress(hNtDll, SYSCALL_ID("NtCreateSection")));
            auto fNtMapView = reinterpret_cast<native::NtMapViewOfSection_t>(native::getExportAddress(hNtDll, SYSCALL_ID("NtMapViewOfSection")));
            auto fNtClose = reinterpret_cast<native::NtClose_t>(native::getExportAddress(hNtDll, SYSCALL_ID("NtClose")));
            if (!fNtOpenFile || !fNtCreateSection || !fNtMapView || !fNtClose)
                return false;

            UNICODE_STRING usPath{};
            usPath.Buffer = const_cast<wchar_t*>(k_wzNtdllPath);
            usPath.Length = static_cast<USHORT>((sizeof(k_wzNtdllPath) - sizeof(wchar_t)));
            usPath.MaximumLength = static_cast<USHORT>(sizeof(k_wzNtdllPath));

            OBJECT_ATTRIBUTES objAttr{};
            objAttr.Length = sizeof(objAttr);
            objAttr.RootDirectory = nullptr;
            objAttr.ObjectName = &usPath;
            objAttr.Attributes = OBJ_CASE_INSENSITIVE;
            objAttr.SecurityDescriptor = nullptr;
            objAttr.SecurityQualityOfService = nullptr;

            HANDLE hFile = nullptr;
            IO_STATUS_BLOCK ioStatus{};
            NTSTATUS status = fNtOpenFile(&hFile, FILE_READ_DATA | SYNCHRONIZE, &objAttr, &ioStatus, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
            if (!native::isSuccess(status) || !hFile)
                return false;

            HANDLE hSection = nullptr;
            status = fNtCreateSection(&hSection, SECTION_MAP_READ | SECTION_QUERY, nullptr, nullptr, PAGE_READONLY, SEC_IMAGE_NO_EXECUTE, hFile);
            fNtClose(hFile);
            if (!native::isSuccess(status) || !hSection)
                return false;

            void* pMappedBase = nullptr;
            SIZE_T uViewSize = 0;
            status = fNtMapView(hSection, native::getCurrentProcess(), &pMappedBase, 0, 0, nullptr, &uViewSize, native::ESectionInherit::VIEW_UNMAP, 0, PAGE_READONLY);
            if (!native::isSuccess(status) || !pMappedBase)
            {
                fNtClose(hSection);
                return false;
            }

            auto pBase = static_cast<uint8_t*>(pMappedBase);
            auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pBase);
            if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            {
                auto fNtUnmapView = reinterpret_cast<native::NtUnmapViewOfSection_t>(native::getExportAddress(hNtDll, SYSCALL_ID("NtUnmapViewOfSection")));
                if (fNtUnmapView)
                    fNtUnmapView(native::getCurrentProcess(), pMappedBase);
                fNtClose(hSection);
                return false;
            }

            auto pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(pBase + pDosHeader->e_lfanew);
            if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
            {
                auto fNtUnmapView = reinterpret_cast<native::NtUnmapViewOfSection_t>(native::getExportAddress(hNtDll, SYSCALL_ID("NtUnmapViewOfSection")));
                if (fNtUnmapView)
                    fNtUnmapView(native::getCurrentProcess(), pMappedBase);
                fNtClose(hSection);
                return false;
            }

            const auto uExportRva = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            if (!uExportRva)
            {
                auto fNtUnmapView = reinterpret_cast<native::NtUnmapViewOfSection_t>(native::getExportAddress(hNtDll, SYSCALL_ID("NtUnmapViewOfSection")));
                if (fNtUnmapView)
                    fNtUnmapView(native::getCurrentProcess(), pMappedBase);
                fNtClose(hSection);
                return false;
            }

            info.m_pModuleBase = pBase;
            info.m_pNtHeaders = pNtHeaders;
            info.m_pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(pBase + uExportRva);
            info.m_hSectionHandle = hSection;
            info.m_bOwned = true;

            return true;
        }

    public:
        static bool resolve(SyscallKey_t moduleKey, ModuleInfo_t& info)
        {
            if (resolveNtdll(moduleKey, info))
                return true;

            return policies::module_source::LoadedInMemory::resolve(moduleKey, info);
        }

        static void release(ModuleInfo_t& info)
        {
            if (!info.m_bOwned || !info.m_pModuleBase)
                return;

            HMODULE hNtDll = native::getModuleBase(SYSCALL_ID("ntdll.dll"));
            if (!hNtDll)
                return;

            auto fNtUnmapView = reinterpret_cast<native::NtUnmapViewOfSection_t>(native::getExportAddress(hNtDll, SYSCALL_ID("NtUnmapViewOfSection")));
            auto fNtClose = reinterpret_cast<native::NtClose_t>(native::getExportAddress(hNtDll, SYSCALL_ID("NtClose")));

            if (fNtUnmapView)
                fNtUnmapView(native::getCurrentProcess(), info.m_pModuleBase);

            if (fNtClose && info.m_hSectionHandle)
                fNtClose(info.m_hSectionHandle);

            info.m_pModuleBase = nullptr;
            info.m_pNtHeaders = nullptr;
            info.m_pExportDir = nullptr;
            info.m_hSectionHandle = nullptr;
            info.m_bOwned = false;
        }
    };
}

#endif
