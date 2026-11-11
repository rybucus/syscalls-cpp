#include <gtest/gtest.h>
#include <syscalls-cpp/syscall.hpp>

static_assert(syscall::IsModuleSourcePolicy<syscall::policies::module_source::LoadedInMemory>);
static_assert(syscall::IsModuleSourcePolicy<syscall::policies::module_source::DiskBased>);

class SourceLoadedTest : public ::testing::Test {};

TEST_F(SourceLoadedTest, ResolvesNtdll)
{
    syscall::ModuleInfo_t info;
    ASSERT_TRUE(syscall::policies::module_source::LoadedInMemory::resolve(SYSCALL_ID("ntdll.dll"), info));

    EXPECT_NE(info.m_pModuleBase, nullptr);
    EXPECT_NE(info.m_pNtHeaders, nullptr);
    EXPECT_NE(info.m_pExportDir, nullptr);
    EXPECT_FALSE(info.m_bOwned);
    EXPECT_EQ(info.m_hSectionHandle, nullptr);
}

TEST_F(SourceLoadedTest, UnknownModuleFails)
{
    syscall::ModuleInfo_t info;
    EXPECT_FALSE(syscall::policies::module_source::LoadedInMemory::resolve(SYSCALL_ID("definitely_not_a_real_module.dll"), info));
}

TEST_F(SourceLoadedTest, ReleaseIsNoOp)
{
    syscall::ModuleInfo_t info;
    ASSERT_TRUE(syscall::policies::module_source::LoadedInMemory::resolve(SYSCALL_ID("ntdll.dll"), info));

    uint8_t* pBaseBefore = info.m_pModuleBase;
    syscall::policies::module_source::LoadedInMemory::release(info);

    EXPECT_EQ(info.m_pModuleBase, pBaseBefore);
}

class SourceDiskTest : public ::testing::Test {};

TEST_F(SourceDiskTest, ResolvesNtdll)
{
    syscall::ModuleInfo_t info;
    ASSERT_TRUE(syscall::policies::module_source::DiskBased::resolve(SYSCALL_ID("ntdll.dll"), info));

    EXPECT_NE(info.m_pModuleBase, nullptr);
    EXPECT_NE(info.m_pNtHeaders, nullptr);
    EXPECT_NE(info.m_pExportDir, nullptr);
    EXPECT_TRUE(info.m_bOwned);
    EXPECT_NE(info.m_hSectionHandle, nullptr);

    syscall::policies::module_source::DiskBased::release(info);
}

TEST_F(SourceDiskTest, DiskBaseDiffersFromLoaded)
{
    syscall::ModuleInfo_t diskInfo;
    ASSERT_TRUE(syscall::policies::module_source::DiskBased::resolve(SYSCALL_ID("ntdll.dll"), diskInfo));

    syscall::ModuleInfo_t loadedInfo;
    ASSERT_TRUE(syscall::policies::module_source::LoadedInMemory::resolve(SYSCALL_ID("ntdll.dll"), loadedInfo));

    EXPECT_NE(diskInfo.m_pModuleBase, loadedInfo.m_pModuleBase);

    syscall::policies::module_source::DiskBased::release(diskInfo);
}

TEST_F(SourceDiskTest, ReleaseClearsFields)
{
    syscall::ModuleInfo_t info;
    ASSERT_TRUE(syscall::policies::module_source::DiskBased::resolve(SYSCALL_ID("ntdll.dll"), info));
    ASSERT_TRUE(info.m_bOwned);

    syscall::policies::module_source::DiskBased::release(info);

    EXPECT_EQ(info.m_pModuleBase, nullptr);
    EXPECT_EQ(info.m_pNtHeaders, nullptr);
    EXPECT_EQ(info.m_pExportDir, nullptr);
    EXPECT_EQ(info.m_hSectionHandle, nullptr);
    EXPECT_FALSE(info.m_bOwned);
}

TEST_F(SourceDiskTest, FallsBackToLoadedForNonNtdll)
{
    syscall::ModuleInfo_t info;
    ASSERT_TRUE(syscall::policies::module_source::DiskBased::resolve(SYSCALL_ID("kernel32.dll"), info));

    EXPECT_NE(info.m_pModuleBase, nullptr);
    EXPECT_FALSE(info.m_bOwned);
    EXPECT_EQ(info.m_hSectionHandle, nullptr);

    syscall::policies::module_source::DiskBased::release(info);
}

TEST_F(SourceDiskTest, ExportDirectoryHasNtExports)
{
    syscall::ModuleInfo_t info;
    ASSERT_TRUE(syscall::policies::module_source::DiskBased::resolve(SYSCALL_ID("ntdll.dll"), info));

    ASSERT_NE(info.m_pExportDir, nullptr);
    EXPECT_GT(info.m_pExportDir->NumberOfNames, 0u);
    EXPECT_GT(info.m_pExportDir->NumberOfFunctions, 0u);

    auto pNamesRva = reinterpret_cast<uint32_t*>(info.m_pModuleBase + info.m_pExportDir->AddressOfNames);
    bool bFoundNtAllocateVirtualMemory = false;
    for (uint32_t i = 0; i < info.m_pExportDir->NumberOfNames; ++i)
    {
        const char* szName = reinterpret_cast<const char*>(info.m_pModuleBase + pNamesRva[i]);
        if (std::string_view{szName} == "NtAllocateVirtualMemory")
        {
            bFoundNtAllocateVirtualMemory = true;
            break;
        }
    }
    EXPECT_TRUE(bFoundNtAllocateVirtualMemory);

    syscall::policies::module_source::DiskBased::release(info);
}

class ManagerDiskSourceTest : public ::testing::Test {};

TEST_F(ManagerDiskSourceTest, InitializesSectionDirectFromDisk)
{
    auto optManager = syscall::SectionDirectManager::create<syscall::policies::module_source::DiskBased>();
    ASSERT_TRUE(optManager.has_value());
}

TEST_F(ManagerDiskSourceTest, InvokeNtAllocateFromDiskSyscalls)
{
    auto optManager = syscall::SectionDirectManager::create<syscall::policies::module_source::DiskBased>();
    ASSERT_TRUE(optManager.has_value());

    PVOID pBaseAddress = nullptr;
    SIZE_T uRegionSize = 0x1000;

    NTSTATUS status = optManager->invoke<NTSTATUS>(
        SYSCALL_ID("NtAllocateVirtualMemory"),
        syscall::native::getCurrentProcess(),
        &pBaseAddress,
        0,
        &uRegionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    EXPECT_TRUE(NT_SUCCESS(status));
    EXPECT_NE(pBaseAddress, nullptr);

    if (pBaseAddress)
    {
        uRegionSize = 0;
        optManager->invoke<NTSTATUS>(
            SYSCALL_ID("NtFreeVirtualMemory"),
            syscall::native::getCurrentProcess(),
            &pBaseAddress,
            &uRegionSize,
            MEM_RELEASE
        );
    }
}

#if SYSCALL_PLATFORM_WINDOWS_64
TEST_F(ManagerDiskSourceTest, InitializesSectionGadgetFromDisk)
{
    auto optManager = syscall::SectionGadgetManager::create<syscall::policies::module_source::DiskBased>();
    ASSERT_TRUE(optManager.has_value());
}

TEST_F(ManagerDiskSourceTest, InvokeNtAllocateViaGadgetFromDiskSyscalls)
{
    auto optManager = syscall::SectionGadgetManager::create<syscall::policies::module_source::DiskBased>();
    ASSERT_TRUE(optManager.has_value());

    PVOID pBaseAddress = nullptr;
    SIZE_T uRegionSize = 0x1000;

    NTSTATUS status = optManager->invoke<NTSTATUS>(
        SYSCALL_ID("NtAllocateVirtualMemory"),
        syscall::native::getCurrentProcess(),
        &pBaseAddress,
        0,
        &uRegionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    EXPECT_TRUE(NT_SUCCESS(status));
    EXPECT_NE(pBaseAddress, nullptr);

    if (pBaseAddress)
    {
        uRegionSize = 0;
        optManager->invoke<NTSTATUS>(
            SYSCALL_ID("NtFreeVirtualMemory"),
            syscall::native::getCurrentProcess(),
            &pBaseAddress,
            &uRegionSize,
            MEM_RELEASE
        );
    }
}
#endif

TEST_F(ManagerDiskSourceTest, DefaultSourceIsLoaded)
{
    auto optLoaded = syscall::SectionDirectManager::create();
    auto optExplicit = syscall::SectionDirectManager::create<syscall::policies::module_source::LoadedInMemory>();

    ASSERT_TRUE(optLoaded.has_value());
    ASSERT_TRUE(optExplicit.has_value());
}
