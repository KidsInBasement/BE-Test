#include "driver.h"
#include "hook.h"
#include "cleaner.h"
#include "be_bypass.h"

// BattleEye Bypass Driver
// Provides memory read/write access, driver hiding, and BE report blocking

static NTSTATUS RealEntry(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    
    // Install syscall hook for memory access
    // This is the core functionality - allows usermode to read/write game memory
    if (!Hook::Install(&Hook::Handler))
        return STATUS_UNSUCCESSFUL;

    // Clean driver traces from PiDDB and MmUnloadedDrivers
    // This hides the driver from BattleEye's driver enumeration
    CleanAllTraces(DriverObject);

    // Install BattleEye bypass (safe version for kdmapper)
    // This version doesn't use dangerous inline hooks
    if (!InstallBEBypass()) {
        // Non-fatal - driver still works for memory access
    }

    return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverEntry(
    PDRIVER_OBJECT  DriverObject,
    PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    return RealEntry(DriverObject);
}
