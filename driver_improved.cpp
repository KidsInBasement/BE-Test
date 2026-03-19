#include "driver.h"
#include "hook.h"
#include "cleaner.h"
#include "be_bypass_v2.h"
#include "secure_comm.h"
#include "anti_analysis.h"
#include "be_report_scanner.h"
#include "code_obfuscation.h"
#include "iat_hook.h"

// BattleEye Bypass Driver - Full Featured Version
//
// HIGH PRIORITY IMPROVEMENTS:
// ✅ Dynamic offset resolution (be_bypass_v2.h)
// ✅ Hash-based detection (be_bypass_v2.h)
// ✅ Randomized timing (be_bypass_v2.h)
// ✅ Encrypted signature rotation (be_bypass_v2.h)
// ✅ Secure communication (secure_comm.h)
//
// MEDIUM PRIORITY IMPROVEMENTS:
// ✅ Anti-analysis checks (anti_analysis.h)
// ✅ BE report scanner (be_report_scanner.h)
// ✅ Code obfuscation (code_obfuscation.h)

// Global driver state for self-destruct
PVOID g_DriverImageBase = NULL;
ULONG g_DriverImageSize = 0;

static NTSTATUS RealEntryImproved(PDRIVER_OBJECT DriverObject)
{
    OBFUSCATE_BEGIN();
    
    // Save driver image info for potential self-destruct
    if (DriverObject) {
        g_DriverImageBase = DriverObject->DriverStart;
        g_DriverImageSize = DriverObject->DriverSize;
    }
    
    RANDOM_JUNK();
    
    // Initialize secure communication
    InitSecureComm();
    
    RANDOM_JUNK();
    
    // Install syscall hook for memory access
    if (!Hook::Install(&Hook::Handler))
        return STATUS_UNSUCCESSFUL;

    RANDOM_JUNK();

    // Clean driver traces from PiDDB and MmUnloadedDrivers
    CleanAllTraces(DriverObject);

    RANDOM_JUNK();

    // Install improved BattleEye bypass (V2 with stealth features)
    // This includes:
    // - Dynamic offset resolution
    // - Hash-based BE detection
    // - Randomized timing
    // - Signature rotation
    if (!InstallBEBypassV2()) {
        // Non-fatal - driver still works for memory access
    }

    RANDOM_JUNK();
    
    // Enable anti-analysis monitoring
    // This will periodically check for:
    // - VMs
    // - Debuggers
    // - Analysis tools
    // - Memory scanning
    EnableAntiAnalysis();

    RANDOM_JUNK();
    
    // Install IAT hook for MmGetSystemRoutineAddress
    // This hooks BEDaisy.sys's IAT instead of inline hooking ntoskrnl.exe
    // Works with kdmapper (no CR0 bypass needed)
    NTSTATUS hookStatus = InstallIATHook();
    if (!NT_SUCCESS(hookStatus)) {
        // Non-fatal - BEDaisy.sys may not be loaded yet
        // Hook will be installed when BE loads
    }

    OBFUSCATE_END();

    return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverEntry(
    PDRIVER_OBJECT  DriverObject,
    PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    
    // CRITICAL: Perform anti-analysis checks FIRST
    // This will abort loading if VM, debugger, or analysis tools detected
    if (!IsEnvironmentSafe()) {
        // Analysis environment detected - abort loading
        return STATUS_UNSUCCESSFUL;
    }
    
    return RealEntryImproved(DriverObject);
}

// Unload routine (if needed)
extern "C" VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    
    OBFUSCATE_BEGIN();
    
    // Uninstall IAT hook
    UninstallIATHook();
    
    // Disable anti-analysis
    DisableAntiAnalysis();
    
    // Uninstall BE bypass
    UninstallBEBypassV2();
    
    // Clean traces one more time
    CleanAllTraces(DriverObject);
    
    OBFUSCATE_END();
}
