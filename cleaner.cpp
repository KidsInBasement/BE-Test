// Driver Trace Cleaner - Implementation
// Removes driver traces from PiDDB and MmUnloadedDrivers
//
// REFACTORED: Function implementations moved from header to avoid compiler crash.

#include "cleaner.h"

// ============================================================================
// GLOBAL VARIABLES (definitions)
// ============================================================================

PVOID g_KernelBase = NULL;
ULONG g_KernelSize = 0;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

PVOID ResolveRelativeAddress(PVOID Instruction, ULONG OffsetOffset, ULONG InstructionSize)
{
    ULONG_PTR Instr = (ULONG_PTR)Instruction;
    LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
    return (PVOID)(Instr + InstructionSize + RipOffset);
}

NTSTATUS PatternScan(
    const UCHAR* pattern, UCHAR wildcard, ULONG_PTR len,
    const void* base, ULONG_PTR size, PVOID* ppFound)
{
    if (!ppFound || !pattern || !base) return STATUS_INVALID_PARAMETER;

    for (ULONG_PTR i = 0; i < size - len; i++) {
        BOOLEAN found = TRUE;
        for (ULONG_PTR j = 0; j < len; j++) {
            if (pattern[j] != wildcard && pattern[j] != ((const UCHAR*)base)[i + j]) {
                found = FALSE;
                break;
            }
        }
        if (found) {
            *ppFound = (PUCHAR)base + i;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

PVOID GetKernelBase(PULONG pSize)
{
    if (g_KernelBase) {
        if (pSize) *pSize = g_KernelSize;
        return g_KernelBase;
    }

    UNICODE_STRING routineName;
    RtlUnicodeStringInit(&routineName, L"NtOpenFile");
    PVOID checkPtr = MmGetSystemRoutineAddress(&routineName);
    if (!checkPtr) return NULL;

    ULONG bytes = 0;
    ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
    if (bytes == 0) return NULL;

    PRTL_PROCESS_MODULES pMods = (PRTL_PROCESS_MODULES)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, bytes, 'Xr3n');
    if (!pMods) return NULL;
    RtlZeroMemory(pMods, bytes);

    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);
    if (NT_SUCCESS(status)) {
        for (ULONG i = 0; i < pMods->NumberOfModules; i++) {
            if (checkPtr >= pMods->Modules[i].ImageBase &&
                checkPtr < (PVOID)((PUCHAR)pMods->Modules[i].ImageBase + pMods->Modules[i].ImageSize))
            {
                g_KernelBase = pMods->Modules[i].ImageBase;
                g_KernelSize = pMods->Modules[i].ImageSize;
                if (pSize) *pSize = g_KernelSize;
                break;
            }
        }
    }
    ExFreePoolWithTag(pMods, 'Xr3n');
    return g_KernelBase;
}

NTSTATUS ScanSection(
    const char* section, const UCHAR* pattern, UCHAR wildcard,
    ULONG_PTR len, PVOID* ppFound)
{
    if (!ppFound) return STATUS_INVALID_PARAMETER;

    PVOID base = GetKernelBase(NULL);
    if (!base) return STATUS_NOT_FOUND;

    PIMAGE_NT_HEADERS64 pHdr = (PIMAGE_NT_HEADERS64)RtlImageNtHeader(base);
    if (!pHdr) return STATUS_INVALID_IMAGE_FORMAT;

    PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
    for (PIMAGE_SECTION_HEADER pSec = pFirstSection;
         pSec < pFirstSection + pHdr->FileHeader.NumberOfSections; pSec++)
    {
        ANSI_STRING s1, s2;
        RtlInitAnsiString(&s1, section);
        RtlInitAnsiString(&s2, (PCCHAR)pSec->Name);
        if (RtlCompareString(&s1, &s2, TRUE) == 0) {
            PVOID ptr = NULL;
            NTSTATUS st = PatternScan(pattern, wildcard, len,
                (PUCHAR)base + pSec->VirtualAddress, pSec->Misc.VirtualSize, &ptr);
            if (NT_SUCCESS(st))
                *(PULONG_PTR)ppFound = (ULONG_PTR)ptr - (ULONG_PTR)base;
            return st;
        }
    }
    return STATUS_NOT_FOUND;
}

// ============================================================================
// PiDDB CLEANING
// ============================================================================

BOOLEAN LocatePiDDB(PERESOURCE* lock, PRTL_AVL_TABLE* table)
{
    UCHAR PiDDBLockPtr_sig[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\x48\x8B\x0D\xCC\xCC\xCC\xCC\x33\xDB";
    UCHAR PiDTablePtr_sig[]  = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\x3D\xCC\xCC\xCC\xCC\x0F\x83\xCC\xCC\xCC\xCC";

    PVOID PiDDBLockPtr = NULL;
    if (!NT_SUCCESS(ScanSection("PAGE", PiDDBLockPtr_sig, 0xCC,
        sizeof(PiDDBLockPtr_sig) - 1, &PiDDBLockPtr)))
        return FALSE;

    PVOID PiDTablePtr = NULL;
    if (!NT_SUCCESS(ScanSection("PAGE", PiDTablePtr_sig, 0xCC,
        sizeof(PiDTablePtr_sig) - 1, &PiDTablePtr)))
        return FALSE;

    UINT64 realLock  = (UINT64)g_KernelBase + (UINT64)PiDDBLockPtr;
    UINT64 realTable = (UINT64)g_KernelBase + (UINT64)PiDTablePtr;

    *lock  = (PERESOURCE)ResolveRelativeAddress((PVOID)realLock, 3, 7);
    *table = (PRTL_AVL_TABLE)ResolveRelativeAddress((PVOID)realTable, 3, 7);
    return TRUE;
}

BOOLEAN CleanPiDDBCacheTable()
{
    PERESOURCE PiDDBLock = NULL;
    PRTL_AVL_TABLE PiDDBCacheTable = NULL;

    if (!LocatePiDDB(&PiDDBLock, &PiDDBCacheTable))
        return FALSE;
    if (!PiDDBLock || !PiDDBCacheTable)
        return FALSE;

    /* Build target driver name on the stack to avoid string in .rdata */
    WCHAR targetName[16] = { 0 };
    targetName[0]  = L'i'; targetName[1]  = L'q'; targetName[2]  = L'v';
    targetName[3]  = L'w'; targetName[4]  = L'6'; targetName[5]  = L'4';
    targetName[6]  = L'e'; targetName[7]  = L'.'; targetName[8]  = L's';
    targetName[9]  = L'y'; targetName[10] = L's'; targetName[11] = L'\0';

    PIDCacheobj lookupEntry;
    UNICODE_STRING driverName;
    RtlInitUnicodeString(&driverName, targetName);
    lookupEntry.DriverName = driverName;
    lookupEntry.TimeDateStamp = 0x5284EAC3;

    ExAcquireResourceExclusiveLite(PiDDBLock, TRUE);

    PIDCacheobj* pFound = (PIDCacheobj*)RtlLookupElementGenericTableAvl(
        PiDDBCacheTable, &lookupEntry);
    if (pFound) {
        RemoveEntryList(&pFound->List);
        RtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFound);
    }

    ExReleaseResourceLite(PiDDBLock);
    return (pFound != NULL);
}

// ============================================================================
// MmUnloadedDrivers CLEANING
// ============================================================================

BOOLEAN CleanMmUnloadedDrivers()
{
    UCHAR sig[] = "\x4C\x8B\xCC\xCC\xCC\xCC\xCC\x4C\x8B\xC9\x4D\x85\xCC\x74";
    PVOID offset = NULL;

    if (!NT_SUCCESS(ScanSection("PAGE", sig, 0xCC, sizeof(sig) - 1, &offset)))
        return FALSE;

    UINT64 realAddr = (UINT64)g_KernelBase + (UINT64)offset;
    PMM_UNLOADED_DRIVER* pMmUnloadedDrivers =
        (PMM_UNLOADED_DRIVER*)ResolveRelativeAddress((PVOID)realAddr, 3, 7);

    if (!pMmUnloadedDrivers || !*pMmUnloadedDrivers)
        return FALSE;

    PMM_UNLOADED_DRIVER drivers = *pMmUnloadedDrivers;
    BOOLEAN cleaned = FALSE;

    /* Build search string on stack */
    WCHAR needle[8] = { L'i',L'q',L'v',L'w',L'6',L'4',L'e',L'\0' };

    for (int i = 0; i < 50; i++) {
        if (drivers[i].Name.Buffer == NULL)
            continue;

        if (wcsstr(drivers[i].Name.Buffer, needle)) {
            RtlZeroMemory(drivers[i].Name.Buffer, drivers[i].Name.MaximumLength);
            RtlZeroMemory(&drivers[i], sizeof(MM_UNLOADED_DRIVER));
            cleaned = TRUE;
        }
    }

    return cleaned;
}

// ============================================================================
// DRIVER OBJECT HIDING
// ============================================================================

VOID HideDriverObject(PDRIVER_OBJECT DriverObject)
{
    if (!DriverObject) return;

    if (DriverObject->DriverName.Buffer) {
        RtlZeroMemory(DriverObject->DriverName.Buffer,
            DriverObject->DriverName.MaximumLength);
        DriverObject->DriverName.Length = 0;
    }

    if (DriverObject->DriverSection) {
        PLIST_ENTRY entry = (PLIST_ENTRY)DriverObject->DriverSection;
        PLIST_ENTRY prev = entry->Blink;
        PLIST_ENTRY next = entry->Flink;
        if (prev && next) {
            prev->Flink = next;
            next->Blink = prev;
            entry->Flink = entry;
            entry->Blink = entry;
        }
    }

    __try {
        if (DriverObject->DriverStart) {
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)DriverObject->DriverStart;
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(
                    (UCHAR*)DriverObject->DriverStart + dos->e_lfanew);
                ULONG headerSize = nt->OptionalHeader.SizeOfHeaders;
                if (headerSize == 0 || headerSize > PAGE_SIZE)
                    headerSize = PAGE_SIZE;
                RtlZeroMemory(DriverObject->DriverStart, headerSize);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { }

    DriverObject->DriverSection = NULL;
    DriverObject->DriverInit    = NULL;
    DriverObject->DriverStart   = NULL;
    DriverObject->DriverSize    = 0;

    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = NULL;
    }
}

// ============================================================================
// MAIN CLEANING FUNCTION
// ============================================================================

BOOLEAN CleanAllTraces(PDRIVER_OBJECT DriverObject)
{
    BOOLEAN ok = TRUE;

    if (!CleanPiDDBCacheTable())
        ok = FALSE;

    CleanMmUnloadedDrivers();

    HideDriverObject(DriverObject);

    return ok;
}
