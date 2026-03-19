#pragma once
#include "definitions.h"

// Driver Trace Cleaner - Declarations
// Removes driver traces from PiDDB and MmUnloadedDrivers
//
// REFACTORED: This header now contains only declarations.
// Implementations are in cleaner.cpp to avoid compiler crash.

// ============================================================================
// GLOBAL VARIABLES (extern declarations)
// ============================================================================

extern PVOID g_KernelBase;
extern ULONG g_KernelSize;

// ============================================================================
// STRUCTURE DEFINITIONS
// ============================================================================

typedef struct _MM_UNLOADED_DRIVER {
    UNICODE_STRING  Name;
    PVOID           ModuleStart;
    PVOID           ModuleEnd;
    LARGE_INTEGER   UnloadTime;
} MM_UNLOADED_DRIVER, *PMM_UNLOADED_DRIVER;

// ============================================================================
// FUNCTION DECLARATIONS
// ============================================================================

// Helper functions
PVOID ResolveRelativeAddress(PVOID Instruction, ULONG OffsetOffset, ULONG InstructionSize);
NTSTATUS PatternScan(const UCHAR* pattern, UCHAR wildcard, ULONG_PTR len, const void* base, ULONG_PTR size, PVOID* ppFound);
PVOID GetKernelBase(PULONG pSize);
NTSTATUS ScanSection(const char* section, const UCHAR* pattern, UCHAR wildcard, ULONG_PTR len, PVOID* ppFound);

// PiDDB cleaning
BOOLEAN LocatePiDDB(PERESOURCE* lock, PRTL_AVL_TABLE* table);
BOOLEAN CleanPiDDBCacheTable();

// MmUnloadedDrivers cleaning
BOOLEAN CleanMmUnloadedDrivers();

// Driver object hiding
VOID HideDriverObject(PDRIVER_OBJECT DriverObject);

// Main cleaning function
BOOLEAN CleanAllTraces(PDRIVER_OBJECT DriverObject);
