#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <intrin.h>
#include <windef.h>
#include <ntstrsafe.h>

#pragma comment(lib, "ntoskrnl.lib")

typedef enum _SYSTEM_INFORMATION_CLASS_EX {
    SystemModuleInformation = 0x0B
} SYSTEM_INFORMATION_CLASS_EX;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    ULONG   Section;
    PVOID   MappedBase;
    PVOID   ImageBase;
    ULONG   ImageSize;
    ULONG   Flags;
    USHORT  LoadOrderIndex;
    USHORT  InitOrderIndex;
    USHORT  LoadCount;
    USHORT  OffsetToFileName;
    CHAR    FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef struct PiDDBCacheEntry {
    LIST_ENTRY      List;
    UNICODE_STRING  DriverName;
    ULONG           TimeDateStamp;
    NTSTATUS        LoadStatus;
    char            _pad[16];
} PIDCacheobj;

typedef struct _PEB_LDR_DATA_KM {
    ULONG       Length;
    BOOLEAN     Initialized;
    PVOID       SsHandle;
    LIST_ENTRY  ModuleListLoadOrder;
    LIST_ENTRY  ModuleListMemoryOrder;
    LIST_ENTRY  ModuleListInitOrder;
} PEB_LDR_DATA_KM, *PPEB_LDR_DATA_KM;

typedef struct _LDR_DATA_TABLE_ENTRY_KM {
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
    PVOID       DllBase;
    PVOID       EntryPoint;
    ULONG       SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_KM, *PLDR_DATA_TABLE_ENTRY_KM;

typedef struct _PEB_KM {
    UCHAR       Reserved1[2];
    UCHAR       BeingDebugged;
    UCHAR       Reserved2[1];
    PVOID       Reserved3[2];
    PPEB_LDR_DATA_KM Ldr;
} PEB_KM, *PPEB_KM;

extern "C" {

NTKERNELAPI PPEB_KM PsGetProcessPeb(IN PEPROCESS Process);

NTKERNELAPI NTSTATUS ObReferenceObjectByName(
    PUNICODE_STRING ObjectName,
    ULONG Attributes,
    PACCESS_STATE AccessState,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    PVOID ParseContext,
    PVOID* Object
);

extern POBJECT_TYPE* IoDriverObjectType;

NTSTATUS NTAPI MmCopyVirtualMemory(
    PEPROCESS   SourceProcess,
    PVOID       SourceAddress,
    PEPROCESS   TargetProcess,
    PVOID       TargetAddress,
    SIZE_T      BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T     ReturnSize
);

NTSTATUS NTAPI ZwProtectVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID*  BaseAddress,
    PSIZE_T ProtectSize,
    ULONG   NewProtect,
    PULONG  OldProtect
);

NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);

NTSYSAPI PVOID NTAPI RtlFindExportedRoutineByName(
    PVOID   ImageBase,
    PCCH    RoutineName
);

NTSTATUS ZwQuerySystemInformation(
    ULONG   InfoClass,
    PVOID   Buffer,
    ULONG   Length,
    PULONG  ReturnLength
);

} /* extern "C" */

extern POBJECT_TYPE* PsProcessType;

// CR0 register structure for write protection control
#pragma warning(push)
#pragma warning(disable: 4201) // nameless struct/union
typedef union _CR0_REG {
    ULONG64 Value;
    struct {
        ULONG64 ProtectionEnable : 1;       // PE (bit 0)
        ULONG64 MonitorCoprocessor : 1;     // MP (bit 1)
        ULONG64 Emulation : 1;              // EM (bit 2)
        ULONG64 TaskSwitched : 1;           // TS (bit 3)
        ULONG64 ExtensionType : 1;          // ET (bit 4)
        ULONG64 NumericError : 1;           // NE (bit 5)
        ULONG64 Reserved1 : 10;             // bits 6-15
        ULONG64 WriteProtect : 1;           // WP (bit 16) - THIS IS WHAT WE NEED
        ULONG64 Reserved2 : 1;              // bit 17
        ULONG64 AlignmentMask : 1;          // AM (bit 18)
        ULONG64 Reserved3 : 10;             // bits 19-28
        ULONG64 NotWriteThrough : 1;        // NW (bit 29)
        ULONG64 CacheDisable : 1;           // CD (bit 30)
        ULONG64 PagingEnable : 1;           // PG (bit 31)
        ULONG64 Reserved4 : 32;             // bits 32-63
    };
} CR0_REG, *PCR0_REG;
#pragma warning(pop)
