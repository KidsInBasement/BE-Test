#include "hook.h"
#include "pte_hook.h"
#include "spoof_call.h"
#include "physical_memory.h"
#include "be_bypass.h"

/* Build "dxgkrnl.sys" on the stack to avoid plain string in .rdata */
static void BuildModName(char* buf)
{
    buf[0]  = 'd'; buf[1]  = 'x'; buf[2]  = 'g';
    buf[3]  = 'k'; buf[4]  = 'r'; buf[5]  = 'n';
    buf[6]  = 'l'; buf[7]  = '.'; buf[8]  = 's';
    buf[9]  = 'y'; buf[10] = 's'; buf[11] = '\0';
}

/* Build "NtQueryCompositionSurfaceStatistics" on the stack */
static void BuildExportName(char* buf)
{
    const char src[] = {
        'N','t','Q','u','e','r','y','C','o','m','p','o','s','i','t','i','o','n',
        'S','u','r','f','a','c','e','S','t','a','t','i','s','t','i','c','s','\0'
    };
    for (int i = 0; src[i]; i++) buf[i] = src[i];
    buf[35] = '\0';
}

BOOL Hook::Install(void* handlerAddr)
{
    if (!handlerAddr)
        return FALSE;

    char modName[16]    = { 0 };
    char exportName[40] = { 0 };
    BuildModName(modName);
    BuildExportName(exportName);

    PVOID hookTarget = GetSystemModuleExport(modName, exportName);
    if (!hookTarget)
        return FALSE;

    InitSpoofCall();

    if (InstallPteHook(hookTarget, handlerAddr))
        return TRUE;

    BYTE patch[12] = { 0 };
    patch[0] = 0x48;
    patch[1] = 0xB8;
    uintptr_t addr = reinterpret_cast<uintptr_t>(handlerAddr);
    memcpy(&patch[2], &addr, sizeof(void*));
    patch[10] = 0xFF;
    patch[11] = 0xE0;

    WriteReadOnlyMemory(hookTarget, patch, sizeof(patch));

    return TRUE;
}

NTSTATUS Hook::Handler(PVOID callParam)
{
    if (!callParam || !MmIsAddressValid(callParam))
        return STATUS_SUCCESS;

    PIO_PACKET req = (PIO_PACKET)callParam;

    if (req->sig != IO_SIGNATURE)
        return STATUS_SUCCESS;

    switch (req->code) {

    case IO_READ:
        req->result = PhysicalReadProcessMemory(
            (HANDLE)req->pid,
            req->address,
            (PVOID)req->buffer,
            (SIZE_T)req->size
        ) ? 1 : 0;
        break;

    case IO_WRITE:
        req->result = PhysicalWriteProcessMemory(
            (HANDLE)req->pid,
            req->address,
            (PVOID)req->buffer,
            (SIZE_T)req->size
        ) ? 1 : 0;
        break;

    case IO_READ_V:
        myReadProcessMemory(
            (HANDLE)req->pid,
            (PVOID)req->address,
            (PVOID)req->buffer,
            (DWORD)req->size
        );
        break;

    case IO_WRITE_V:
        myWriteProcessMemory(
            (HANDLE)req->pid,
            (PVOID)req->address,
            (PVOID)req->buffer,
            (DWORD)req->size
        );
        break;

    case IO_MODBASE:
        req->result = (unsigned __int64)GetProcessModuleBase(
            (HANDLE)req->pid,
            req->mod_name
        );
        break;

    case IO_ALLOC:
        req->result = (unsigned __int64)AllocateVirtualMemory(
            (HANDLE)req->pid,
            req->size,
            req->protect
        );
        break;

    case IO_FREE:
        FreeVirtualMemory(
            (HANDLE)req->pid,
            (PVOID)req->result
        );
        break;

    case IO_PROTECT:
        ProtectVirtualMemory(
            (HANDLE)req->pid,
            req->address,
            req->size,
            req->protect
        );
        break;

    case IO_BATCH:
    {
        PBATCH_PKT batch = (PBATCH_PKT)req;
        if (batch->count > MAX_BATCH_ENTRIES)
            batch->count = MAX_BATCH_ENTRIES;

        ULONG64 cr3 = GetProcessCR3((HANDLE)batch->pid);
        if (!cr3) {
            for (unsigned int i = 0; i < batch->count; i++)
                batch->entries[i].result = 0;
            break;
        }

        for (unsigned int i = 0; i < batch->count; i++) {
            batch->entries[i].result = PhysicalReadProcessMemoryCR3(
                cr3,
                batch->entries[i].address,
                (PVOID)batch->entries[i].buffer,
                (SIZE_T)batch->entries[i].size
            ) ? 1 : 0;
        }
        break;
    }

    case IO_CHECK:
        req->result = g_PteHook.active ? 0x1A2B3C4D : 0x5E6F7A8B;
        break;

    case IO_DBG_PTE:
    {
        if (!req->buffer || !MmIsAddressValid((PVOID)req->buffer)) {
            req->result = 0;
            break;
        }

        PUCHAR out = (PUCHAR)req->buffer;
        RtlZeroMemory(out, 64);

        *(PULONG64)(out + 0)  = g_PteHook.active ? 1ULL : 0ULL;
        *(PULONG64)(out + 8)  = g_PteHook.originalPfn;
        *(PULONG64)(out + 16) = g_PteHook.newPfn;
        *(PULONG64)(out + 24) = (ULONG64)g_PteHook.targetVA;

        if (g_PteHook.active && g_PteHook.targetVA) {
            ULONG pageOffset = (ULONG)((ULONG64)g_PteHook.targetVA & 0xFFF);

            PHYSICAL_ADDRESS origPA;
            origPA.QuadPart = (LONGLONG)(g_PteHook.originalPfn << 12);
            PVOID mapped = MmMapIoSpace(origPA, PAGE_SIZE, MmCached);
            if (mapped) {
                RtlCopyMemory(out + 32, (PUCHAR)mapped + pageOffset, 16);
                MmUnmapIoSpace(mapped, PAGE_SIZE);
            }

            if (MmIsAddressValid(g_PteHook.targetVA)) {
                RtlCopyMemory(out + 48, g_PteHook.targetVA, 16);
            }
        }

        req->result = 1;
        break;
    }

    case IO_DBG_SPOOF:
    {
        if (req->buffer && MmIsAddressValid((PVOID)req->buffer)) {
            PUCHAR out = (PUCHAR)req->buffer;
            RtlZeroMemory(out, 16);
            *(PULONG64)(out + 0) = (ULONG64)g_SpoofGadget;
            *(PULONG64)(out + 8) = (ULONG64)g_SpoofStub;
        }
        req->result = (g_SpoofGadget && g_SpoofStub) ? 1 : 0;
        break;
    }

    case IO_DBG_BE_STATS:
    {
        // Get BattleEye bypass statistics
        if (req->buffer && MmIsAddressValid((PVOID)req->buffer)) {
            PULONG stats = (PULONG)req->buffer;
            ULONG blockedAllocs = 0, blockedPackets = 0;
            GetBEBypassStats(&blockedAllocs, &blockedPackets);
            stats[0] = blockedAllocs;
            stats[1] = blockedPackets;
        }
        req->result = 1;
        break;
    }

    default:
        break;
    }

    return STATUS_SUCCESS;
}
