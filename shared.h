#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _IO_CTRL_CODE {
    IO_NONE         = 0,
    IO_READ         = 1,
    IO_WRITE        = 2,
    IO_MODBASE      = 3,
    IO_ALLOC        = 4,
    IO_FREE         = 5,
    IO_PROTECT      = 6,
    IO_READ_V       = 7,
    IO_WRITE_V      = 8,
    IO_BATCH        = 10,
    IO_CHECK        = 99,
    IO_DBG_PTE      = 100,
    IO_DBG_SPOOF    = 101,
    IO_DBG_BE_STATS = 102,
} IO_CTRL_CODE;

#define IO_SIGNATURE  0xC3A17F2E

typedef struct _IO_PACKET {
    unsigned int     sig;
    unsigned int     code;
    unsigned __int64 pid;
    unsigned __int64 address;
    unsigned __int64 buffer;
    unsigned __int64 size;
    unsigned __int64 result;
    unsigned int     protect;
    wchar_t          mod_name[64];
} IO_PACKET, *PIO_PACKET;

#define MAX_BATCH_ENTRIES 64

typedef struct _BATCH_ITEM {
    unsigned __int64 address;
    unsigned __int64 buffer;
    unsigned __int64 size;
    unsigned __int64 result;
} BATCH_ITEM, *PBATCH_ITEM;

typedef struct _BATCH_PKT {
    unsigned int    sig;
    unsigned int    code;
    unsigned __int64 pid;
    unsigned int    count;
    unsigned int    _pad;
    BATCH_ITEM      entries[MAX_BATCH_ENTRIES];
} BATCH_PKT, *PBATCH_PKT;

#ifdef __cplusplus
}
#endif
