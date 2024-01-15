#ifndef THREAD_H
#define THREAD_H

#include <ntifs.h>

#include "common.h"
#include "callbacks.h"

typedef struct _HIDDEN_SYSTEM_THREAD_REPORT
{
        INT    report_code;
        INT    found_in_kthreadlist;
        INT    found_in_pspcidtable;
        UINT64 thread_address;
        LONG   thread_id;
        CHAR   thread[4096];

} HIDDEN_SYSTEM_THREAD_REPORT, *PHIDDEN_SYSTEM_THREAD_REPORT;

typedef struct _ATTACH_PROCESS_REPORT
{
        INT    report_code;
        UINT32 thread_id;
        UINT64 thread_address;

} ATTACH_PROCESS_REPORT, *PATTACH_PROCESS_REPORT;

typedef struct _KPRCB_THREAD_VALIDATION_CTX
{
        UINT64  thread;
        BOOLEAN thread_found_in_pspcidtable;
        // BOOLEAN thread_found_in_kthreadlist;
        BOOLEAN finished;

} KPRCB_THREAD_VALIDATION_CTX, *PKPRCB_THREAD_VALIDATION_CTX;

BOOLEAN
ValidateThreadsPspCidTableEntry(_In_ PETHREAD Thread);

VOID
DetectThreadsAttachedToProtectedProcess();

#endif