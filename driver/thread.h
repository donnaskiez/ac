#ifndef THREAD_H
#define THREAD_H

#include <ntifs.h>

#include "common.h"

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

VOID
ValidateKPCRBThreads();

VOID
DetectThreadsAttachedToProtectedProcess();

#endif