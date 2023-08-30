#ifndef THREAD_H
#define THREAD_H

#include <ntifs.h>

#include  "common.h"

#define IA32_GS_BASE 0xc0000101
#define KPRCB_OFFSET_FROM_GS_BASE 0x180
#define KPCRB_CURRENT_THREAD 0x8
#define KPROCESS_THREADLIST_OFFSET 0x030
#define KTHREAD_THREADLIST_OFFSET 0x2f8

#define REPORT_HIDDEN_SYSTEM_THREAD 90

VOID ValidateKPCRBThreads(
	_In_ PIRP Irp
);

typedef struct _HIDDEN_SYSTEM_THREAD_REPORT
{
	INT report_code;
	INT found_in_kthreadlist;
	INT found_in_pspcidtable;
	UINT64 thread_address;
	LONG thread_id;
	CHAR thread[ 4096 ];

}HIDDEN_SYSTEM_THREAD_REPORT, *PHIDDEN_SYSTEM_THREAD_REPORT;

#endif