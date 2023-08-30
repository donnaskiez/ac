#ifndef THREAD_H
#define THREAD_H

#include <ntifs.h>

#include  "common.h"

#define IA32_GS_BASE 0xc0000101
#define KPRCB_OFFSET_FROM_GS_BASE 0x180
#define KPCRB_CURRENT_THREAD 0x8
#define KPROCESS_THREADLIST_OFFSET 0x030
#define KTHREAD_THREADLIST_OFFSET 0x2f8

NTSTATUS ValidateKPCRBThreads(
	//_In_ PIRP Irp
);

#endif