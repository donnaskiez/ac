#include "thread.h"

#include <intrin.h>

#include "pool.h"
#include "callbacks.h"
#include "driver.h"
#include "queue.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ValidateKPCRBThreads)
#pragma alloc_text(PAGE, DetectThreadsAttachedToProtectedProcess)
#endif

typedef struct _KPRCB_THREAD_VALIDATION_CTX
{
	UINT64 current_kpcrb_thread;
	UINT8 thread_found_in_pspcidtable;
	UINT8 thread_found_in_kthreadlist;
	BOOLEAN finished;

}KPRCB_THREAD_VALIDATION_CTX, * PKPRCB_THREAD_VALIDATION_CTX;

STATIC
VOID
KPRCBThreadValidationProcessCallback(
	_In_ PTHREAD_LIST_ENTRY ThreadListEntry,
	_Inout_opt_ PVOID Context
)
{
	UINT32 thread_id;
	PKPRCB_THREAD_VALIDATION_CTX context = (PKPRCB_THREAD_VALIDATION_CTX)Context;

	if (!Context || context->finished == TRUE)
		return;

	if (ThreadListEntry->thread == context->current_kpcrb_thread)
	{
		context->thread_found_in_kthreadlist = TRUE;

		thread_id = PsGetThreadId(ThreadListEntry->thread);

		if (thread_id != NULL)
		{
			context->thread_found_in_pspcidtable = TRUE;
			context->finished = TRUE;
		}
	}
}

/*
* How this will work:
*
* 1. The KPCRB (processor control block) contains 3 pointers to 3 threads:
*
*		+0x008 CurrentThread    : Ptr64 _KTHREAD
*		+0x010 NextThread       : Ptr64 _KTHREAD
*		+0x018 IdleThread       : Ptr64 _KTHREAD
*
* 2. These threads are stored in a list that is seperate to the KTHREADs linked list.
*    We know this because if you unlink a process, the threads are still scheduled by
*	 the OS, meaning the OS has a seperate list that it uses to schedule these threads.
*
* 3. From here we can firstly check if the KTHREAD is within the KTHREAD linked list,
*    if it is we can then use this to check if its in the PspCidTable by passing it
*    to PsGetThreadId which returns the thread id by enumerating the PspCidTable and
*    finding the corresponding object pointer. If the thread id is not found, we know
*    that it's been removed from the PspCidTable, and if the thread is not in any
*    process' thread list , we know it's been removed from the KTHREAD linked list.
*
*/
VOID
ValidateKPCRBThreads(
	_Inout_ PIRP Irp
)
{
	UINT64 kpcr;
	UINT64 kprcb;
	KAFFINITY old_affinity = { 0 };
	KPRCB_THREAD_VALIDATION_CTX context = { 0 };

	for (LONG processor_index = 0; processor_index < KeQueryActiveProcessorCount(0); processor_index++)
	{
		old_affinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1ull << processor_index));

		while (KeGetCurrentProcessorNumber() != processor_index)
			YieldProcessor();

		kpcr = __readmsr(IA32_GS_BASE);
		kprcb = kpcr + KPRCB_OFFSET_FROM_GS_BASE;

		/* sanity check */
		if (!MmIsAddressValid(kprcb + KPCRB_CURRENT_THREAD))
			continue;

		context.current_kpcrb_thread = *(UINT64*)(kprcb + KPCRB_CURRENT_THREAD);

		DEBUG_LOG("Proc number: %lx, Current thread: %llx", processor_index, context.current_kpcrb_thread);

		if (!context.current_kpcrb_thread)
			continue;

		EnumerateThreadListWithCallbackRoutine(
			KPRCBThreadValidationProcessCallback,
			&context
		);

		DEBUG_LOG("Found in kthread: %lx, found in pspcid: %lx", (UINT32)context.thread_found_in_kthreadlist, (UINT32)context.thread_found_in_pspcidtable);

		if (context.current_kpcrb_thread == FALSE || context.thread_found_in_pspcidtable == FALSE)
		{
			PHIDDEN_SYSTEM_THREAD_REPORT report =
				ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(HIDDEN_SYSTEM_THREAD_REPORT), REPORT_POOL_TAG);

			if (!report)
				goto increment;

			report->report_code = REPORT_HIDDEN_SYSTEM_THREAD;
			report->found_in_kthreadlist = context.thread_found_in_kthreadlist;
			report->found_in_pspcidtable = context.thread_found_in_pspcidtable;
			report->thread_id = PsGetThreadId(context.current_kpcrb_thread);
			report->thread_address = context.current_kpcrb_thread;

			RtlCopyMemory(
				report->thread,
				context.current_kpcrb_thread,
				sizeof(report->thread));

			InsertReportToQueue(report);
		}

	increment:
		KeRevertToUserAffinityThreadEx(old_affinity);
	}
}

STATIC
VOID
DetectAttachedThreadsProcessCallback(
	_In_ PTHREAD_LIST_ENTRY ThreadListEntry,
	_Inout_opt_ PVOID Context
)
{
	UNREFERENCED_PARAMETER(Context);

	PKAPC_STATE apc_state;
	PEPROCESS protected_process = NULL;

	GetProtectedProcessEProcess(&protected_process);

	if (protected_process == NULL)
		return;

	apc_state = (PKAPC_STATE)((UINT64)ThreadListEntry->thread + KTHREAD_APC_STATE_OFFSET);

	if (apc_state->Process == protected_process)
	{
		DEBUG_LOG("Program attached to notepad: %llx", (UINT64)ThreadListEntry->thread);

		PATTACH_PROCESS_REPORT report =
			ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ATTACH_PROCESS_REPORT), REPORT_POOL_TAG);

		if (!report)
			return;

		report->report_code = REPORT_ILLEGAL_ATTACH_PROCESS;
		report->thread_id = PsGetThreadId(ThreadListEntry->thread);
		report->thread_address = ThreadListEntry->thread;

		InsertReportToQueue(report);
	}
}

/*
* I did not reverse this myself and previously had no idea how you would go about
* detecting KiAttachProcess so credits to KANKOSHEV for the explanation:
*
* https://github.com/KANKOSHEV/Detect-KeAttachProcess/tree/main
* https://doxygen.reactos.org/d0/dc9/procobj_8c.html#adec6dc539d4a5c0ee7d0f48e24ef0933
*
* To expand on his writeup a little, the offset that he provides is equivalent to PKAPC_STATE->Process.
* This is where KiAttachProcess writes the process that thread is attaching to when it's called.
* The APC_STATE structure holds relevant information about the thread's APC state and is quite
* important during context switch scenarios as it's how the thread determines if it has any APC's
* queued.
*/
VOID DetectThreadsAttachedToProtectedProcess()
{
	EnumerateThreadListWithCallbackRoutine(
		DetectAttachedThreadsProcessCallback,
		NULL
	);
}
