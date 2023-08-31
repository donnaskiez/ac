#include "thread.h"

#include "pool.h"
#include "callbacks.h"

#include <intrin.h>

UINT8 thread_found_in_pspcidtable = FALSE;
UINT8 thread_found_in_kthreadlist = FALSE;
BOOLEAN finished = FALSE;

UINT64 current_kpcrb_thread = NULL;

VOID ProcessEnumerationCallback(
	_In_ PEPROCESS Process
)
{
	NTSTATUS status;
	PLIST_ENTRY thread_list_head;
	PLIST_ENTRY thread_list_entry;
	PETHREAD current_thread;
	UINT32 thread_id;

	if ( finished == TRUE )
		return;

	thread_list_head = ( PLIST_ENTRY )( ( UINT64 )Process + KPROCESS_THREADLIST_OFFSET );
	thread_list_entry = thread_list_head->Flink;

	while ( thread_list_entry != thread_list_head )
	{
		current_thread = ( PETHREAD )( ( UINT64 )thread_list_entry - KTHREAD_THREADLIST_OFFSET );

		if ( current_thread == current_kpcrb_thread )
		{
			thread_found_in_kthreadlist = TRUE;

			thread_id = PsGetThreadId( current_thread );

			if ( thread_id != NULL )
			{
				thread_found_in_pspcidtable = TRUE;
				finished = TRUE;
			}
		}

		thread_list_entry = thread_list_entry->Flink;
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

VOID ValidateKPCRBThreads(
	_In_ PIRP Irp
)
{
	NTSTATUS status;
	UINT64 kpcr;
	UINT64 kprcb;
	KAFFINITY old_affinity = { 0 };

	for ( LONG processor_index = 0; processor_index < KeQueryActiveProcessorCount( 0 ); processor_index++ )
	{
		old_affinity = KeSetSystemAffinityThreadEx( ( KAFFINITY )( 1 << processor_index ) );

		kpcr = __readmsr( IA32_GS_BASE );
		kprcb = kpcr + KPRCB_OFFSET_FROM_GS_BASE;
		current_kpcrb_thread = *( UINT64* )( kprcb + KPCRB_CURRENT_THREAD );

		EnumerateProcessListWithCallbackFunction(
			ProcessEnumerationCallback
		);

		if ( thread_found_in_kthreadlist == FALSE || thread_found_in_pspcidtable == FALSE )
		{
			Irp->IoStatus.Information = sizeof( HIDDEN_SYSTEM_THREAD_REPORT );

			HIDDEN_SYSTEM_THREAD_REPORT report;
			report.report_code = REPORT_HIDDEN_SYSTEM_THREAD;
			report.found_in_kthreadlist = thread_found_in_kthreadlist;
			report.found_in_pspcidtable = thread_found_in_pspcidtable;
			report.thread_id = PsGetThreadId( current_kpcrb_thread );
			report.thread_address = current_kpcrb_thread;

			RtlCopyMemory(
				report.thread,
				current_kpcrb_thread,
				sizeof( report.thread ));

			RtlCopyMemory( 
				Irp->AssociatedIrp.SystemBuffer, 
				&report, 
				sizeof( HIDDEN_SYSTEM_THREAD_REPORT ) );
		}

		current_kpcrb_thread = NULL;
		thread_found_in_pspcidtable = FALSE;
		thread_found_in_kthreadlist = FALSE;
		finished = FALSE;

		KeRevertToUserAffinityThreadEx( old_affinity );
	}
}

