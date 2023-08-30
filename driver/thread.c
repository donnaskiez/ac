#include "thread.h"

#include "pool.h"
#include "callbacks.h"

#include <intrin.h>

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
* 3. Now from here, we can get thread ID and pass it to PsLookupThreadByThreadId which
*    takes the thread ID and returns a pointer to the ETHREAD structure. It does this
*    by indexing the PspCidTable using the TID we pass in. 
* 
* What we can potentially observer is that any threads that have been removed from the
* PspCidTable will return a null ptr from PsLookupThreadById. In addition to this, we
* can also check if the KTHREAD address referenced in the KPCRB is not in the KTHREAD
* linked list. Allowing us to find threads removed from both the PspCidTable and the 
* KTHREAD linked list.
*/

/*
* IDEA: we can run a thread on each core to maximise the search, so it would be 3 * num procs
*/

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

NTSTATUS ValidateKPCRBThreads(
	//_In_ PIRP Irp
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

		DEBUG_LOG( "Current processor: %lx, current kprcb: %llx, current thread: %llx", KeGetCurrentProcessorNumber(), kprcb, current_kpcrb_thread );

		EnumerateProcessListWithCallbackFunction(
			ProcessEnumerationCallback
		);

		DEBUG_LOG( "Thread in psp: %i, thread in list: %i", thread_found_in_pspcidtable, thread_found_in_kthreadlist );

		if ( thread_found_in_kthreadlist == FALSE || thread_found_in_pspcidtable == FALSE )
		{

		}

		current_kpcrb_thread = NULL;
		thread_found_in_pspcidtable = FALSE;
		thread_found_in_kthreadlist = FALSE;
		finished = FALSE;

		KeRevertToUserAffinityThreadEx( old_affinity );
	}

}