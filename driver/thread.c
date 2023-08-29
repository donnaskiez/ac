#include "thread.h"

#include "pool.h"
#include "callbacks.h"

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

BOOLEAN HasThreadBeenRemovedFromPspCidTable(
	_In_ PETHREAD Thread
)
{
	BOOLEAN result = TRUE;

	return result;
}

BOOLEAN HasThreadBeenRemovedFromEThreadList(
	_In_ PETHREAD Thread
)
{
	BOOLEAN result = TRUE;

	return result;
}

NTSTATUS ValidateKPCRBThreads(
	//_In_ PIRP Irp
)
{
	NTSTATUS status;
}