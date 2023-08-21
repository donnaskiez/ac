#include "callbacks.h"

#include "common.h"
#include "driver.h"

#include "queue.h"

QUEUE_HEAD head = { 0 };

/*
* This mutex is to prevent a new item being pushed to the queue
* while the HandlePeriodicCallbackReportQueue is iterating through
* the objects. This can be an issue because the spinlock is released
* after each report is placed in the IRP buffer which means a new report
* can be pushed into the queue before the next iteration can take ownership
* of the spinlock. 
*/
KGUARDED_MUTEX mutex;

VOID InitCallbackReportQueue(
	_In_ PBOOLEAN Status 
)
{
	head.start = NULL;
	head.end = NULL;
	head.entries = 0;

	KeInitializeSpinLock( &head.lock );
	KeInitializeGuardedMutex( &mutex );

	*Status = TRUE;
}

VOID InsertReportToQueue(
	_In_ POPEN_HANDLE_FAILURE_REPORT Report
)
{
	KeAcquireGuardedMutex( &mutex );
	QueuePush( &head, Report );
	KeReleaseGuardedMutex( &mutex );
}

VOID FreeQueueObjectsAndCleanup()
{
	KeAcquireGuardedMutex( &mutex );

	PVOID report = QueuePop(&head );

	if ( report == NULL )
		goto end;

	while ( report != NULL )
		report = QueuePop( &head );

end:
	KeReleaseGuardedMutex( &mutex );
}

NTSTATUS HandlePeriodicCallbackReportQueue( 
	_In_ PIRP Irp 
)
{
	PVOID report = NULL;
	INT count = 0;
	OPEN_HANDLE_FAILURE_REPORT_HEADER header;

	KeAcquireGuardedMutex( &mutex );
	report = QueuePop( &head );

	if ( report == NULL )
	{
		DEBUG_LOG( "callback report queue is empty, returning" );
		Irp->IoStatus.Information = sizeof( OPEN_HANDLE_FAILURE_REPORT_HEADER );
		goto end;
	}

	Irp->IoStatus.Information = sizeof( OPEN_HANDLE_FAILURE_REPORT ) * MAX_HANDLE_REPORTS_PER_IRP + 
		sizeof( OPEN_HANDLE_FAILURE_REPORT_HEADER );

	while ( report != NULL )
	{
		if ( count >= MAX_HANDLE_REPORTS_PER_IRP )
			goto end;

		RtlCopyMemory(
			 ( ( UINT64 )Irp->AssociatedIrp.SystemBuffer + sizeof( OPEN_HANDLE_FAILURE_REPORT_HEADER ) ) + count * sizeof( OPEN_HANDLE_FAILURE_REPORT ),
			report,
			sizeof( OPEN_HANDLE_FAILURE_REPORT )
		);

		report = QueuePop( &head );
		count += 1;
	}

end:

	header.count = count;
	RtlCopyMemory( Irp->AssociatedIrp.SystemBuffer, &header, sizeof( OPEN_HANDLE_FAILURE_REPORT_HEADER ));
	KeReleaseGuardedMutex( &mutex );

	DEBUG_LOG( "Moved all reports into the IRP, sending !" );
	return STATUS_SUCCESS;
}

VOID ObPostOpCallbackRoutine(
	_In_ PVOID RegistrationContext,
	_In_ POB_POST_OPERATION_INFORMATION OperationInformation
)
{

}

OB_PREOP_CALLBACK_STATUS ObPreOpCallbackRoutine(
	_In_ PVOID RegistrationContext,
	_In_ POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
	UNREFERENCED_PARAMETER( RegistrationContext );

	/* access mask to completely strip permissions */
	ACCESS_MASK deny_access = SYNCHRONIZE | PROCESS_TERMINATE;

	/* Access mask to be used for crss / lsass */
	ACCESS_MASK downgrade_access = 0;

	/*
	* This callback routine is executed in the context of the thread that
	* is requesting to open said handle
	*/
	PEPROCESS process_creator = PsGetCurrentProcess();
	PEPROCESS target_process = ( PEPROCESS )OperationInformation->Object;

	LONG target_process_id = PsGetProcessId( target_process );
	LONG process_creator_id = PsGetProcessId( process_creator );

	LONG protected_process_id;
	LONG parent_process_id;

	GetProtectedProcessId( &protected_process_id );
	GetProtectedProcessParentId( &parent_process_id );

	LPCSTR process_creator_name = PsGetProcessImageFileName( process_creator );
	LPCSTR target_process_name = PsGetProcessImageFileName( target_process );

	/* 
	* NOTE for whatever fukin reason this shit prevent notepad rfom launching need
	* 2 fix lol
	*/

	if ( !strcmp( "notepad.exe", target_process_name) )
	{
		if ( !strcmp( process_creator_name, "lsass.exe" ) || !strcmp( process_creator_name, "csrss.exe" ) )
		{
			/* We will downgrade these handles later */
			DEBUG_LOG( "Handles created by CSRSS and LSASS are allowed for now..." );
		}
		else if ( target_process == process_creator )
		{
			DEBUG_LOG( "handles made by NOTEPAD r okay :)" );
			/* handles created by the game (notepad) are okay */
		}
		/* NOTE: try allowing only 1 handle from the proc creator */
		else if ( parent_process_id == process_creator_id )
		{
			/* Allow handles created by the protected process' creator i.e explorer, cmd etc. */
			DEBUG_LOG( "Process creator: %s handles are fine for now...", process_creator_name );
		}
		else
		{
			OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = deny_access;
			OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = deny_access;
			DEBUG_LOG( "handle stripped from: %s", process_creator_name );

			POPEN_HANDLE_FAILURE_REPORT report = ExAllocatePool2( POOL_FLAG_NON_PAGED, sizeof( OPEN_HANDLE_FAILURE_REPORT ), REPORT_POOL_TAG );

			if ( !report )
				goto end;

			KeAcquireGuardedMutex( &mutex );
			report->report_code = REPORT_ILLEGAL_HANDLE_OPERATION;
			report->desired_access = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
			report->is_kernel_handle = OperationInformation->KernelHandle;
			report->process_id = process_creator_id;
			report->thread_id = PsGetCurrentThreadId();
			memcpy( report->process_name, process_creator_name, HANDLE_REPORT_PROCESS_NAME_MAX_LENGTH );

			InsertReportToQueue( report );
			KeReleaseGuardedMutex( &mutex );
		}
	}

end:

	return OB_PREOP_SUCCESS;
}

VOID ProcessCreateNotifyRoutine(
	_In_ HANDLE ParentId,
	_In_ HANDLE ProcessId,
	_In_ BOOLEAN Create
)
{
	NTSTATUS status;
	PEPROCESS parent_process;
	PEPROCESS target_process;
	LONG parent_process_id;
	LPCSTR target_process_name = NULL;
	LPCSTR parent_process_name = NULL;

	status = PsLookupProcessByProcessId( ParentId, &parent_process );

	if ( !NT_SUCCESS( status ) )
		return;

	status = PsLookupProcessByProcessId( ProcessId, &target_process );

	if ( !NT_SUCCESS( status ) )
		return;

	parent_process_name = PsGetProcessImageFileName( parent_process );

	if ( !parent_process_name )
		return;

	target_process_name = PsGetProcessImageFileName( target_process );

	if ( !target_process_name )
		return;

	if ( !strcmp( target_process_name, "notepad.exe") )
	{
		parent_process_id = PsGetProcessId( target_process );
		UpdateProtectedProcessId( parent_process_id );
		DEBUG_LOG( "Protected process parent proc id: %lx", parent_process_id );
	}
}