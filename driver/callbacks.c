#include "callbacks.h"

#include "common.h"
#include "driver.h"

#include "queue.h"

PQUEUE_HEAD report_queue = NULL;

VOID InitCallbackReportQueue( PBOOLEAN Status )
{
	report_queue = QueueCreate();

	if ( report_queue == NULL )
		*Status = FALSE;

	*Status = TRUE;
}

VOID DeleteCallbackReportQueueHead()
{
	ExFreePoolWithTag( report_queue, QUEUE_POOL_TAG );
}

VOID InsertReportToQueue( POPEN_HANDLE_FAILURE_REPORT Report )
{
	QueuePush( report_queue, Report );
}

PVOID PopFirstReportFromQueue( report_queue )
{
	return QueuePop( report_queue );
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

	if ( protected_process_id ==  target_process_id)
	{
		if ( !strcmp( process_creator_name, "lsass.exe" ) || !strcmp( process_creator_name, "csrss.exe" ) )
		{
			/* We will downgrade these handles later */
			DEBUG_LOG( "Handles created by CSRSS and LSASS are allowed for now..." );
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
		}
	}

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
		LOG_INFO( "Protected process parent proc id: %lx", parent_process_id );
	}
}