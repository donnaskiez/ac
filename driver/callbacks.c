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

UNICODE_STRING OBJECT_TYPE_PROCESS = RTL_CONSTANT_STRING( L"Process" );

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
	LONG protected_process_id = NULL;
	LPCSTR process_creator_name;
	LPCSTR target_process_name;

	GetProtectedProcessId( &protected_process_id );

	process_creator_name = PsGetProcessImageFileName( process_creator );
	target_process_name = PsGetProcessImageFileName( target_process );

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
		else
		{
			OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = deny_access;
			OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = deny_access;
			DEBUG_LOG( "handle stripped from: %s", process_creator_name );

			POPEN_HANDLE_FAILURE_REPORT report = ExAllocatePool2( POOL_FLAG_NON_PAGED, sizeof( OPEN_HANDLE_FAILURE_REPORT ), REPORT_POOL_TAG );

			if ( !report )
				goto end;

			report->report_code = REPORT_ILLEGAL_HANDLE_OPERATION;
			report->access = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
			report->is_kernel_handle = OperationInformation->KernelHandle;
			report->process_id = process_creator_id;
			report->thread_id = PsGetCurrentThreadId();
			RtlCopyMemory( report->process_name, process_creator_name, HANDLE_REPORT_PROCESS_NAME_MAX_LENGTH );

			InsertReportToQueue( report );
		}
	}

end:

	return OB_PREOP_SUCCESS;
}

//VOID ProcessCreateNotifyRoutine(
//	_In_ HANDLE ParentId,
//	_In_ HANDLE ProcessId,
//	_In_ BOOLEAN Create
//)
//{
//	NTSTATUS status;
//	PEPROCESS parent_process;
//	PEPROCESS target_process;
//	LONG parent_process_id;
//	LONG target_process_id;
//	LPCSTR target_process_name = NULL;
//	LPCSTR parent_process_name = NULL;
//
//	status = PsLookupProcessByProcessId( ParentId, &parent_process );
//
//	if ( !NT_SUCCESS( status ) )
//		return;
//
//	status = PsLookupProcessByProcessId( ProcessId, &target_process );
//
//	if ( !NT_SUCCESS( status ) )
//		return;
//
//	parent_process_name = PsGetProcessImageFileName( parent_process );
//
//	if ( !parent_process_name )
//		return;
//
//	target_process_name = PsGetProcessImageFileName( target_process );
//
//	if ( !target_process_name )
//		return;
//
//	if ( !strcmp( target_process_name, "notepad.exe") )
//	{
//		parent_process_id = PsGetProcessId( parent_process );
//		UpdateProtectedProcessParentId( parent_process_id );
//
//		target_process_id = PsGetProcessId( target_process );
//		UpdateProtectedProcessId( target_process_id );
//
//		DEBUG_LOG( "Protected process parent proc id: %lx", parent_process_id );
//	}
//}

/* stolen from ReactOS xD */
VOID NTAPI ExUnlockHandleTableEntry(
	IN PHANDLE_TABLE HandleTable,
	IN PHANDLE_TABLE_ENTRY HandleTableEntry
)
{
	LONG_PTR old_value;
	PAGED_CODE();

	/* Set the lock bit and make sure it wasn't earlier */
	old_value = InterlockedOr( ( PLONG )&HandleTableEntry->VolatileLowValue, 1 );

	/* Unblock any waiters */
	ExfUnblockPushLock( &HandleTable->HandleContentionEvent, NULL );
}

BOOLEAN EnumHandleCallback(
	_In_ PHANDLE_TABLE HandleTable,
	_In_ PHANDLE_TABLE_ENTRY Entry,
	_In_ HANDLE Handle,
	_In_ PVOID Context
)
{
	PVOID object;
	PVOID object_header;
	POBJECT_TYPE object_type;
	PEPROCESS process;
	PEPROCESS protected_process = NULL;
	LPCSTR process_name;
	LPCSTR protected_process_name;
	LONG protected_process_id = NULL;
	ACCESS_MASK handle_access_mask;

	object_header = GET_OBJECT_HEADER_FROM_HANDLE( Entry->ObjectPointerBits );

	/* Object header is the first 30 bytes of the object */
	object = ( uintptr_t )object_header + OBJECT_HEADER_SIZE;

	object_type = ObGetObjectType( object );

	/* TODO: check for threads aswell */
	if ( !RtlCompareUnicodeString( &object_type->Name, &OBJECT_TYPE_PROCESS, TRUE ) )
	{
		process = ( PEPROCESS )object;
		process_name = PsGetProcessImageFileName( process );

		GetProtectedProcessId( &protected_process_id );
		GetProtectedProcessEProcess( &protected_process );

		protected_process_name = PsGetProcessImageFileName( protected_process );

		if ( strcmp( process_name, protected_process_name ) )
			goto end;

		DEBUG_LOG( "Handle references our protected process with access mask: %lx", ( ACCESS_MASK )Entry->GrantedAccessBits );

		handle_access_mask = ( ACCESS_MASK )Entry->GrantedAccessBits;

		/* These permissions can be stripped from every process including CSRSS and LSASS */
		if ( handle_access_mask & PROCESS_CREATE_PROCESS )
		{
			Entry->GrantedAccessBits &= ~PROCESS_CREATE_PROCESS;
			DEBUG_LOG( "Stripped PROCESS_CREATE_PROCESS" );
		}

		if ( handle_access_mask & PROCESS_CREATE_THREAD )
		{
			Entry->GrantedAccessBits &= ~PROCESS_CREATE_THREAD;
			DEBUG_LOG( "Stripped PROCESS_CREATE_THREAD" );
		}

		if ( handle_access_mask & PROCESS_DUP_HANDLE )
		{
			Entry->GrantedAccessBits &= ~PROCESS_DUP_HANDLE;
			DEBUG_LOG( "Stripped PROCESS_DUP_HANDLE" );
		}

		if ( handle_access_mask & PROCESS_QUERY_INFORMATION )
		{
			Entry->GrantedAccessBits &= ~PROCESS_QUERY_INFORMATION;
			DEBUG_LOG( "Stripped PROCESS_QUERY_INFORMATION" );
		}

		if ( handle_access_mask & PROCESS_QUERY_LIMITED_INFORMATION )
		{
			Entry->GrantedAccessBits &= ~PROCESS_QUERY_LIMITED_INFORMATION;
			DEBUG_LOG( "Stripped PROCESS_QUERY_LIMITED_INFORMATION" );
		}

		if ( handle_access_mask & PROCESS_VM_READ )
		{
			Entry->GrantedAccessBits &= ~PROCESS_VM_READ;
			DEBUG_LOG( "Stripped PROCESS_VM_READ" );
		}

		if ( !strcmp( process_name, "csrss.exe" ) || !strcmp( process_name, "lsass.exe" ) )
		{
			DEBUG_LOG( "Required system process allowed, only stripping some permissions" );
			goto end;
		}

		/* Permissions beyond here can only be stripped from non critical processes */
		if ( handle_access_mask & PROCESS_SET_INFORMATION )
		{
			Entry->GrantedAccessBits &= ~PROCESS_SET_INFORMATION;
			DEBUG_LOG( "Stripped PROCESS_SET_INFORMATION" );
		}

		if ( handle_access_mask & PROCESS_SET_QUOTA )
		{
			Entry->GrantedAccessBits &= ~PROCESS_SET_QUOTA;
			DEBUG_LOG( "Stripped PROCESS_SET_QUOTA" );
		}

		if ( handle_access_mask & PROCESS_SUSPEND_RESUME )
		{
			Entry->GrantedAccessBits &= ~PROCESS_SUSPEND_RESUME;
			DEBUG_LOG( "Stripped PROCESS_SUSPEND_RESUME " );
		}

		if ( handle_access_mask & PROCESS_TERMINATE )
		{
			Entry->GrantedAccessBits &= ~PROCESS_TERMINATE;
			DEBUG_LOG( "Stripped PROCESS_TERMINATE" );
		}

		if ( handle_access_mask & PROCESS_VM_OPERATION )
		{
			Entry->GrantedAccessBits &= ~PROCESS_VM_OPERATION;
			DEBUG_LOG( "Stripped PROCESS_VM_OPERATION" );
		}

		if ( handle_access_mask & PROCESS_VM_WRITE )
		{
			Entry->GrantedAccessBits &= ~PROCESS_VM_WRITE;
			DEBUG_LOG( "Stripped PROCESS_VM_WRITE" );
		}

		POPEN_HANDLE_FAILURE_REPORT report = ExAllocatePool2( POOL_FLAG_NON_PAGED, sizeof( OPEN_HANDLE_FAILURE_REPORT ), REPORT_POOL_TAG );

		if ( !report )
			goto end;

		/*
		* Using the same report structure as the ObRegisterCallbacks report
		* since both of these reports are closely related by the fact they are
		* triggered by a process either opening a handle to our protected process
		* or have a valid open handle to it. I also don't think its worth creating
		* another queue specifically for open handle reports since they will be 
		* rare.
		*/
		report->report_code = REPORT_ILLEGAL_HANDLE_OPERATION;
		report->is_kernel_handle = NULL;
		report->process_id = PsGetProcessId( process );
		report->thread_id = NULL;
		report->access = handle_access_mask;
		RtlCopyMemory( report->process_name, protected_process_name, HANDLE_REPORT_PROCESS_NAME_MAX_LENGTH );

		InsertReportToQueue( report );
	}

end:
	ExUnlockHandleTableEntry( HandleTable, Entry );
	return FALSE;
}

NTSTATUS EnumerateProcessHandles(
	_In_ PEPROCESS Process
)
{
	/* Handles are paged out so we need to be at an IRQL that allows paging */
	PAGED_CODE();

	if ( !Process )
		return STATUS_INVALID_PARAMETER;

	//if ( Process == PsInitialSystemProcess )
	//	return STATUS_SUCCESS;

	PHANDLE_TABLE handle_table = *( PHANDLE_TABLE* )( ( uintptr_t )Process + EPROCESS_HANDLE_TABLE_OFFSET );

	if ( !handle_table )
		return STATUS_ABANDONED;

	if ( !MmIsAddressValid( handle_table ) )
		return STATUS_ABANDONED;

#pragma warning(push)
#pragma warning(suppress : 6387)

	BOOLEAN result = ExEnumHandleTable(
		handle_table,
		EnumHandleCallback,
		NULL,
		NULL
	);

#pragma warning(pop)

	return STATUS_SUCCESS;
}

/*
* I dont think this way of enumerating processes is valid for something like an anti
* cheat which is mass deployed and needs to ensure that it won't crash the system.
* Since we have no access to the process structure locks it is definitely not
* mass deployment safe lol.
*/
VOID EnumerateProcessListWithCallbackFunction(
	_In_ PVOID Function
)
{
	if ( !Function )
		return;

	PEPROCESS base_process = PsInitialSystemProcess;

	if ( !base_process )
		return;

	PEPROCESS current_process = base_process;

	do
	{
		VOID( *callback_function_ptr )( PEPROCESS ) = Function;
		( *callback_function_ptr )( current_process );

		PLIST_ENTRY list = ( PLIST_ENTRY )( ( uintptr_t )current_process + EPROCESS_PLIST_ENTRY_OFFSET );
		current_process = ( PEPROCESS )( ( uintptr_t )list->Flink - EPROCESS_PLIST_ENTRY_OFFSET );

	} while ( current_process != base_process || !current_process );
}