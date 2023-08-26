#include "driver.h"

#include "common.h"
#include "ioctl.h"
#include "callbacks.h"

#include "hv.h"

#include "integrity.h"

DRIVER_CONFIG config = { 0 };

UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING( L"\\Device\\DonnaAC" );
UNICODE_STRING DEVICE_SYMBOLIC_LINK = RTL_CONSTANT_STRING( L"\\??\\DonnaAC" );

VOID ReadInitialisedConfigFlag(
	_Out_ PBOOLEAN Flag
)
{
	KeAcquireGuardedMutex( &config.lock );
	*Flag = config.initialised;
	KeReleaseGuardedMutex( &config.lock );
}

VOID GetProtectedProcessEProcess( 
	_Out_ PEPROCESS Process 
)
{
	KeAcquireGuardedMutex( &config.lock );
	Process = config.protected_process_eprocess;
	KeReleaseGuardedMutex( &config.lock );
}

VOID GetProtectedProcessId( 
	_Out_ PLONG ProcessId 
)
{
	KeAcquireGuardedMutex( &config.lock );
	*ProcessId = config.protected_process_id;
	KeReleaseGuardedMutex( &config.lock );
}

VOID ClearDriverConfigOnProcessTermination()
{
	DEBUG_LOG( "Process closed, clearing driver configuration" );
	KeAcquireGuardedMutex( &config.lock );
	config.protected_process_id = NULL;
	config.protected_process_eprocess = NULL;
	config.initialised = FALSE;
	KeReleaseGuardedMutex( &config.lock );
}

NTSTATUS InitialiseDriverConfigOnProcessLaunch(
	_In_ PIRP Irp
)
{
	NTSTATUS status;
	PDRIVER_INITIATION_INFORMATION information;
	PEPROCESS eprocess;

	information = ( PDRIVER_INITIATION_INFORMATION )Irp->AssociatedIrp.SystemBuffer;

	status = PsLookupProcessByProcessId( information->protected_process_id, &eprocess );

	if ( !NT_SUCCESS( status ) )
		return status;

	/*
	* acquire the mutex here to prevent a race condition if an unknown party trys 
	* to fuzz our IOCTL codes whilst the target process launches.
	*/
	KeAcquireGuardedMutex( &config.lock );

	config.protected_process_eprocess = eprocess;
	config.protected_process_id = information->protected_process_id;
	config.initialised = TRUE;

	KeReleaseGuardedMutex( &config.lock );

	Irp->IoStatus.Status = status;

	return status;
}

VOID DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	//PsSetCreateProcessNotifyRoutine( ProcessCreateNotifyRoutine, TRUE );
	FreeQueueObjectsAndCleanup();
	IoDeleteSymbolicLink( &DEVICE_SYMBOLIC_LINK );
	IoDeleteDevice( DriverObject->DeviceObject );
}

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER( RegistryPath );

	BOOLEAN flag = FALSE;
	NTSTATUS status;

	KeInitializeGuardedMutex( &config.lock );

	config.initialised = FALSE;
	config.protected_process_eprocess = NULL;
	config.protected_process_id = NULL;

	WalkKernelPageTables();

	status = IoCreateDevice(
		DriverObject,
		NULL,
		&DEVICE_NAME,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&DriverObject->DeviceObject
	);

	if ( !NT_SUCCESS( status ) )
		return STATUS_FAILED_DRIVER_ENTRY;

	status = IoCreateSymbolicLink(
		&DEVICE_SYMBOLIC_LINK,
		&DEVICE_NAME
	);

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "failed to create symbolic link" );
		IoDeleteDevice( DriverObject->DeviceObject );
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	DriverObject->MajorFunction[ IRP_MJ_CREATE ] = DeviceCreate;
	DriverObject->MajorFunction[ IRP_MJ_CLOSE ] = DeviceClose;
	DriverObject->MajorFunction[ IRP_MJ_DEVICE_CONTROL ] = DeviceControl;
	DriverObject->DriverUnload = DriverUnload;

	InitCallbackReportQueue(&flag);

	if ( !flag )
	{
		DEBUG_ERROR( "failed to init report queue" );
		IoDeleteSymbolicLink( &DEVICE_SYMBOLIC_LINK );
		IoDeleteDevice( DriverObject->DeviceObject );
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	DEBUG_LOG( "DonnaAC Driver Entry Complete. type: %lx", DriverObject->DeviceObject->DeviceType );

	return status;
}

