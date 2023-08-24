#include "driver.h"

#include "common.h"
#include "ioctl.h"
#include "callbacks.h"

#include "hv.h"

#include "integrity.h"


PVOID callback_registration_handle;

DRIVER_CONFIG config = { 0 };

UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING( L"\\Device\\DonnaAC" );
UNICODE_STRING DEVICE_SYMBOLIC_LINK = RTL_CONSTANT_STRING( L"\\??\\DonnaAC" );

VOID GetProtectedProcessEProcess( 
	_In_ PEPROCESS Process 
)
{
	KeAcquireGuardedMutex( &config.lock );
	Process = config.protected_process_eprocess;
	KeReleaseGuardedMutex( &config.lock );
}

VOID GetProtectedProcessId( 
	_In_ PLONG ProcessId 
)
{
	KeAcquireGuardedMutex( &config.lock );
	*ProcessId = config.protected_process_id;
	KeReleaseGuardedMutex( &config.lock );
}

VOID ClearDriverConfigOnProcessTermination(
	_In_ PIRP Irp
)
{
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

	config.protected_process_eprocess = eprocess;
	config.protected_process_id = information->protected_process_id;
	config.initialised = TRUE;

	Irp->IoStatus.Status = status;

	return status;
}

VOID DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	//PsSetCreateProcessNotifyRoutine( ProcessCreateNotifyRoutine, TRUE );
	ObUnRegisterCallbacks( callback_registration_handle );
	FreeQueueObjectsAndCleanup();
	IoDeleteSymbolicLink( &DEVICE_SYMBOLIC_LINK );
	IoDeleteDevice( DriverObject->DeviceObject );
}

NTSTATUS InitiateDriverCallbacks()
{
	NTSTATUS status;

	OB_CALLBACK_REGISTRATION callback_registration = { 0 };
	OB_OPERATION_REGISTRATION operation_registration = { 0 };

	operation_registration.ObjectType = PsProcessType;
	operation_registration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	operation_registration.PreOperation = ObPreOpCallbackRoutine;
	operation_registration.PostOperation = ObPostOpCallbackRoutine;

	callback_registration.Version = OB_FLT_REGISTRATION_VERSION;
	callback_registration.OperationRegistration = &operation_registration;
	callback_registration.OperationRegistrationCount = 1;
	callback_registration.RegistrationContext = NULL;

	status = ObRegisterCallbacks(
		&callback_registration,
		&callback_registration_handle
	);

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "failed to launch obregisters with status %x", status );
		return status;
	}

	//status = PsSetCreateProcessNotifyRoutine(
	//	ProcessCreateNotifyRoutine,
	//	FALSE
	//);

	//if ( !NT_SUCCESS( status ) )
	//	DEBUG_ERROR( "Failed to launch ps create notif routines with status %x", status );

	return status;
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

