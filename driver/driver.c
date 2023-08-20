#include "driver.h"

#include "common.h"
#include "ioctl.h"
#include "callbacks.h"

PVOID callback_registration_handle;

LONG protected_process_id;
LONG protected_process_parent_id;
KGUARDED_MUTEX mutex;

UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING( L"\\Device\\DonnaAC" );
UNICODE_STRING DEVICE_SYMBOLIC_LINK = RTL_CONSTANT_STRING( L"\\??\\DonnaAC" );

VOID UpdateProtectedProcessId( 
	_In_ LONG NewProcessId 
)
{
	KeAcquireGuardedMutex( &mutex );
	protected_process_id = NewProcessId;
	KeReleaseGuardedMutex( &mutex );
}

VOID GetProtectedProcessId(
	_Out_ PLONG ProcessId
)
{
	KeAcquireGuardedMutex( &mutex );
	*ProcessId = protected_process_id;
	KeReleaseGuardedMutex( &mutex );
}

VOID GetProtectedProcessParentId( 
	_Out_ PLONG ProcessId 
)
{
	KeAcquireGuardedMutex( &mutex );
	*ProcessId = protected_process_parent_id;
	KeReleaseGuardedMutex( &mutex );
}

VOID UpdateProtectedProcessParentId( 
	_In_ LONG NewProcessId 
)
{
	KeAcquireGuardedMutex( &mutex );
	protected_process_parent_id = NewProcessId;
	KeReleaseGuardedMutex( &mutex );
}

VOID DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	IoDeleteSymbolicLink( &DEVICE_SYMBOLIC_LINK );
	IoDeleteDevice( DriverObject->DeviceObject );
}

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER( RegistryPath );

	BOOLEAN flag;
	NTSTATUS status;

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
		IoDeleteDevice( DriverObject->DeviceObject );
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	DriverObject->MajorFunction[ IRP_MJ_CREATE ] = DeviceCreate;
	DriverObject->MajorFunction[ IRP_MJ_CLOSE ] = DeviceClose;
	DriverObject->MajorFunction[ IRP_MJ_DEVICE_CONTROL ] = DeviceControl;
	DriverObject->DriverUnload = DriverUnload;

	KeInitializeGuardedMutex( &mutex );

	InitCallbackReportQueue(&flag);

	if ( !flag )
	{
		IoDeleteSymbolicLink( &DEVICE_SYMBOLIC_LINK );
		IoDeleteDevice( DriverObject->DeviceObject );
		return STATUS_FAILED_DRIVER_ENTRY;
	}

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
		DeleteCallbackReportQueueHead();
		IoDeleteSymbolicLink( &DEVICE_SYMBOLIC_LINK );
		IoDeleteDevice( DriverObject->DeviceObject );
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	DEBUG_LOG( "DonnaAC Driver Entry Complete. type: %lx", DriverObject->DeviceObject->DeviceType );

	return status;
}

