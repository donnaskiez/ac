#include "driver.h"

#include "common.h"
#include "ioctl.h"
#include "callbacks.h"

#include "hv.h"
#include "pool.h"
#include "thread.h"
#include "modules.h"
#include "integrity.h"


DRIVER_CONFIG driver_config = { 0 };
PROCESS_CONFIG process_config = { 0 };

VOID ReadProcessInitialisedConfigFlag(
	_Out_ PBOOLEAN Flag
)
{
	KeAcquireGuardedMutex( &process_config.lock );
	*Flag = process_config.initialised;
	KeReleaseGuardedMutex( &process_config.lock );
}

VOID GetProtectedProcessEProcess( 
	_Out_ PEPROCESS* Process 
)
{
	KeAcquireGuardedMutex( &process_config.lock );
	*Process = process_config.protected_process_eprocess;
	KeReleaseGuardedMutex( &process_config.lock );
}

VOID GetProtectedProcessId(
	_Out_ PLONG ProcessId
)
{
	KeAcquireGuardedMutex( &process_config.lock );
	*ProcessId = process_config.protected_process_id;
	KeReleaseGuardedMutex( &process_config.lock );
}

VOID ClearProcessConfigOnProcessTermination()
{
	DEBUG_LOG( "Process closed, clearing driver process_configuration" );
	KeAcquireGuardedMutex( &process_config.lock );
	process_config.protected_process_id = NULL;
	process_config.protected_process_eprocess = NULL;
	process_config.initialised = FALSE;
	KeReleaseGuardedMutex( &process_config.lock );
}

VOID GetDriverName(
	_In_ LPCSTR* DriverName
)
{
	KeAcquireGuardedMutex( &driver_config.lock );
	*DriverName = driver_config.driver_name;
	KeReleaseGuardedMutex( &driver_config.lock );
}

VOID GetDriverPath(
	_In_ PUNICODE_STRING DriverPath
)
{
	KeAcquireGuardedMutex( &driver_config.lock );
	RtlCopyUnicodeString( DriverPath, &driver_config.driver_path );
	KeReleaseGuardedMutex( &driver_config.lock );
}

VOID GetDriverRegistryPath(
	_In_ PUNICODE_STRING RegistryPath
)
{
	KeAcquireGuardedMutex( &driver_config.lock );
	RtlCopyUnicodeString( RegistryPath, &driver_config.registry_path );
	KeReleaseGuardedMutex( &driver_config.lock );
}

VOID GetDriverDeviceName(
	_In_ PUNICODE_STRING DeviceName
)
{
	KeAcquireGuardedMutex( &driver_config.lock );
	RtlCopyUnicodeString( DeviceName, &driver_config.device_name );
	KeReleaseGuardedMutex( &driver_config.lock );
}

VOID GetDriverSymbolicLink(
	_In_ PUNICODE_STRING DeviceSymbolicLink
)
{
	KeAcquireGuardedMutex( &driver_config.lock );
	RtlCopyUnicodeString( DeviceSymbolicLink, &driver_config.device_symbolic_link );
	KeReleaseGuardedMutex( &driver_config.lock );
}

VOID InitialiseDriverConfigOnDriverEntry(
	_In_ PUNICODE_STRING RegistryPath
)
{
	KeInitializeGuardedMutex( &driver_config.lock );
	
	RtlInitUnicodeString( &driver_config.device_name, L"\\Device\\DonnaAC" );
	RtlInitUnicodeString( &driver_config.device_symbolic_link, L"\\??\\DonnaAC" );
	RtlCopyUnicodeString( &driver_config.registry_path, RegistryPath );
}


VOID TerminateProtectedProcessOnViolation()
{
	NTSTATUS status;
	ULONG process_id;

	GetProtectedProcessId( &process_id );

	if ( !process_id )
	{
		DEBUG_ERROR( "Failed to terminate process as process id is null" );
		return;
	}

	status = ZwTerminateProcess( process_id, STATUS_SYSTEM_INTEGRITY_POLICY_VIOLATION );

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "ZwTerminateProcess failed with status %x", status );
		return;
	}

	ClearDriverConfigOnProcessTermination();
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
	KeAcquireGuardedMutex( &process_config.lock );

	process_config.protected_process_eprocess = eprocess;
	process_config.protected_process_id = information->protected_process_id;
	process_config.initialised = TRUE;

	KeReleaseGuardedMutex( &process_config.lock );

	Irp->IoStatus.Status = status;

	return status;
}

VOID CleanupDriverConfigOnUnload()
{
	IoDeleteSymbolicLink( &driver_config.device_symbolic_link );
}

VOID DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	//PsSetCreateProcessNotifyRoutine( ProcessCreateNotifyRoutine, TRUE );
	CleanupDriverConfigOnUnload();
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

	InitialiseDriverConfigOnDriverEntry( RegistryPath );

	status = IoCreateDevice(
		DriverObject,
		NULL,
		&driver_config.device_name,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&DriverObject->DeviceObject
	);

	if ( !NT_SUCCESS( status ) )
		return STATUS_FAILED_DRIVER_ENTRY;

	status = IoCreateSymbolicLink(
		&driver_config.device_symbolic_link,
		&driver_config.device_name
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
		IoDeleteSymbolicLink( &driver_config.device_symbolic_link );
		IoDeleteDevice( DriverObject->DeviceObject );
		return STATUS_FAILED_DRIVER_ENTRY;
	} 

	DEBUG_LOG( "DonnaAC Driver Entry Complete" );

	HANDLE handle;
	PsCreateSystemThread(
		&handle,
		PROCESS_ALL_ACCESS,
		NULL,
		NULL,
		NULL,
		VerifyInMemoryImageVsDiskImage,
		NULL
	);

	ZwClose( handle );

	return STATUS_SUCCESS;
}

