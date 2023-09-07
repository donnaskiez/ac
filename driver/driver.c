#include "driver.h"

#include "common.h"
#include "ioctl.h"
#include "callbacks.h"

#include "hv.h"
#include "pool.h"
#include "thread.h"
#include "modules.h"
#include "integrity.h"

#include "queue.h"

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
	*DriverName = driver_config.ansi_driver_name.Buffer;
	KeReleaseGuardedMutex( &driver_config.lock );
}

VOID GetDriverPath(
	_In_ PUNICODE_STRING DriverPath
)
{
	KeAcquireGuardedMutex( &driver_config.lock );
	RtlInitUnicodeString( DriverPath, driver_config.driver_path.Buffer );
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

VOID GetDriverConfigSystemInformation(
	_In_ PSYSTEM_INFORMATION* SystemInformation
)
{
	KeAcquireGuardedMutex( &driver_config.lock );
	*SystemInformation = &driver_config.system_information;
	KeReleaseGuardedMutex( &driver_config.lock );
}

NTSTATUS RegistryPathQueryCallbackRoutine(
	IN PWSTR ValueName,
	IN ULONG ValueType,
	IN PVOID ValueData,
	IN ULONG ValueLength,
	IN PVOID Context,
	IN PVOID EntryContext
)
{
	UNICODE_STRING value_name;
	UNICODE_STRING image_path = RTL_CONSTANT_STRING( L"ImagePath" );
	UNICODE_STRING display_name = RTL_CONSTANT_STRING( L"DisplayName" );
	UNICODE_STRING value;
	PVOID temp_buffer;

	RtlInitUnicodeString( &value_name, ValueName );

	if ( RtlCompareUnicodeString(&value_name, &image_path, FALSE) == FALSE )
	{
		temp_buffer = ExAllocatePool2( POOL_FLAG_NON_PAGED, ValueLength, POOL_TAG_STRINGS );

		if ( !temp_buffer )
			return STATUS_MEMORY_NOT_ALLOCATED;

		RtlCopyMemory(
			temp_buffer,
			ValueData,
			ValueLength
		);

		driver_config.driver_path.Buffer = (PWCH)temp_buffer;
		driver_config.driver_path.Length = ValueLength;
		driver_config.driver_path.MaximumLength = ValueLength + 1;
	}

	if ( RtlCompareUnicodeString( &value_name, &display_name, FALSE ) == FALSE )
	{
		temp_buffer = ExAllocatePool2( POOL_FLAG_NON_PAGED, ValueLength, POOL_TAG_STRINGS );

		if ( !temp_buffer )
			return STATUS_MEMORY_NOT_ALLOCATED;

		RtlCopyMemory(
			temp_buffer,
			ValueData,
			ValueLength
		);

		driver_config.unicode_driver_name.Buffer = ( PWCH )temp_buffer;
		driver_config.unicode_driver_name.Length = ValueLength;
		driver_config.unicode_driver_name.MaximumLength = ValueLength + 1;
	}

	return STATUS_SUCCESS;
}

VOID FreeDriverConfigurationStringBuffers()
{
	if ( driver_config.unicode_driver_name.Buffer )
		ExFreePoolWithTag( driver_config.unicode_driver_name.Buffer, POOL_TAG_STRINGS );

	if ( driver_config.driver_path.Buffer )
		ExFreePoolWithTag( driver_config.driver_path.Buffer, POOL_TAG_STRINGS );

	if (driver_config.ansi_driver_name.Buffer )
		RtlFreeAnsiString( &driver_config.ansi_driver_name );
}

NTSTATUS InitialiseDriverConfigOnDriverEntry(
	_In_ PUNICODE_STRING RegistryPath
)
{
	NTSTATUS status;

	/* 3rd page acts as a null terminator for the callback routine */
	RTL_QUERY_REGISTRY_TABLE query_table[ 3 ] = { 0 };

	KeInitializeGuardedMutex( &driver_config.lock );
	
	RtlInitUnicodeString( &driver_config.device_name, L"\\Device\\DonnaAC" );
	RtlInitUnicodeString( &driver_config.device_symbolic_link, L"\\??\\DonnaAC" );
	RtlCopyUnicodeString( &driver_config.registry_path, RegistryPath );

	query_table[ 0 ].Flags = RTL_QUERY_REGISTRY_NOEXPAND;
	query_table[ 0 ].Name = L"ImagePath";
	query_table[ 0 ].DefaultType = REG_MULTI_SZ;
	query_table[ 0 ].DefaultLength = 0;
	query_table[ 0 ].DefaultData = NULL;
	query_table[ 0 ].EntryContext = NULL;
	query_table[ 0 ].QueryRoutine = RegistryPathQueryCallbackRoutine;

	query_table[ 1 ].Flags = RTL_QUERY_REGISTRY_NOEXPAND;
	query_table[ 1 ].Name = L"DisplayName";
	query_table[ 1 ].DefaultType = REG_SZ;
	query_table[ 1 ].DefaultLength = 0;
	query_table[ 1 ].DefaultData = NULL;
	query_table[ 1 ].EntryContext = NULL;
	query_table[ 1 ].QueryRoutine = RegistryPathQueryCallbackRoutine;

	status = RtlxQueryRegistryValues(
		RTL_REGISTRY_ABSOLUTE,
		RegistryPath->Buffer,
		&query_table,
		NULL,
		NULL
	);

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "RtlxQueryRegistryValues failed with status %x", status );
		FreeDriverConfigurationStringBuffers();
		return status;
	}

	status = RtlUnicodeStringToAnsiString(
		&driver_config.ansi_driver_name,
		&driver_config.unicode_driver_name,
		TRUE
	);

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "Failed to convert unicode string to ansi string" );
		FreeDriverConfigurationStringBuffers();
		return status;
	}

	status = ParseSMBIOSTable( 
		&driver_config.system_information.motherboard_serial,
		sizeof(driver_config.system_information.motherboard_serial)
	);

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "ParseSMBIOSTable failed with status %x", status );
		FreeDriverConfigurationStringBuffers();
		return status;
	}

	status = GetHardDiskDriveSerialNumber(
		&driver_config.system_information.drive_0_serial,
		sizeof( driver_config.system_information.drive_0_serial )
	);

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "GetHardDiskDriverSerialNumber failed with status %x", status );
		FreeDriverConfigurationStringBuffers();
		return status;
	}

	DEBUG_LOG( "Motherboard serial: %s", driver_config.system_information.motherboard_serial );
	DEBUG_LOG( "Drive 0 serial: %s", driver_config.system_information.drive_0_serial );

	return status;
}

NTSTATUS InitialiseProcessConfigOnProcessLaunch(
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

VOID InitialiseProcessConfigOnDriverEntry()
{
	KeInitializeGuardedMutex( &process_config.lock );
}

VOID CleanupDriverConfigOnUnload()
{
	FreeDriverConfigurationStringBuffers();
	FreeGlobalReportQueueObjects();
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

	/*
	* THERE IS A BUG WIHT THE HANDLE!! xD todo fix !
	*/
	status = ZwTerminateProcess( process_id, STATUS_SYSTEM_INTEGRITY_POLICY_VIOLATION );

	if ( !NT_SUCCESS( status ) )
	{
		/*
		* We don't want to clear the process config if ZwTerminateProcess fails 
		* so we can try again.
		*/
		DEBUG_ERROR( "ZwTerminateProcess failed with status %x", status );
		return;
	}

	ClearProcessConfigOnProcessTermination();
}

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	BOOLEAN flag = FALSE;
	NTSTATUS status;

	status = InitialiseDriverConfigOnDriverEntry( RegistryPath );

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "InitialiseDriverConfigOnDriverEntry failed with status %x", status );
		return status;
	}

	InitialiseProcessConfigOnDriverEntry();

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
	{
		DEBUG_ERROR( "IoCreateDevice failed with status %x", status );
		FreeDriverConfigurationStringBuffers();
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	status = IoCreateSymbolicLink(
		&driver_config.device_symbolic_link,
		&driver_config.device_name
	);

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "failed to create symbolic link" );
		FreeDriverConfigurationStringBuffers();
		IoDeleteDevice( DriverObject->DeviceObject );
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	DriverObject->MajorFunction[ IRP_MJ_CREATE ] = DeviceCreate;
	DriverObject->MajorFunction[ IRP_MJ_CLOSE ] = DeviceClose;
	DriverObject->MajorFunction[ IRP_MJ_DEVICE_CONTROL ] = DeviceControl;
	DriverObject->DriverUnload = DriverUnload;

	InitialiseGlobalReportQueue(&flag);

	if ( !flag )
	{
		DEBUG_ERROR( "failed to init report queue" );
		FreeDriverConfigurationStringBuffers();
		IoDeleteSymbolicLink( &driver_config.device_symbolic_link );
		IoDeleteDevice( DriverObject->DeviceObject );
		return STATUS_FAILED_DRIVER_ENTRY;
	} 

	DEBUG_LOG( "DonnaAC Driver Entry Complete" );

	return STATUS_SUCCESS;
}

