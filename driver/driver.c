#include "driver.h"

#include "common.h"
#include "ioctl.h"

VOID DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	IoDeleteSymbolicLink( &DEVICE_SYMBOLIC_LINK );
	IoDeleteDevice( &DriverObject->DeviceObject );
}

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER( RegistryPath );

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
		IoDeleteDevice( &DriverObject->DeviceObject );
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	DriverObject->MajorFunction[ IRP_MJ_CREATE ] = DeviceCreate;
	DriverObject->MajorFunction[ IRP_MJ_CLOSE ] = DeviceClose;
	DriverObject->MajorFunction[ IRP_MJ_DEVICE_CONTROL ] = DeviceControl;
	DriverObject->DriverUnload = DriverUnload;

	DEBUG_LOG( "DonnaAC Driver Entry Complete" );

	return status;
}

