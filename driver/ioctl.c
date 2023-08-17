#include "ioctl.h"

#include "common.h"

NTSTATUS DeviceControl(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PIRP Irp
)
{
	DEBUG_LOG( "Handle opened to DonnaAC" );
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return Irp->IoStatus.Status;
}

NTSTATUS DeviceClose(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
)
{
	DEBUG_LOG( "Handle closed to DonnaAC" );
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return Irp->IoStatus.Status;
}

NTSTATUS DeviceCreate(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
)
{
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return Irp->IoStatus.Status;
}