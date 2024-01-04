#include "driver.h"

UNICODE_STRING DRIVER_NAME = RTL_CONSTANT_STRING(L"donna-ac-test");
UNICODE_STRING DRIVER_LINK = RTL_CONSTANT_STRING(L"donna-ac-test-link");

#define IOCTL_RUN_NMI_CALLBACKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20001, METHOD_BUFFERED, FILE_ANY_ACCESS)

NTSTATUS
DeviceControl(
	_In_ PDRIVER_OBJECT DriverObject,
	_Inout_ PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DriverObject);

	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION stack_location = IoGetCurrentIrpStackLocation(Irp);

	switch (stack_location->Parameters.DeviceIoControl.IoControlCode)
	{

	}
end:
	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS
DeviceClose(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

NTSTATUS
DeviceCreate(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

STATIC
VOID
DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	IoDeleteDevice(DriverObject->DeviceObject);
	DEBUG_LOG("Driver unloaded");
}

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	NTSTATUS status;
	
	status = IoCreateDevice(
		DriverObject,
		NULL,
		&DRIVER_NAME,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&DriverObject->DeviceObject
	);

	if (!NT_SUCCESS(status))
	{
		DEBUG_ERROR("IoCreateDevice failed with status %x", status);
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	status = IoCreateSymbolicLink(
		&DRIVER_LINK,
		&DRIVER_NAME
	);

	if (!NT_SUCCESS(status))
	{
		DEBUG_ERROR("failed to create symbolic link");
		IoDeleteDevice(DriverObject->DeviceObject);
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
	DriverObject->DriverUnload = DriverUnload;

	return STATUS_SUCCESS;
}
