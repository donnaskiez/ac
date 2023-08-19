#ifndef IOCTL_H
#define IOCTL_H

#include <ntifs.h>
#include <wdftypes.h>
#include <wdf.h>

#include "nmi.h"

#define IOCCTL_RUN_NMI_CALLBACKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VALIDATE_DRIVER_OBJECTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2002, METHOD_BUFFERED, FILE_ANY_ACCESS)

NTSTATUS DeviceControl(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PIRP Irp
);

NTSTATUS DeviceClose(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
);

NTSTATUS DeviceCreate(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
);

#endif