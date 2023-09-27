#ifndef IOCTL_H
#define IOCTL_H

#include <ntifs.h>
#include <wdftypes.h>
#include <wdf.h>
#include "common.h"

typedef struct _DRIVER_INITIATION_INFORMATION
{
	LONG protected_process_id;

} DRIVER_INITIATION_INFORMATION, * PDRIVER_INITIATION_INFORMATION;

NTSTATUS 
DeviceControl(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PIRP Irp
);

NTSTATUS 
DeviceClose(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
);

NTSTATUS 
DeviceCreate(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
);

#endif