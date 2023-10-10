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

//_Dispatch_type_(IRP_MJ_SYSTEM_CONTROL)
NTSTATUS
DeviceControl(
	_In_ PDRIVER_OBJECT DriverObject,
	_Inout_ PIRP Irp
);

_Dispatch_type_(IRP_MJ_CLOSE)
NTSTATUS
DeviceClose(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
);

_Dispatch_type_(IRP_MJ_CREATE)
NTSTATUS
DeviceCreate(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
);

#endif