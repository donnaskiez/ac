#ifndef IO_H
#define IO_H

#include <ntifs.h>
#include <wdftypes.h>
#include <wdf.h>
#include "common.h"

typedef struct _DRIVER_INITIATION_INFORMATION
{
        ULONG protected_process_id;

} DRIVER_INITIATION_INFORMATION, *PDRIVER_INITIATION_INFORMATION;

NTSTATUS
DeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);

NTSTATUS
DeviceClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);

NTSTATUS
DeviceCreate(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);

NTSTATUS
ValidateIrpOutputBuffer(_In_ PIRP Irp, _In_ ULONG RequiredSize);

NTSTATUS
ValidateIrpInputBuffer(_In_ PIRP Irp, _In_ ULONG RequiredSize);

NTSTATUS
IrpQueueInitialise();

#endif