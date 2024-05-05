#ifndef IO_H
#define IO_H

#include <ntifs.h>
#include <wdftypes.h>
#include <wdf.h>
#include "common.h"

typedef struct _SHARED_MAPPING_INIT {
    PVOID  buffer;
    SIZE_T size;

} SHARED_MAPPING_INIT, *PSHARED_MAPPING_INIT;

typedef enum _SHARED_STATE_OPERATION_ID {
    ssRunNmiCallbacks = 0,
    ssValidateDriverObjects,
    ssEnumerateHandleTables,
    ssScanForUnlinkedProcesses,
    ssPerformModuleIntegrityCheck,
    ssScanForAttachedThreads,
    ssScanForEptHooks,
    ssInitiateDpcStackwalk,
    ssValidateSystemModules,
    ssValidateWin32kDispatchTables
} SHARED_STATE_OPERATION_ID;

typedef struct _SHARED_STATE {
    volatile UINT32 status;
    volatile UINT16 operation_id;

} SHARED_STATE, *PSHARED_STATE;

typedef struct _SHARED_MAPPING {
    volatile LONG    work_item_status;
    PVOID            user_buffer;
    PSHARED_STATE    kernel_buffer;
    PMDL             mdl;
    SIZE_T           size;
    volatile BOOLEAN active;
    KTIMER           timer;
    KDPC             timer_dpc;
    PIO_WORKITEM     work_item;

} SHARED_MAPPING, *PSHARED_MAPPING;

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

NTSTATUS
IrpQueueCompletePacket(_In_ PVOID Buffer, _In_ ULONG BufferSize);

#endif