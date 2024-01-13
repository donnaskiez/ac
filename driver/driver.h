#ifndef DRIVER_H
#define DRIVER_H

#include <ntifs.h>
#include <wdftypes.h>
#include <wdf.h>

#include "common.h"
#include "queue.h"
#include "modules.h"
#include "integrity.h"
#include "callbacks.h"

NTSTATUS
ProcLoadInitialiseProcessConfig(_In_ PIRP Irp);

VOID
GetProtectedProcessEProcess(_Out_ PEPROCESS* Process);

VOID
GetProtectedProcessId(_Out_ PLONG ProcessId);

VOID
ReadProcessInitialisedConfigFlag(_Out_ PBOOLEAN Flag);

NTSTATUS
QueryActiveApcContextsForCompletion();

VOID
TerminateProtectedProcessOnViolation();

NTSTATUS
ProcLoadEnableObCallbacks();

VOID
ProcCloseDisableObCallbacks();

VOID
ProcCloseClearProcessConfiguration();

VOID
GetCallbackConfigStructure(_Out_ POB_CALLBACKS_CONFIG* CallbackConfiguration);

LPCSTR
GetDriverName();

PDEVICE_OBJECT
GetDriverDeviceObject();

PDRIVER_OBJECT
GetDriverObject();

PIRP_QUEUE_HEAD
GetIrpQueueHead();

PSYS_MODULE_VAL_CONTEXT
GetSystemModuleValidationContext();

PUNICODE_STRING
GetDriverPath();

PUNICODE_STRING
GetDriverRegistryPath();

PUNICODE_STRING
GetDriverDeviceName();

PUNICODE_STRING
GetDriverSymbolicLink();

PSYSTEM_INFORMATION
GetDriverConfigSystemInformation();

PREPORT_QUEUE_HEAD
GetDriverReportQueue();

PTHREAD_LIST_HEAD
GetThreadList();

PDRIVER_LIST_HEAD
GetDriverList();

PPROCESS_LIST_HEAD
GetProcessList();

PUINT64
GetApcContextArray();

VOID
AcquireDriverConfigLock();

VOID
ReleaseDriverConfigLock();

BOOLEAN
IsDriverUnloading();

#endif