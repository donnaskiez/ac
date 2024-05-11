#ifndef DRIVER_H
#define DRIVER_H

#include "common.h"

#include <wdf.h>

#include "queue.h"
#include "modules.h"
#include "integrity.h"
#include "callbacks.h"

BCRYPT_ALG_HANDLE*
GetCryptAlgHandle();

NTSTATUS
QueryActiveApcContextsForCompletion();

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

PACTIVE_SESSION
GetActiveSession();

PSHARED_MAPPING
GetSharedMappingConfig();

VOID
UnsetNmiInProgressFlag();

BOOLEAN
IsNmiInProgress();

BOOLEAN
HasDriverLoaded();

#endif