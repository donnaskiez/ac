#ifndef DRIVER_H
#define DRIVER_H

#include <ntifs.h>
#include <wdftypes.h>
#include <wdf.h>

#include "common.h"
#include "queue.h"
#include "modules.h"

#define DRIVER_PATH_MAX_LENGTH 512
#define MOTHERBOARD_SERIAL_CODE_LENGTH 64
#define DEVICE_DRIVE_0_SERIAL_CODE_LENGTH 64

#define MAX_REPORTS_PER_IRP 20

#define POOL_TAG_STRINGS 'strs'

#define IOCTL_STORAGE_QUERY_PROPERTY 0x002D1400

typedef struct _SYSTEM_INFORMATION
{
	CHAR motherboard_serial[MOTHERBOARD_SERIAL_CODE_LENGTH];
	CHAR drive_0_serial[DEVICE_DRIVE_0_SERIAL_CODE_LENGTH];

}SYSTEM_INFORMATION, * PSYSTEM_INFORMATION;

typedef struct _OB_CALLBACKS_CONFIG
{
	PVOID registration_handle;
	KGUARDED_MUTEX lock;

}OB_CALLBACKS_CONFIG, * POB_CALLBACKS_CONFIG;

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
NTSTATUS
ProcLoadInitialiseProcessConfig(
	_In_ PIRP Irp
);

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
VOID 
GetProtectedProcessEProcess(
	_Out_ PEPROCESS* Process
);

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
VOID 
GetProtectedProcessId(
	_Out_ PLONG ProcessId
);

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
VOID 
ReadProcessInitialisedConfigFlag(
	_Out_ PBOOLEAN Flag
);

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
VOID GetDriverPath(
	_Out_ PUNICODE_STRING DriverPath
);

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
VOID GetDriverConfigSystemInformation(
	_Out_ PSYSTEM_INFORMATION* SystemInformation
);

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
VOID 
GetApcContext(
	_Inout_ PVOID* Context,
	_In_ LONG ContextIdentifier
);

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
NTSTATUS 
InsertApcContext(
	_In_ PVOID Context
);

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
VOID
GetApcContextByIndex(
	_Inout_ PVOID* Context,
	_In_ INT Index
);

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
VOID
IncrementApcCount(
	_In_ LONG ContextId
);

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
VOID
FreeApcAndDecrementApcCount(
	_Inout_ PRKAPC Apc,
	_In_ LONG ContextId
);

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
NTSTATUS
QueryActiveApcContextsForCompletion();

VOID
TerminateProtectedProcessOnViolation();

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
NTSTATUS
ProcLoadEnableObCallbacks();

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
VOID
ProcCloseDisableObCallbacks();

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
VOID
ProcCloseClearProcessConfiguration();

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
VOID
GetCallbackConfigStructure(
	_Out_ POB_CALLBACKS_CONFIG* CallbackConfiguration
);

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
VOID
ImageLoadSetProcessId(
	_In_ HANDLE ProcessId
);

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
VOID
GetDriverDeviceName(
	_Out_ PUNICODE_STRING DeviceName
);

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
VOID
GetDriverRegistryPath(
	_Out_ PUNICODE_STRING RegistryPath
);

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
VOID 
GetDriverName(
	_Out_ LPCSTR* DriverName
);

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
VOID
GetDriverSymbolicLink(
	_Out_ PUNICODE_STRING DeviceSymbolicLink
);

#endif