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
	CHAR motherboard_serial[ MOTHERBOARD_SERIAL_CODE_LENGTH ];
	CHAR drive_0_serial[ DEVICE_DRIVE_0_SERIAL_CODE_LENGTH ];

}SYSTEM_INFORMATION, * PSYSTEM_INFORMATION;

NTSTATUS InitialiseProcessConfigOnProcessLaunch(
	_In_ PIRP Irp
);

VOID GetProtectedProcessEProcess(
	_Out_ PEPROCESS* Process
);


VOID GetProtectedProcessId(
	_Out_ PLONG ProcessId
);

VOID ReadProcessInitialisedConfigFlag(
	_Out_ PBOOLEAN Flag
);

VOID GetDriverPath(
	_Out_ PUNICODE_STRING DriverPath
);

VOID GetDriverConfigSystemInformation(
	_Out_ PSYSTEM_INFORMATION* SystemInformation
);

VOID GetApcContext(
	_Inout_ PVOID* Context,
	_In_ LONG ContextIdentifier
);

VOID InsertApcContext(
	_In_ PVOID Context
);

VOID
GetApcContextByIndex(
	_Inout_ PVOID* Context,
	_In_ INT Index
);

VOID
IncrementApcCount(
	_In_ LONG ContextId
);

VOID
FreeApcAndDecrementApcCount(
	_In_ PRKAPC Apc,
	_In_ LONG ContextId
);

NTSTATUS
QueryActiveApcContextsForCompletion();

VOID 
TerminateProtectedProcessOnViolation();

VOID 
ClearProcessConfigOnProcessTermination();

#endif