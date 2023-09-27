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

/*
* This structure is strictly for driver related stuff
* that should only be written at driver entry.
* 
* Note that the lock isnt really needed here but Im using one
* just in case c:
*/

#define MAXIMUM_APC_CONTEXTS 10

typedef struct _DRIVER_CONFIG
{
	UNICODE_STRING unicode_driver_name;
	ANSI_STRING ansi_driver_name;
	UNICODE_STRING device_name;
	UNICODE_STRING device_symbolic_link;
	UNICODE_STRING driver_path;
	UNICODE_STRING registry_path;
	SYSTEM_INFORMATION system_information;
	PVOID apc_contexts[ MAXIMUM_APC_CONTEXTS ];
	KGUARDED_MUTEX lock;

}DRIVER_CONFIG, *PDRIVER_CONFIG;

/*
* This structure can change at anytime based on whether
* the target process to protect is open / closed / changes etc.
*/
typedef struct _PROCESS_CONFIG
{
	BOOLEAN initialised;
	LONG um_handle;
	LONG km_handle;
	PEPROCESS protected_process_eprocess;
	KGUARDED_MUTEX lock;

}PROCESS_CONFIG, *PPROCESS_CONFIG;

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

VOID RemoveApcFromApcContextList(
	_In_ PLIST_HEAD ListHead,
	_Inout_ PLIST_ITEM ListEntry
);

VOID InsertApcIntoApcContextList(
	_In_ PLIST_HEAD ListHead,
	_In_ PAPC_ENTRY ApcStatus
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

VOID TerminateProtectedProcessOnViolation();

VOID ClearProcessConfigOnProcessTermination();

NTSTATUS
QueryActiveApcContextForCompletion(
	_In_ LONG ContextId
);

#endif