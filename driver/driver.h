#ifndef DRIVER_H
#define DRIVER_H

#include <ntifs.h>
#include <wdftypes.h>
#include <wdf.h>
#include "common.h"

#define DRIVER_PATH_MAX_LENGTH 512
#define MOTHERBOARD_SERIAL_CODE_LENGTH 128

typedef struct _SYSTEM_INFORMATION
{
	CHAR motherboard_uuid[ MOTHERBOARD_SERIAL_CODE_LENGTH ];

}SYSTEM_INFORMATION, * PSYSTEM_INFORMATION;

/*
* This structure is strictly for driver related stuff
* that should only be written at driver entry.
* 
* Note that the lock isnt really needed here but Im using one
* just in case c:
*/
typedef struct _DRIVER_CONFIG
{
	UNICODE_STRING unicode_driver_name;
	ANSI_STRING ansi_driver_name;
	UNICODE_STRING device_name;
	UNICODE_STRING device_symbolic_link;
	UNICODE_STRING driver_path;
	UNICODE_STRING registry_path;
	SYSTEM_INFORMATION system_information;
	KGUARDED_MUTEX lock;

}DRIVER_CONFIG, *PDRIVER_CONFIG;

/*
* This structure can change at anytime based on whether
* the target process to protect is open / closed / changes etc.
*/
typedef struct _PROCESS_CONFIG
{
	BOOLEAN initialised;
	LONG protected_process_id;
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
	_In_ PUNICODE_STRING DriverPath
);


VOID TerminateProtectedProcessOnViolation();

VOID ClearProcessConfigOnProcessTermination();

#endif