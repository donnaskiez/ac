#ifndef DRIVER_H
#define DRIVER_H

#include <ntifs.h>
#include <wdftypes.h>
#include <wdf.h>

typedef struct _DRIVER_CONFIG
{
	BOOLEAN initialised;
	LONG protected_process_id;
	PEPROCESS protected_process_eprocess;
	KGUARDED_MUTEX lock;

}DRIVER_CONFIG, *PDRIVER_CONFIG;

NTSTATUS InitialiseDriverConfigOnProcessLaunch(
	_In_ PIRP Irp
);

VOID GetProtectedProcessEProcess(
	_In_ PEPROCESS Process
);


VOID GetProtectedProcessId(
	_In_ PLONG ProcessId
);


VOID ClearDriverConfigOnProcessTermination(
	_In_ PIRP Irp
);

NTSTATUS InitiateDriverCallbacks();

#endif