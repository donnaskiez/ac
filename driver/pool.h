#ifndef POOL_H
#define POOL_H

#include <ntifs.h>
#include "common.h"

#define REPORT_INVALID_PROCESS_BUFFER_SIZE 4096

typedef struct _INVALID_PROCESS_ALLOCATION_REPORT
{
	INT report_code;
	CHAR process[ REPORT_INVALID_PROCESS_BUFFER_SIZE ];

}INVALID_PROCESS_ALLOCATION_REPORT, *PINVALID_PROCESS_ALLOCATION_REPORT;

NTSTATUS 
FindUnlinkedProcesses(
	_In_ PIRP Irp
);

VOID 
GetPsActiveProcessHead(
	_In_ PUINT64 Address
);

PKDDEBUGGER_DATA64 
GetGlobalDebuggerData();

#endif