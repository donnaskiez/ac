#ifndef CALLBACKS_H
#define CALLBACKS_H

#include <ntifs.h>
#include <wdftypes.h>
#include <wdf.h>

#define REPORT_ILLEGAL_HANDLE_OPERATION 70

#define HANDLE_REPORT_PROCESS_NAME_MAX_LENGTH 64

#define REPORT_POOL_TAG 'repo'

#define MAX_HANDLE_REPORTS_PER_IRP 10

typedef struct _OPEN_HANDLE_FAILURE_REPORT_HEADER
{
	INT count;

}OPEN_HANDLE_FAILURE_REPORT_HEADER, *POPEN_HANDLE_FAILURE_REPORT_HEADER;

typedef struct _OPEN_HANDLE_FAILURE_REPORT
{
	INT report_code;
	INT is_kernel_handle;
	LONG process_id;
	LONG thread_id;
	LONG desired_access;
	CHAR process_name[ HANDLE_REPORT_PROCESS_NAME_MAX_LENGTH ];

}OPEN_HANDLE_FAILURE_REPORT, *POPEN_HANDLE_FAILURE_REPORT;

//handle access masks
//https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
#define PROCESS_CREATE_PROCESS 0x0080
#define PROCESS_TERMINATE 0x0001
#define PROCESS_CREATE_THREAD 0x0002
#define PROCESS_DUP_HANDLE 0x0040
#define PROCESS_QUERY_INFORMATION 0x0400
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#define PROCESS_SET_INFORMATION 0x0200
#define PROCESS_SET_QUOTA 0x0100
#define PROCESS_SUSPEND_RESUME 0x0800
#define PROCESS_VM_OPERATION 0x0008
#define PROCESS_VM_READ 0x0010
#define PROCESS_VM_WRITE 0x0020

VOID ObPostOpCallbackRoutine(
	_In_ PVOID RegistrationContext,
	_In_ POB_POST_OPERATION_INFORMATION OperationInformation
);

OB_PREOP_CALLBACK_STATUS ObPreOpCallbackRoutine(
	_In_ PVOID RegistrationContext,
	_In_ POB_PRE_OPERATION_INFORMATION OperationInformation
);

VOID InitCallbackReportQueue(PBOOLEAN Status);
VOID DeleteCallbackReportQueueHead();

NTSTATUS HandlePeriodicCallbackReportQueue(
	_In_ PIRP Irp
);

#endif
