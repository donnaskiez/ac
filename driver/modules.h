#ifndef MODULES_H
#define MODULES_H

#include <ntifs.h>
#include <intrin.h>

#include "common.h"
#include "queue.h"

typedef struct NMI_CALLBACK_FAILURE
{
	INT report_code;
	INT were_nmis_disabled;
	UINT64 kthread_address;
	UINT64 invalid_rip;

}NMI_CALLBACK_FAILURE, * PNMI_CALLBACK_FAILURE;

typedef struct _MODULE_VALIDATION_FAILURE
{
	INT report_code;
	INT report_type;
	UINT64 driver_base_address;
	UINT64 driver_size;
	CHAR driver_name[128];

}MODULE_VALIDATION_FAILURE, * PMODULE_VALIDATION_FAILURE;

#define APC_STACKWALK_BUFFER_SIZE 4096

typedef struct _APC_STACKWALK_REPORT
{
	INT report_code;
	UINT64 kthread_address;
	UINT64 invalid_rip;
	CHAR driver[APC_STACKWALK_BUFFER_SIZE];

}APC_STACKWALK_REPORT, * PAPC_STACKWALK_REPORT;

typedef struct _APC_OPERATION_ID
{
	int operation_id;

}APC_OPERATION_ID, * PAPC_OPERATION_ID;

/* system modules information */

typedef struct _SYSTEM_MODULES
{
	PVOID address;
	INT module_count;

}SYSTEM_MODULES, * PSYSTEM_MODULES;

#define APC_CONTEXT_ID_STACKWALK 0x1

typedef struct _APC_CONTEXT_HEADER
{
	LONG context_id;
	volatile INT count;
	volatile INT allocation_in_progress;

}APC_CONTEXT_HEADER, * PAPC_CONTEXT_HEADER;

typedef struct _APC_STACKWALK_CONTEXT
{
	APC_CONTEXT_HEADER header;
	PSYSTEM_MODULES modules;

}APC_STACKWALK_CONTEXT, * PAPC_STACKWALK_CONTEXT;

NTSTATUS
GetSystemModuleInformation(
	_Out_ PSYSTEM_MODULES ModuleInformation
);

NTSTATUS
HandleValidateDriversIOCTL(
	_Inout_ PIRP Irp
);

PRTL_MODULE_EXTENDED_INFO
FindSystemModuleByName(
	_In_ LPCSTR ModuleName,
	_In_ PSYSTEM_MODULES SystemModules
);

NTSTATUS
HandleNmiIOCTL(
	_Inout_ PIRP Irp
);

BOOLEAN
FreeApcContextStructure(
	_Inout_ PAPC_CONTEXT_HEADER Context
);

NTSTATUS
ValidateThreadsViaKernelApc();

VOID
FreeApcStackwalkApcContextInformation(
	_Inout_ PAPC_STACKWALK_CONTEXT Context
);

NTSTATUS
IsInstructionPointerInInvalidRegion(
	_In_ UINT64 RIP,
	_In_ PSYSTEM_MODULES SystemModules,
	_Out_ PBOOLEAN Result
);

BOOLEAN
FlipKThreadMiscFlagsFlag(
	_In_ PKTHREAD Thread,
	_In_ ULONG FlagIndex,
	_In_ BOOLEAN NewValue
);

NTSTATUS
LaunchInterProcessInterrupt(
	_In_ PIRP Irp
);

#endif
