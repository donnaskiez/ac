#ifndef MODULES_H
#define MODULES_H

#include <ntifs.h>
#include <intrin.h>

#include "common.h"
#include "queue.h"

typedef struct _APC_OPERATION_ID {
    int operation_id;

} APC_OPERATION_ID, *PAPC_OPERATION_ID;

/* system modules information */

typedef struct _SYSTEM_MODULES {
    PVOID address;
    INT   module_count;

} SYSTEM_MODULES, *PSYSTEM_MODULES;

#define APC_CONTEXT_ID_STACKWALK 0x1

typedef struct _APC_CONTEXT_HEADER {
    LONG         context_id;
    volatile INT count;
    volatile INT allocation_in_progress;

} APC_CONTEXT_HEADER, *PAPC_CONTEXT_HEADER;

typedef struct _APC_STACKWALK_CONTEXT {
    APC_CONTEXT_HEADER header;
    PSYSTEM_MODULES    modules;

} APC_STACKWALK_CONTEXT, *PAPC_STACKWALK_CONTEXT;

NTSTATUS
GetSystemModuleInformation(_Out_ PSYSTEM_MODULES ModuleInformation);

NTSTATUS
HandleValidateDriversIOCTL();

PRTL_MODULE_EXTENDED_INFO
FindSystemModuleByName(_In_ LPCSTR          ModuleName,
                       _In_ PSYSTEM_MODULES SystemModules);

NTSTATUS
HandleNmiIOCTL();

BOOLEAN
FreeApcContextStructure(_Inout_ PAPC_CONTEXT_HEADER Context);

NTSTATUS
ValidateThreadsViaKernelApc();

VOID
FreeApcStackwalkApcContextInformation(_Inout_ PAPC_STACKWALK_CONTEXT Context);

BOOLEAN
IsInstructionPointerInInvalidRegion(_In_ UINT64          RIP,
                                    _In_ PSYSTEM_MODULES SystemModules);

PVOID
FindDriverBaseNoApi(_In_ PDRIVER_OBJECT DriverObject, _In_ PWCH Name);

NTSTATUS
DispatchStackwalkToEachCpuViaDpc();

NTSTATUS
ValidateHalDispatchTables();

PVOID
FindDriverBaseNoApi(_In_ PDRIVER_OBJECT DriverObject, _In_ PWCH Name);

NTSTATUS
GetDriverObjectByDriverName(_In_ PUNICODE_STRING  DriverName,
                            _Out_ PDRIVER_OBJECT* DriverObject);

NTSTATUS
ValidateWin32kDispatchTables();

#endif
