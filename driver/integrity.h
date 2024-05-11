#ifndef INTEGRITY_H
#define INTEGRITY_H

#include <ntifs.h>

#include "common.h"

typedef struct _MODULE_DISPATCHER_HEADER {
    volatile UINT32 validated; // if this is > 0, a thread is already using it
    UINT8           result;

} MODULE_DISPATCHER_HEADER, *PMODULE_DISPATCHER_HEADER;

typedef struct _SYSTEM_MODULE_INFORMATION {
    MODULE_DISPATCHER_HEADER dispatcher_header;
    RTL_MODULE_EXTENDED_INFO module_information;

} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

#define VERIFICATION_THREAD_COUNT 4

typedef struct _SYS_MODULE_VAL_CONTEXT {
    /* Stores the number of actively executing worker threads */
    volatile LONG active_thread_count;

    /* determines whether a validation is in progress */
    volatile LONG active;

    /* determines whether a validation is complete */
    volatile LONG complete;

    /* current count of validated modules */
    volatile LONG current_count;

    /* total count of modules */
    UINT32 total_count;

    /* number of modules to validate in a single sweep */
    UINT32 block_size;

    /* pointer to the buffer containing the system module information */
    PRTL_MODULE_EXTENDED_INFO module_info;

    /* pointer to the array of dispatcher info used to synchonize threads */
    PMODULE_DISPATCHER_HEADER dispatcher_info;

    /* array of pointers to work items, used to free work items when
     * complete */
    PIO_WORKITEM work_items[VERIFICATION_THREAD_COUNT];

} SYS_MODULE_VAL_CONTEXT, *PSYS_MODULE_VAL_CONTEXT;

typedef enum _SMBIOS_TABLE_INDEX {
    SmbiosInformation = 0,
    SystemInformation,
    VendorSpecificInformation,
    ChassisInformation

} SMBIOS_TABLE_INDEX;

#define SMBIOS_VMWARE_SERIAL_NUMBER_SUB_INDEX 3
#define SMBIOS_NATIVE_SERIAL_NUMBER_SUB_INDEX 4
#define SMBIOS_VENDOR_STRING_SUB_INDEX        1

NTSTATUS
GetDriverImageSize(_Inout_ PIRP Irp);

NTSTATUS
RetrieveInMemoryModuleExecutableSections(_Inout_ PIRP Irp);

NTSTATUS
ValidateProcessLoadedModule(_Inout_ PIRP Irp);

NTSTATUS
GetHardDiskDriveSerialNumber(_Inout_ PVOID ConfigDrive0Serial,
                             _In_ SIZE_T   ConfigDrive0MaxSize);

NTSTATUS
ParseSMBIOSTable(_Out_ PVOID             Buffer,
                 _In_ SIZE_T             BufferSize,
                 _In_ SMBIOS_TABLE_INDEX TableIndex,
                 _In_ ULONG              TableSubIndex);

NTSTATUS
DetectEptHooksInKeyFunctions();

PVOID
ScanForSignature(_In_ PVOID  BaseAddress,
                 _In_ SIZE_T MaxLength,
                 _In_ LPCSTR Signature,
                 _In_ SIZE_T SignatureLength);

NTSTATUS
GetOsVersionInformation(_Out_ PRTL_OSVERSIONINFOW VersionInfo);

NTSTATUS
SystemModuleVerificationDispatcher();

NTSTATUS
ValidateOurDriverImage();

VOID
CleanupValidationContextOnUnload(_In_ PSYS_MODULE_VAL_CONTEXT Context);

UINT32
CalculateCpuCoreUsage(_In_ UINT32 Core);

NTSTATUS
HashModule(_In_ PRTL_MODULE_EXTENDED_INFO Module, _Out_ PVOID Hash);

VOID
ValidateSystemModule(_In_ PRTL_MODULE_EXTENDED_INFO Module);

BOOLEAN
ValidateOurDriversDispatchRoutines();

VOID
DeferredModuleHashingCallback(_In_ PDEVICE_OBJECT DeviceObject,
                              _In_opt_ PVOID      Context);

VOID
FindWinLogonProcess(_In_ PPROCESS_LIST_ENTRY Entry, _In_opt_ PVOID Context);

NTSTATUS
InitialiseHeartbeatConfiguration(
    _Inout_ PHEARTBEAT_CONFIGURATION Configuration);

VOID
FreeHeartbeatConfiguration(_Inout_ PHEARTBEAT_CONFIGURATION Configuration);

#endif
