#ifndef DRIVER_H
#define DRIVER_H

#include <ntifs.h>
#include <wdftypes.h>
#include <wdf.h>

#include "common.h"
#include "queue.h"
#include "modules.h"
#include "integrity.h"

#define DRIVER_PATH_MAX_LENGTH            512
#define MOTHERBOARD_SERIAL_CODE_LENGTH    64
#define DEVICE_DRIVE_0_SERIAL_CODE_LENGTH 64

#define MAX_REPORTS_PER_IRP 20

#define POOL_TAG_STRINGS 'strs'

#define IOCTL_STORAGE_QUERY_PROPERTY 0x002D1400

#define MAXIMUM_APC_CONTEXTS 10

typedef struct _TIMER_OBJECT
{
        /*
         * state = 1: callback in progress
         * state = 0: no callback in progress (i.e safe to free and unregister)
         */
        volatile LONG state;

        PKTIMER      timer;
        PKDPC        dpc;
        PIO_WORKITEM work_item;

} TIMER_OBJECT, *PTIMER_OBJECT;

typedef enum _ENVIRONMENT_TYPE
{
        NativeWindows = 0,
        Vmware,
        VirtualBox

} ENVIRONMENT_TYPE;

typedef enum _PROCESSOR_TYPE
{
        Unknown = 0,
        GenuineIntel,
        AuthenticAmd

} PROCESSOR_TYPE;

#define VENDOR_STRING_MAX_LENGTH 256

typedef struct _SYSTEM_INFORMATION
{
        CHAR               motherboard_serial[MOTHERBOARD_SERIAL_CODE_LENGTH];
        CHAR               drive_0_serial[DEVICE_DRIVE_0_SERIAL_CODE_LENGTH];
        CHAR               vendor[VENDOR_STRING_MAX_LENGTH];
        BOOLEAN            virtualised_environment;
        ENVIRONMENT_TYPE   environment;
        PROCESSOR_TYPE     processor;
        RTL_OSVERSIONINFOW os_information;

} SYSTEM_INFORMATION, *PSYSTEM_INFORMATION;

typedef struct _OB_CALLBACKS_CONFIG
{
        PVOID          registration_handle;
        KGUARDED_MUTEX lock;

} OB_CALLBACKS_CONFIG, *POB_CALLBACKS_CONFIG;

typedef struct _IRP_QUEUE_HEAD
{
        SINGLE_LIST_ENTRY start;
        volatile INT      count;
        KGUARDED_MUTEX    lock;

} IRP_QUEUE_HEAD, *PIRP_QUEUE_HEAD;

typedef struct _IRP_QUEUE_ENTRY
{
        SINGLE_LIST_ENTRY entry;
        PIRP              irp;

} IRP_QUEUE_ENTRY, *PIRP_QUEUE_ENTRY;

NTSTATUS
ProcLoadInitialiseProcessConfig(_In_ PIRP Irp);

VOID
GetProtectedProcessEProcess(_Out_ PEPROCESS* Process);

VOID
GetProtectedProcessId(_Out_ PLONG ProcessId);

VOID
ReadProcessInitialisedConfigFlag(_Out_ PBOOLEAN Flag);

VOID
GetDriverPath(_Out_ PUNICODE_STRING DriverPath);

VOID
GetDriverConfigSystemInformation(_Out_ PSYSTEM_INFORMATION* SystemInformation);

VOID
GetApcContext(_Inout_ PVOID* Context, _In_ LONG ContextIdentifier);

VOID
InsertApcContext(_In_ PVOID Context);

VOID
GetApcContextByIndex(_Inout_ PVOID* Context, _In_ INT Index);

VOID
IncrementApcCount(_In_ LONG ContextId);

VOID
FreeApcAndDecrementApcCount(_Inout_ PRKAPC Apc, _In_ LONG ContextId);

NTSTATUS
QueryActiveApcContextsForCompletion();

VOID
TerminateProtectedProcessOnViolation();

NTSTATUS
ProcLoadEnableObCallbacks();

VOID
ProcCloseDisableObCallbacks();

VOID
ProcCloseClearProcessConfiguration();

VOID
GetCallbackConfigStructure(_Out_ POB_CALLBACKS_CONFIG* CallbackConfiguration);

VOID
ImageLoadSetProcessId(_In_ HANDLE ProcessId);

VOID
GetDriverDeviceName(_Out_ PUNICODE_STRING DeviceName);

VOID
GetDriverRegistryPath(_Out_ PUNICODE_STRING RegistryPath);

VOID
GetDriverName(_Out_ LPCSTR* DriverName);

VOID
GetDriverSymbolicLink(_Out_ PUNICODE_STRING DeviceSymbolicLink);

PDEVICE_OBJECT
GetDriverDeviceObject();

GetSystemModuleValidationContext(_Out_ PSYS_MODULE_VAL_CONTEXT* Context);

PDRIVER_OBJECT
GetDriverObject();

PIRP_QUEUE_HEAD
GetIrpQueueHead();

#endif