#ifndef IMPORTS_H
#define IMPORTS_H

#include "common.h"

PVOID
FindNtExport(PDRIVER_OBJECT DriverObject, PCZPSTR ExportName);

NTSTATUS
ResolveDynamicImports(_In_ PDRIVER_OBJECT DriverObject);

#define IMPORT_FUNCTION_MAX_LENGTH 128
#define IMPORT_FUNCTION_COUNT      256

// clang-format off

typedef 
void* (*pObDereferenceObject)(
        void* Object
        );

typedef 
void* (*pObReferenceObject)(
        void* Object
        );

typedef 
NTSTATUS (*pPsLookupThreadByThreadId)(
        HANDLE ThreadId, 
        PETHREAD* Thread
        );

typedef 
BOOLEAN (*pMmIsAddressValid)(
        void* VirtualAddress
        );

typedef 
NTSTATUS (*pPsSetCreateProcessNotifyRoutine)(
        PCREATE_PROCESS_NOTIFY_ROUTINE NotifyRoutine,
        BOOLEAN Remove
        );

typedef 
NTSTATUS (*pPsRemoveCreateThreadNotifyRoutine)(
        PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine
        );

typedef 
HANDLE (*pPsGetCurrentThreadId)(
        void
        );

typedef 
HANDLE (*pPsGetProcessId)(
        PEPROCESS Process
        );

typedef 
NTSTATUS (*pPsLookupProcessByProcessId)(
        HANDLE ProcessId,
        PEPROCESS* Process
        );

typedef 
void* (*pExEnumHandleTable)(
        PHANDLE_TABLE HandleTable,
        void*     Callback,
        void*     Context,
        PHANDLE   Handle);

typedef 
POBJECT_TYPE (*pObGetObjectType)(
        void* Object
        );

typedef 
void (*pExfUnblockPushLock)(
        PEX_PUSH_LOCK PushLock, 
        void* WaitBlock
        );

typedef 
LPCSTR (*pPsGetProcessImageFileName)(
        PEPROCESS Process
        );

typedef 
INT (*pstrcmp)(
        const CHAR* str1, 
        const CHAR* str2
        );

typedef 
PCHAR (*pstrstr)(
        const CHAR* haystack, 
        const CHAR* needle
        );

typedef 
void (*pRtlInitUnicodeString)(
        PUNICODE_STRING DestinationString, 
        PCWSTR SourceString
        );

typedef 
NTSTATUS (*pRtlQueryRegistryValues)(
        ULONG                     RelativeTo,
        PCWSTR                    Path,
        PRTL_QUERY_REGISTRY_TABLE QueryTable,
        void*                     Context,
        void*                     Environment
        );

typedef 
void* (*pMmGetSystemRoutineAddress)(
        PUNICODE_STRING SystemRoutineName
        );

typedef 
NTSTATUS (*pRtlUnicodeStringToAnsiString)(
        PANSI_STRING     DestinationString,
        PCUNICODE_STRING SourceString,
        BOOLEAN          AllocateDestinationString
        );

typedef 
void (*pRtlCopyUnicodeString)(
        PUNICODE_STRING  DestinationString,
        PCUNICODE_STRING SourceString
        );

typedef 
void (*pRtlFreeAnsiString)(
        PANSI_STRING AnsiString
        );

typedef 
void (*pKeInitializeGuardedMutex)(
        PKGUARDED_MUTEX GuardedMutex
        );

typedef 
NTSTATUS (*pIoCreateDevice)(
        PDRIVER_OBJECT  DriverObject,
        ULONG           DeviceExtensionSize,
        PUNICODE_STRING DeviceName,
        DEVICE_TYPE     DeviceType,
        ULONG           DeviceCharacteristics,
        BOOLEAN         Exclusive,
        PDEVICE_OBJECT  *DeviceObject
        );

typedef 
NTSTATUS (*pIoCreateSymbolicLink)(
        PUNICODE_STRING SymbolicLinkName,
        PUNICODE_STRING DeviceName
        );

typedef 
void (*pIoDeleteDevice)(
        PDEVICE_OBJECT DeviceObject
        );

typedef 
void (*pIoDeleteSymbolicLink)(
        PUNICODE_STRING SymbolicLinkName
        );

typedef 
NTSTATUS (*pObRegisterCallbacks)(
        POB_CALLBACK_REGISTRATION CallbackRegistration,
        void**                    RegistrationHandle
        );

typedef 
void (*pObUnRegisterCallbacks)(
        void* RegistrationHandle
        );

typedef 
NTSTATUS (*pPsSetCreateThreadNotifyRoutine)(
        PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine
        );

typedef 
void (*pKeRevertToUserAffinityThreadEx)(
        KAFFINITY Affinity
        );

typedef 
KAFFINITY (*pKeSetSystemAffinityThreadEx)(
        KAFFINITY Affinity
        );

typedef 
SIZE_T (*pstrnlen)(
        const CHAR* str, 
        SIZE_T maxCount
        );

typedef 
void (*pRtlInitAnsiString)(
        PANSI_STRING DestinationString, 
        PCSZ SourceString
        );

typedef 
NTSTATUS (*pRtlAnsiStringToUnicodeString)(
        PUNICODE_STRING DestinationString,
        PCANSI_STRING   SourceString,
        BOOLEAN         AllocateDestinationString
        );

typedef 
PEPROCESS (*pIoGetCurrentProcess)(
        void
        );

typedef 
NTSTATUS (*pRtlGetVersion)(
        PRTL_OSVERSIONINFOW lpVersionInformation
        );

typedef 
SIZE_T (*pRtlCompareMemory)(
        const void* Source1, 
        const void* Source2, 
        SIZE_T Length
        );

typedef 
NTSTATUS (*pExGetSystemFirmwareTable)(
        ULONG FirmwareTableProviderSignature,
        ULONG FirmwareTableID,
        void* pFirmwareTableBuffer,
        ULONG BufferLength,
        PULONG ReturnLength
        );

typedef 
PIO_WORKITEM (*pIoAllocateWorkItem)(
        PDEVICE_OBJECT DeviceObject
        );

typedef 
void (*pIoFreeWorkItem)(
        PIO_WORKITEM WorkItem
        );

typedef 
void (*pIoQueueWorkItem)(
        PIO_WORKITEM         IoWorkItem,
        PIO_WORKITEM_ROUTINE WorkerRoutine,
        WORK_QUEUE_TYPE      QueueType,
        void* Context
        );

typedef 
NTSTATUS (*pZwOpenFile)(
        PHANDLE            FileHandle,
        ACCESS_MASK        DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PIO_STATUS_BLOCK   IoStatusBlock,
        ULONG              ShareAccess,
        ULONG              OpenOptions
        );

typedef 
NTSTATUS (*pZwClose)(
        HANDLE Handle
        );

typedef 
NTSTATUS (*pZwCreateSection)(
        PHANDLE            SectionHandle,
        ACCESS_MASK        DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PLARGE_INTEGER     MaximumSize,
        ULONG              SectionPageProtection,
        ULONG              AllocationAttributes,
        HANDLE             FileHandle
        );

typedef 
NTSTATUS (*pZwMapViewOfSection)(
        HANDLE          SectionHandle,
        HANDLE          ProcessHandle,
        void**          BaseAddress,
        ULONG_PTR       ZeroBits,
        SIZE_T          CommitSize,
        PLARGE_INTEGER  SectionOffset,
        PSIZE_T         ViewSize,
        SECTION_INHERIT InheritDisposition,
        ULONG           AllocationType,
        ULONG           Win32Protect
        );

typedef 
NTSTATUS (*pZwUnmapViewOfSection)(
        HANDLE ProcessHandle, 
        void* BaseAddress
        );

typedef 
NTSTATUS (*pMmCopyMemory)(
        PVOID           TargetAddress,
        MM_COPY_ADDRESS SourceAddress,
        SIZE_T          NumberOfBytes,
        ULONG           Flags,
        PSIZE_T         NumberOfBytesTransferred
        );

typedef 
NTSTATUS (*pZwDeviceIoControlFile)(
        HANDLE           FileHandle,
        HANDLE           Event,
        PIO_APC_ROUTINE  ApcRoutine,
        void*            ApcContext,
        PIO_STATUS_BLOCK IoStatusBlock,
        ULONG            IoControlCode,
        void*            InputBuffer,
        ULONG            InputBufferLength,
        void*            OutputBuffer,
        ULONG            OutputBufferLength
        );

typedef 
void (*pKeStackAttachProcess)(
        PRKPROCESS Process, 
        PKAPC_STATE ApcState
        );

typedef 
void (*pKeUnstackDetachProcess)(
        PKAPC_STATE ApcState
        );

typedef 
NTSTATUS (*pKeWaitForSingleObject)(
        void*           Object,
        KWAIT_REASON    WaitReason,
        KPROCESSOR_MODE WaitMode,
        BOOLEAN         Alertable,
        PLARGE_INTEGER  Timeout
        );

typedef 
NTSTATUS (*pPsCreateSystemThread)(
        PHANDLE            ThreadHandle,
        ULONG              DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        HANDLE             ProcessHandle,
        PCLIENT_ID         ClientId,
        PKSTART_ROUTINE    StartRoutine,
        void*              StartContext
        );

typedef 
void (*pIofCompleteRequest)(
        PIRP Irp, 
        CCHAR PriorityBoost
        );

typedef 
NTSTATUS (*pObReferenceObjectByHandle)(
        HANDLE                     Handle,
        ACCESS_MASK                DesiredAccess,
        POBJECT_TYPE               ObjectType,
        KPROCESSOR_MODE            AccessMode,
        void**                     Object,
        POBJECT_HANDLE_INFORMATION HandleInformation
        );

typedef 
NTSTATUS (*pKeDelayExecutionThread)(
        KPROCESSOR_MODE WaitMode,
        BOOLEAN         Alertable,
        PLARGE_INTEGER  Interval
        );

typedef 
void* (*pKeRegisterNmiCallback)(
        void* CallbackRoutine, 
        void* Context
        );

typedef 
NTSTATUS (*pKeDeregisterNmiCallback)(
        void* Handle
        );

typedef 
ULONG (*pKeQueryActiveProcessorCount)(
        PKAFFINITY ActiveProcessors
        );

typedef 
void (*pExAcquirePushLockExclusiveEx)(
        PEX_PUSH_LOCK PushLock, 
        ULONG Flags
        );

typedef 
void (*pExReleasePushLockExclusiveEx)(
        PEX_PUSH_LOCK PushLock, 
        ULONG Flags
        );

typedef 
HANDLE (*pPsGetThreadId)(
        PETHREAD Thread
        );

typedef 
USHORT (*pRtlCaptureStackBackTrace)(
        ULONG  FramesToSkip,
        ULONG  FramesToCapture,
        void** BackTrace,
        PULONG BackTraceHash
        );

typedef 
NTSTATUS (*pZwOpenDirectoryObject)(
        PHANDLE            DirectoryHandle,
        ACCESS_MASK        DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes
        );

typedef 
void (*pKeInitializeAffinityEx)(
        PKAFFINITY_EX AffinityMask
        );

typedef 
void (*pKeAddProcessorAffinityEx)(
        PKAFFINITY_EX Affinity, 
        INT CoreNumber
        );

typedef 
NTSTATUS (*pRtlQueryModuleInformation)(
        ULONG* InformationLength,
        ULONG  SizePerModule,
        PVOID  InformationBuffer
        );

typedef 
void (*pKeInitializeApc)(
        PKAPC             Apc,
        PKTHREAD          Thread,
        KAPC_ENVIRONMENT  Environment,
        PKKERNEL_ROUTINE  KernelRoutine,
        PKRUNDOWN_ROUTINE RundownRoutine,
        PKNORMAL_ROUTINE  NormalRoutine,
        KPROCESSOR_MODE   ApcMode,
        void*             NormalContext
        );

typedef 
BOOLEAN (*pKeInsertQueueApc)(
        PKAPC     Apc,
        void*     SystemArgument1,
        void*     SystemArgument2,
        KPRIORITY Increment
        );

typedef 
void (*pKeGenericCallDpc)(
        PKDEFERRED_ROUTINE DpcRoutine, 
        void* Context
        );

typedef 
void (*pKeSignalCallDpcDone)(
        void* SystemArgument1
        );

typedef 
PPHYSICAL_MEMORY_RANGE (*pMmGetPhysicalMemoryRangesEx2)(
        PVOID PartitionObject, 
        ULONG Flags
        );

typedef 
void* (*pMmGetVirtualForPhysical)(
        PHYSICAL_ADDRESS PhysicalAddress
        );

typedef 
LONG_PTR (*pObfReferenceObject)(
        void* Object
        );

typedef 
void (*pExFreePoolWithTag)(
        void* P, 
        ULONG Tag
        );

typedef 
void* (*pExAllocatePool2)(
        POOL_FLAGS Flags, 
        SIZE_T NumberOfBytes, 
        ULONG Tag
        );

typedef 
void (*pKeReleaseGuardedMutex)(
        PKGUARDED_MUTEX GuardedMutex
        );

typedef 
void (*pKeAcquireGuardedMutex)(
        PKGUARDED_MUTEX GuardedMutex
        );

typedef 
ULONG (*pDbgPrintEx)(
        ULONG ComponentId, 
        ULONG Level, 
        PCSTR Format, 
        ...
        );

typedef 
LONG (*pRtlCompareUnicodeString)(
        PCUNICODE_STRING String1,
        PCUNICODE_STRING String2,
        BOOLEAN          CaseInSensitive
        );

typedef 
PIO_STACK_LOCATION (*pIoGetCurrentIrpStackLocation)(
        PIRP Irp
        );

typedef 
void (*pRtlFreeUnicodeString)(
        PUNICODE_STRING UnicodeString
        );

// clang-format on

#define OB_DEREFERENCE_OBJECT_INDEX                0
#define PS_LOOKUP_THREAD_BY_THREAD_ID_INDEX        1
#define MM_IS_ADDRESS_VALID_INDEX                  2
#define PS_SET_CREATE_PROCESS_NOTIFY_ROUTINE_INDEX 3

#define PS_REMOVE_CREATE_THREAD_NOTIFY_ROUTINE_INDEX 4
#define PS_GET_CURRENT_THREAD_ID_INDEX               5
#define PS_GET_PROCESS_ID_INDEX                      6
#define PS_LOOKUP_PROCESS_BY_PROCESS_ID_INDEX        7

#define EX_ENUM_HANDLE_TABLE_INDEX           8
#define OB_GET_OBJECT_TYPE_INDEX             9
#define EXF_UNBLOCK_PUSH_LOCK_INDEX          10
#define PS_GET_PROCESS_IMAGE_FILE_NAME_INDEX 11

#define STRSTR_INDEX                        12
#define RTL_INIT_UNICODE_STRING_INDEX       13
#define RTL_QUERY_REGISTRY_VALUES_INDEX     14
#define MM_GET_SYSTEM_ROUTINE_ADDRESS_INDEX 15

#define RTL_UNICODE_STRING_TO_ANSI_STRING_INDEX 16
#define RTL_COPY_UNICODE_STRING_INDEX           17
#define RTL_FREE_ANSI_STRING_INDEX              18
#define KE_INITIALIZE_GUARDED_MUTEX_INDEX       19

#define IO_CREATE_DEVICE_INDEX        20
#define IO_CREATE_SYMBOLIC_LINK_INDEX 21
#define IO_DELETE_DEVICE_INDEX        22
#define IO_DELETE_SYMBOLIC_LINK_INDEX 23

#define OB_REGISTER_CALLBACKS_INDEX                24
#define OB_UNREGISTER_CALLBACKS_INDEX              25
#define PS_SET_CREATE_THREAD_NOTIFY_ROUTINE_INDEX  26
#define KE_REVERT_TO_USER_AFFINITY_THREAD_EX_INDEX 27

#define KE_SET_SYSTEM_AFFINITY_THREAD_EX_INDEX  28
#define STRNLEN_INDEX                           29
#define RTL_INIT_ANSI_STRING_INDEX              30
#define RTL_ANSI_STRING_TO_UNICODE_STRING_INDEX 31

#define IO_GET_CURRENT_PROCESS_INDEX       32
#define RTL_GET_VERSION_INDEX              33
#define RTL_COMPARE_MEMORY_INDEX           34
#define EX_GET_SYSTEM_FIRMWARE_TABLE_INDEX 35

#define IO_ALLOCATE_WORK_ITEM_INDEX 36
#define IO_FREE_WORK_ITEM_INDEX     37
#define IO_QUEUE_WORK_ITEM_INDEX    38
#define ZW_OPEN_FILE_INDEX          39

#define ZW_CLOSE_INDEX                 40
#define ZW_CREATE_SECTION_INDEX        41
#define ZW_MAP_VIEW_OF_SECTION_INDEX   42
#define ZW_UNMAP_VIEW_OF_SECTION_INDEX 43

#define MM_COPY_MEMORY_INDEX            44
#define ZW_DEVICE_IO_CONTROL_FILE_INDEX 45
#define KE_STACK_ATTACH_PROCESS_INDEX   46
#define KE_UNSTACK_DETACH_PROCESS_INDEX 47

#define KE_WAIT_FOR_SINGLE_OBJECT_INDEX     48
#define PS_CREATE_SYSTEM_THREAD_INDEX       49
#define IOF_COMPLETE_REQUEST_INDEX          50
#define OB_REFERENCE_OBJECT_BY_HANDLE_INDEX 51

#define KE_DELAY_EXECUTION_THREAD_INDEX       52
#define KE_REGISTER_NMI_CALLBACK_INDEX        53
#define KE_DEREGISTER_NMI_CALLBACK_INDEX      54
#define KE_QUERY_ACTIVE_PROCESSOR_COUNT_INDEX 55

#define EX_ACQUIRE_PUSH_LOCK_EXCLUSIVE_EX_INDEX 56
#define EX_RELEASE_PUSH_LOCK_EXCLUSIVE_EX_INDEX 57
#define PS_GET_THREAD_ID_INDEX                  58
#define RTL_CAPTURE_STACK_BACK_TRACE_INDEX      59

#define ZW_OPEN_DIRECTORY_OBJECT_INDEX     60
#define KE_INITIALIZE_AFFINITY_EX_INDEX    61
#define KE_ADD_PROCESSOR_AFFINITY_EX_INDEX 62
#define RTL_QUERY_MODULE_INFORMATION_INDEX 63

#define KE_INITIALIZE_APC_INDEX       64
#define KE_INSERT_QUEUE_APC_INDEX     65
#define KE_GENERIC_CALL_DPC_INDEX     66
#define KE_SIGNAL_CALL_DPC_DONE_INDEX 67

#define MM_GET_PHYSICAL_MEMORY_RANGES_EX2_INDEX 68
#define MM_GET_VIRTUAL_FOR_PHYSICAL_INDEX       69
#define OBF_REFERENCE_OBJECT_INDEX              70
#define EX_FREE_POOL_WITH_TAG_INDEX             71

#define EX_ALLOCATE_POOL2_INDEX        72
#define KE_RELEASE_GUARDED_MUTEX_INDEX 73
#define KE_ACQUIRE_GUARDED_MUTEX_INDEX 74
#define DBG_PRINT_EX_INDEX             75

#define RTL_COMPARE_UNICODE_STRING_INDEX     76
#define RTL_FREE_UNICODE_STRING_INDEX        77
#define PS_GET_PROCESS_IMAGE_FILE_NAME_INDEX 78

typedef struct _DRIVER_IMPORTS
{
        pObDereferenceObject             DrvImpObDereferenceObject;
        pPsLookupThreadByThreadId        DrvImpPsLookupThreadByThreadId;
        pMmIsAddressValid                DrvImpMmIsAddressValid;
        pPsSetCreateProcessNotifyRoutine DrvImpPsSetCreateProcessNotifyRoutine;

        pPsRemoveCreateThreadNotifyRoutine DrvImpPsRemoveCreateThreadNotifyRoutine;
        pPsGetCurrentThreadId              DrvImpPsGetCurrentThreadId;
        pPsGetProcessId                    DrvImpPsGetProcessId;
        pPsLookupProcessByProcessId        DrvImpPsLookupProcessByProcessId;

        pExEnumHandleTable         DrvImpExEnumHandleTable;
        pObGetObjectType           DrvImpObGetObjectType;
        pExfUnblockPushLock        DrvImpExfUnblockPushLock;
        pPsGetProcessImageFileName DrvImpPsGetProcessImage;

        pstrstr                    DrvImpstrstr;
        pRtlInitUnicodeString      DrvImpRtlInitUnicodeString;
        pRtlQueryRegistryValues    DrvImpRtlQueryRegistryValues;
        pMmGetSystemRoutineAddress DrvImpMmGetSystemRoutineAddress;

        pRtlUnicodeStringToAnsiString DrvImpRtlUnicodeStringToAnsiString;
        pRtlCopyUnicodeString         DrvImpRtlCopyUnicodeString;
        pRtlFreeAnsiString            DrvImpRtlFreeAnsiString;
        pKeInitializeGuardedMutex     DrvImpKeInitializeGuardedMutex;

        pIoCreateDevice       DrvImpIoCreateDevice;
        pIoCreateSymbolicLink DrvImpIoCreateSymbolicLink;
        pIoDeleteDevice       DrvImpIoDeleteDevice;
        pIoDeleteSymbolicLink DrvImpIoDeleteSymbolicLink;

        pObRegisterCallbacks            DrvImpObRegisterCallbacks;
        pObUnRegisterCallbacks          DrvImpObUnRegisterCallbacks;
        pPsSetCreateThreadNotifyRoutine DrvImpPsSetCreateThreadNotifyRoutine;
        pKeRevertToUserAffinityThreadEx DrvImpKeRevertToUserAffinityThreadEx;

        pKeSetSystemAffinityThreadEx  DrvImpKeSetSystemAffinityThreadEx;
        pstrnlen                      DrvImpstrnlen;
        pRtlInitAnsiString            DrvImpRtlInitAnsiString;
        pRtlAnsiStringToUnicodeString DrvImpRtlAnsiStringToUnicodeString;

        pIoGetCurrentProcess      DrvImpIoGetCurrentProcess;
        pRtlGetVersion            DrvImpRtlGetVersion;
        pRtlCompareMemory         DrvImpRtlCompareMemory;
        pExGetSystemFirmwareTable DrvImpExGetSystemFirmwareTable;

        pIoAllocateWorkItem DrvImpIoAllocateWorkItem;
        pIoFreeWorkItem     DrvImpIoFreeWorkItem;
        pIoQueueWorkItem    DrvImpIoQueueWorkItem;
        pZwOpenFile         DrvImpZwOpenFile;

        pZwClose              DrvImpZwClose;
        pZwCreateSection      DrvImpZwCreateSection;
        pZwMapViewOfSection   DrvImpZwMapViewOfSection;
        pZwUnmapViewOfSection DrvImpZwUnmapViewOfSection;

        pMmCopyMemory           DrvImpMmCopyMemory;
        pZwDeviceIoControlFile  DrvImpZwDeviceIoControlFile;
        pKeStackAttachProcess   DrvImpKeStackAttachProcess;
        pKeUnstackDetachProcess DrvImpKeUnstackDetachProcess;

        pKeWaitForSingleObject     DrvImpKeWaitForSingleObject;
        pPsCreateSystemThread      DrvImpPsCreateSystemThread;
        pIofCompleteRequest        DrvImpIofCompleteRequest;
        pObReferenceObjectByHandle DrvImpObReferenceObjectByHandle;

        pKeDelayExecutionThread      DrvImpKeDelayExecutionThread;
        pKeRegisterNmiCallback       DrvImpKeRegisterNmiCallback;
        pKeDeregisterNmiCallback     DrvImpKeDeregisterNmiCallback;
        pKeQueryActiveProcessorCount DrvImpKeQueryActiveProcessorCount;

        pExAcquirePushLockExclusiveEx DrvImpExAcquirePushLockExclusiveEx;
        pExReleasePushLockExclusiveEx DrvImpExReleasePushLockExclusiveEx;
        pPsGetThreadId                DrvImpPsGetThreadId;
        pRtlCaptureStackBackTrace     DrvImpRtlCaptureStackBackTrace;

        pZwOpenDirectoryObject     DrvImpZwOpenDirectoryObject;
        pKeInitializeAffinityEx    DrvImpKeInitializeAffinityEx;
        pKeAddProcessorAffinityEx  DrvImpKeAddProcessorAffinityEx;
        pRtlQueryModuleInformation DrvImpRtlQueryModuleInformation;

        pKeInitializeApc     DrvImpKeInitializeApc;
        pKeInsertQueueApc    DrvImpKeInsertQueueApc;
        pKeGenericCallDpc    DrvImpKeGenericCallDpc;
        pKeSignalCallDpcDone DrvImpKeSignalCallDpcDone;

        pMmGetPhysicalMemoryRangesEx2 DrvImpMmGetPhysicalMemoryRangesEx2;
        pMmGetVirtualForPhysical      DrvImpMmGetVirtualForPhysical;
        pObfReferenceObject           DrvImpObfReferenceObject;
        pExFreePoolWithTag            DrvImpExFreePoolWithTag;

        pExAllocatePool2       DrvImpExAllocatePool2;
        pKeReleaseGuardedMutex DrvImpKeReleaseGuardedMutex;
        pKeAcquireGuardedMutex DrvImpKeAcquireGuardedMutex;
        pDbgPrintEx            DrvImpDbgPrintEx;

        pRtlCompareUnicodeString   DrvImpRtlCompareUnicodeString;
        pRtlFreeUnicodeString      DrvImpRtlFreeUnicodeString;
        pPsGetProcessImageFileName DrvImpPsGetProcessImageFileName;
        UINT64                     dummy;

} DRIVER_IMPORTS, *PDRIVER_IMPORTS;

#define IMPORTS_LENGTH sizeof(DRIVER_IMPORTS) / sizeof(UINT64)

VOID
ImpObDereferenceObject(_In_ PVOID Object);

NTSTATUS
ImpPsLookupThreadByThreadId(HANDLE ThreadId, PETHREAD* Thread);

BOOLEAN
ImpMmIsAddressValid(_In_ PVOID VirtualAddress);

NTSTATUS
ImpPsSetCreateProcessNotifyRoutine(PCREATE_PROCESS_NOTIFY_ROUTINE NotifyRoutine, BOOLEAN Remove);

NTSTATUS
ImpPsRemoveCreateThreadNotifyRoutine(PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine);

HANDLE
ImpPsGetCurrentThreadId();

HANDLE
ImpPsGetProcessId(PEPROCESS Process);

NTSTATUS
ImpPsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS* Process);

PVOID
ImpExEnumHandleTable(_In_ PHANDLE_TABLE HandleTable,
                     _In_ PVOID         Callback,
                     _In_opt_ PVOID     Context,
                     _Out_opt_ PHANDLE  Handle);

POBJECT_TYPE
ImpObGetObjectType(_In_ PVOID Object);

VOID
ImpExfUnblockPushLock(_In_ PEX_PUSH_LOCK PushLock, _In_ PVOID WaitBlock);

LPCSTR
ImpPsGetProcessImageFileName(PEPROCESS Process);

INT
ImpStrStr(_In_ CHAR* haystack, _In_ CHAR* needle);

void
ImpRtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);

NTSTATUS
ImpRtlQueryRegistryValues(ULONG                     RelativeTo,
                          PCWSTR                    Path,
                          PRTL_QUERY_REGISTRY_TABLE QueryTable,
                          void*                     Context,
                          void*                     Environment);

void*
ImpMmGetSystemRoutineAddress(PUNICODE_STRING SystemRoutineName);

NTSTATUS
ImpRtlUnicodeStringToAnsiString(PANSI_STRING     DestinationString,
                                PCUNICODE_STRING SourceString,
                                BOOLEAN          AllocateDestinationString);

void
ImpRtlCopyUnicodeString(PUNICODE_STRING DestinationString, PCUNICODE_STRING SourceString);

void
ImpRtlFreeAnsiString(PANSI_STRING AnsiString);

void
ImpKeInitializeGuardedMutex(PKGUARDED_MUTEX GuardedMutex);

NTSTATUS
ImpIoCreateDevice(PDRIVER_OBJECT  DriverObject,
                  ULONG           DeviceExtensionSize,
                  PUNICODE_STRING DeviceName,
                  DEVICE_TYPE     DeviceType,
                  ULONG           DeviceCharacteristics,
                  BOOLEAN         Exclusive,
                  PDEVICE_OBJECT* DeviceObject);

NTSTATUS
ImpIoCreateSymbolicLink(PUNICODE_STRING SymbolicLinkName, PUNICODE_STRING DeviceName);

void
ImpIoDeleteDevice(PDEVICE_OBJECT DeviceObject);

void
ImpIoDeleteSymbolicLink(PUNICODE_STRING SymbolicLinkName);

NTSTATUS
ImpObRegisterCallbacks(_In_ POB_CALLBACK_REGISTRATION CallbackRegistration,
                       _Out_ PVOID*                   RegistrationHandle);

VOID
ImpObUnRegisterCallbacks(_In_ PVOID RegistrationHandle);

NTSTATUS
ImpPsSetCreateThreadNotifyRoutine(PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine);

void
ImpKeRevertToUserAffinityThreadEx(KAFFINITY Affinity);

KAFFINITY
ImpKeSetSystemAffinityThreadEx(KAFFINITY Affinity);

SIZE_T
ImpStrnlen(_In_ CHAR* str, _In_ SIZE_T maxCount);

void
ImpRtlInitAnsiString(PANSI_STRING DestinationString, PCSZ SourceString);

NTSTATUS
ImpRtlAnsiStringToUnicodeString(PUNICODE_STRING DestinationString,
                                PCANSI_STRING   SourceString,
                                BOOLEAN         AllocateDestinationString);

PEPROCESS
ImpIoGetCurrentProcess(void);

NTSTATUS
ImpRtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);

SIZE_T
ImpRtlCompareMemory(_In_ PVOID Source1, _In_ PVOID Source2, _In_ SIZE_T Length);

NTSTATUS
ImpExGetSystemFirmwareTable(_In_ ULONG   FirmwareTableProviderSignature,
                            _In_ ULONG   FirmwareTableID,
                            _In_ PVOID   pFirmwareTableBuffer,
                            _In_ ULONG   BufferLength,
                            _Out_ PULONG ReturnLength);

PIO_WORKITEM
ImpIoAllocateWorkItem(PDEVICE_OBJECT DeviceObject);

void
ImpIoFreeWorkItem(PIO_WORKITEM WorkItem);

VOID
ImpIoQueueWorkItem(_In_ PIO_WORKITEM         IoWorkItem,
                   _In_ PIO_WORKITEM_ROUTINE WorkerRoutine,
                   _In_ WORK_QUEUE_TYPE      QueueType,
                   _In_opt_ PVOID            Context);

NTSTATUS
ImpZwOpenFile(PHANDLE            FileHandle,
              ACCESS_MASK        DesiredAccess,
              POBJECT_ATTRIBUTES ObjectAttributes,
              PIO_STATUS_BLOCK   IoStatusBlock,
              ULONG              ShareAccess,
              ULONG              OpenOptions);

NTSTATUS
ImpZwClose(HANDLE Handle);

NTSTATUS
ImpZwCreateSection(PHANDLE            SectionHandle,
                   ACCESS_MASK        DesiredAccess,
                   POBJECT_ATTRIBUTES ObjectAttributes,
                   PLARGE_INTEGER     MaximumSize,
                   ULONG              SectionPageProtection,
                   ULONG              AllocationAttributes,
                   HANDLE             FileHandle);

NTSTATUS
ImpZwMapViewOfSection(_In_ HANDLE                SectionHandle,
                      _In_ HANDLE                ProcessHandle,
                      _Inout_ PVOID*             BaseAddress,
                      _In_ ULONG_PTR             ZeroBits,
                      _In_ SIZE_T                CommitSize,
                      _Inout_opt_ PLARGE_INTEGER SectionOffset,
                      _Inout_ PSIZE_T            ViewSize,
                      _In_ SECTION_INHERIT       InheritDisposition,
                      _In_ ULONG                 AllocationType,
                      _In_ ULONG                 Win32Protect);

NTSTATUS
ImpZwUnmapViewOfSection(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress);

NTSTATUS
ImpMmCopyMemory(PVOID           TargetAddress,
                MM_COPY_ADDRESS SourceAddress,
                SIZE_T          NumberOfBytes,
                ULONG           Flags,
                PSIZE_T         NumberOfBytesTransferred);

NTSTATUS
ImpZwDeviceIoControlFile(_In_ HANDLE              FileHandle,
                         _In_opt_ HANDLE          Event,
                         _In_opt_ PIO_APC_ROUTINE ApcRoutine,
                         _In_opt_ PVOID           ApcContext,
                         _Out_ PIO_STATUS_BLOCK   IoStatusBlock,
                         _In_ ULONG               IoControlCode,
                         _In_opt_ PVOID           InputBuffer,
                         _In_ ULONG               InputBufferLength,
                         _Out_opt_ PVOID          OutputBuffer,
                         _In_ ULONG               OutputBufferLength);

void
ImpKeStackAttachProcess(PRKPROCESS Process, PKAPC_STATE ApcState);

void
ImpKeUnstackDetachProcess(PKAPC_STATE ApcState);

NTSTATUS
ImpKeWaitForSingleObject(_In_ PVOID           Object,
                         _In_ KWAIT_REASON    WaitReason,
                         _In_ KPROCESSOR_MODE WaitMode,
                         _In_ BOOLEAN         Alertable,
                         _In_ PLARGE_INTEGER  Timeout);

NTSTATUS
ImpPsCreateSystemThread(_Out_ PHANDLE               ThreadHandle,
                        _In_ ULONG                  DesiredAccess,
                        _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
                        _In_opt_ HANDLE             ProcessHandle,
                        _Out_opt_ PCLIENT_ID        ClientId,
                        _In_ PKSTART_ROUTINE        StartRoutine,
                        _In_opt_ PVOID              StartContext);

void
ImpIofCompleteRequest(PIRP Irp, CCHAR PriorityBoost);

NTSTATUS
ImpObReferenceObjectByHandle(_In_ HANDLE                          Handle,
                             _In_ ACCESS_MASK                     DesiredAccess,
                             _In_opt_ POBJECT_TYPE                ObjectType,
                             _In_ KPROCESSOR_MODE                 AccessMode,
                             _Out_ PVOID*                         Object,
                             _Out_opt_ POBJECT_HANDLE_INFORMATION HandleInformation);

NTSTATUS
ImpKeDelayExecutionThread(KPROCESSOR_MODE WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Interval);

PVOID
ImpKeRegisterNmiCallback(_In_ PVOID CallbackRoutine, _In_opt_ PVOID Context);

NTSTATUS
ImpKeDeregisterNmiCallback(_In_ PVOID Handle);

ULONG
ImpKeQueryActiveProcessorCount(PKAFFINITY ActiveProcessors);

void
ImpExAcquirePushLockExclusiveEx(PEX_PUSH_LOCK PushLock, ULONG Flags);

void
ImpExReleasePushLockExclusiveEx(PEX_PUSH_LOCK PushLock, ULONG Flags);

HANDLE
ImpPsGetThreadId(PETHREAD Thread);

USHORT
ImpRtlCaptureStackBackTrace(_In_ ULONG       FramesToSkip,
                            _In_ ULONG       FramesToCapture,
                            _Out_ PVOID*     BackTrace,
                            _Out_opt_ PULONG BackTraceHash);

NTSTATUS
ImpZwOpenDirectoryObject(PHANDLE            DirectoryHandle,
                         ACCESS_MASK        DesiredAccess,
                         POBJECT_ATTRIBUTES ObjectAttributes);

void
ImpKeInitializeAffinityEx(PKAFFINITY_EX AffinityMask);

VOID
ImpKeAddProcessorAffinityEx(_In_ PKAFFINITY_EX affinity, _In_ INT num);

NTSTATUS
ImpRtlQueryModuleInformation(_Inout_ ULONG* InformationLength,
                             _In_ ULONG     SizePerModule,
                             _In_ PVOID     InformationBuffer);

VOID
ImpKeInitializeApc(_In_ PKAPC             Apc,
                   _In_ PKTHREAD          Thread,
                   _In_ KAPC_ENVIRONMENT  Environment,
                   _In_ PKKERNEL_ROUTINE  KernelRoutine,
                   _In_ PKRUNDOWN_ROUTINE RundownRoutine,
                   _In_ PKNORMAL_ROUTINE  NormalRoutine,
                   _In_ KPROCESSOR_MODE   ApcMode,
                   _In_ PVOID             NormalContext);

BOOLEAN
ImpKeInsertQueueApc(_In_ PKAPC     Apc,
                    _In_ PVOID     SystemArgument1,
                    _In_ PVOID     SystemArgument2,
                    _In_ KPRIORITY Increment);

VOID
ImpKeGenericCallDpc(_In_ PKDEFERRED_ROUTINE DpcRoutine, _In_ PVOID Context);

VOID
ImpKeSignalCallDpcDone(_In_ PVOID SystemArgument1);

PPHYSICAL_MEMORY_RANGE
ImpMmGetPhysicalMemoryRangesEx2(_In_ PVOID PartitionObject, _In_ ULONG Flags);

void*
ImpMmGetVirtualForPhysical(_In_ PHYSICAL_ADDRESS PhysicalAddress);

LONG_PTR
ImpObfReferenceObject(_In_ PVOID Object);

VOID
ImpExFreePoolWithTag(_In_ PVOID P, _In_ ULONG Tag);

void*
ImpExAllocatePool2(_In_ POOL_FLAGS Flags, _In_ SIZE_T NumberOfBytes, _In_ ULONG Tag);

VOID
ImpKeReleaseGuardedMutex(_In_ PKGUARDED_MUTEX GuardedMutex);

VOID
ImpKeAcquireGuardedMutex(_In_ PKGUARDED_MUTEX GuardedMutex);

ULONG
ImpDbgPrintEx(_In_ ULONG ComponentId, _In_ ULONG Level, _In_ PCSTR Format, ...);

LONG
ImpRtlCompareUnicodeString(_In_ PCUNICODE_STRING String1,
                           _In_ PCUNICODE_STRING String2,
                           _In_ BOOLEAN          CaseInSensitive);

VOID
ImpRtlFreeUnicodeString(_In_ PUNICODE_STRING UnicodeString);

#endif