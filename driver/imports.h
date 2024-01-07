#ifndef IMPORTS_H
#define IMPORTS_H

#include "common.h"

void*
FindNtExport(const char* ExportName);

VOID
FreeDriverImportsStructure();

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
        PKAFFINITY_EX affinity, 
        INT num
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

typedef struct _DRIVER_IMPORTS
{
        pObDereferenceObject               DrvImpObDereferenceObject;
        pIoGetCurrentIrpStackLocation      DrvImpIoGetCurrentIrpStackLocation;
        pPsLookupThreadByThreadId          DrvImpPsLookupThreadByThreadId;
        pMmIsAddressValid                  DrvImpMmIsAddressValid;
        pPsSetCreateProcessNotifyRoutine   DrvImpPsSetCreateProcessNotifyRoutine;
        pPsRemoveCreateThreadNotifyRoutine DrvImpPsRemoveCreateThreadNotifyRoutine;
        pPsGetCurrentThreadId              DrvImpPsGetCurrentThreadId;
        pPsGetProcessId                    DrvImpPsGetProcessId;
        pPsLookupProcessByProcessId        DrvImpPsLookupProcessByProcessId;
        pExEnumHandleTable                 DrvImpExEnumHandleTable;
        pObGetObjectType                   DrvImpObGetObjectType;
        pExfUnblockPushLock                DrvImpExfUnblockPushLock;
        pPsGetProcessImageFileName         DrvImpPsGetProcessImage;
        pstrstr                            DrvImpstrstr;
        pRtlInitUnicodeString              DrvImpRtlInitUnicodeString;
        pRtlQueryRegistryValues            DrvImpRtlQueryRegistryValues;
        pMmGetSystemRoutineAddress         DrvImpMmGetSystemRoutineAddress;
        pRtlUnicodeStringToAnsiString      DrvImpRtlUnicodeStringToAnsiString;
        pRtlCopyUnicodeString              DrvImpRtlCopyUnicodeString;
        pRtlFreeAnsiString                 DrvImpRtlFreeAnsiString;
        pKeInitializeGuardedMutex          DrvImpKeInitializeGuardedMutex;
        pIoCreateDevice                    DrvImpIoCreateDevice;
        pIoCreateSymbolicLink              DrvImpIoCreateSymbolicLink;
        pIoDeleteDevice                    DrvImpIoDeleteDevice;
        pIoDeleteSymbolicLink              DrvImpIoDeleteSymbolicLink;
        pObRegisterCallbacks               DrvImpObRegisterCallbacks;
        pObUnRegisterCallbacks             DrvImpObUnRegisterCallbacks;
        pPsSetCreateThreadNotifyRoutine    DrvImpPsSetCreateThreadNotifyRoutine;
        pKeRevertToUserAffinityThreadEx    DrvImpKeRevertToUserAffinityThreadEx;
        pKeSetSystemAffinityThreadEx       DrvImpKeSetSystemAffinityThreadEx;
        pstrnlen                           DrvImpstrnlen;
        pRtlInitAnsiString                 DrvImpRtlInitAnsiString;
        pRtlAnsiStringToUnicodeString      DrvImpRtlAnsiStringToUnicodeString;
        pIoGetCurrentProcess               DrvImpIoGetCurrentProcess;
        pRtlGetVersion                     DrvImpRtlGetVersion;
        pRtlCompareMemory                  DrvImpRtlCompareMemory;
        pExGetSystemFirmwareTable          DrvImpExGetSystemFirmwareTable;
        pIoAllocateWorkItem                DrvImpIoAllocateWorkItem;
        pIoFreeWorkItem                    DrvImpIoFreeWorkItem;
        pIoQueueWorkItem                   DrvImpIoQueueWorkItem;
        pZwOpenFile                        DrvImpZwOpenFile;
        pZwClose                           DrvImpZwClose;
        pZwCreateSection                   DrvImpZwCreateSection;
        pZwMapViewOfSection                DrvImpZwMapViewOfSection;
        pZwUnmapViewOfSection              DrvImpZwUnmapViewOfSection;
        pMmCopyMemory                      DrvImpMmCopyMemory;
        pZwDeviceIoControlFile             DrvImpZwDeviceIoControlFile;
        pKeStackAttachProcess              DrvImpKeStackAttachProcess;
        pKeUnstackDetachProcess            DrvImpKeUnstackDetachProcess;
        pKeWaitForSingleObject             DrvImpKeWaitForSingleObject;
        pPsCreateSystemThread              DrvImpPsCreateSystemThread;
        pIofCompleteRequest                DrvImpIofCompleteRequest;
        pObReferenceObjectByHandle         DrvImpObReferenceObjectByHandle;
        pKeDelayExecutionThread            DrvImpKeDelayExecutionThread;
        pKeRegisterNmiCallback             DrvImpKeRegisterNmiCallback;
        pKeDeregisterNmiCallback           DrvImpKeDeregisterNmiCallback;
        pKeQueryActiveProcessorCount       DrvImpKeQueryActiveProcessorCount;
        pExAcquirePushLockExclusiveEx      DrvImpExAcquirePushLockExclusiveEx;
        pExReleasePushLockExclusiveEx      DrvImpExReleasePushLockExclusiveEx;
        pPsGetThreadId                     DrvImpPsGetThreadId;
        pRtlCaptureStackBackTrace          DrvImpRtlCaptureStackBackTrace;
        pZwOpenDirectoryObject             DrvImpZwOpenDirectoryObject;
        pKeInitializeAffinityEx            DrvImpKeInitializeAffinityEx;
        pKeAddProcessorAffinityEx          DrvImpKeAddProcessorAffinityEx;
        pRtlQueryModuleInformation         DrvImpRtlQueryModuleInformation;
        pKeInitializeApc                   DrvImpKeInitializeApc;
        pKeInsertQueueApc                  DrvImpKeInsertQueueApc;
        pKeGenericCallDpc                  DrvImpKeGenericCallDpc;
        pKeSignalCallDpcDone               DrvImpKeSignalCallDpcDone;
        pMmGetPhysicalMemoryRangesEx2      DrvImpMmGetPhysicalMemoryRangesEx2;
        pMmGetVirtualForPhysical           DrvImpMmGetVirtualForPhysical;
        pObfReferenceObject                DrvImpObfReferenceObject;
        pExFreePoolWithTag                 DrvImpExFreePoolWithTag;
        pExAllocatePool2                   DrvImpExAllocatePool2;
        pKeReleaseGuardedMutex             DrvImpKeReleaseGuardedMutex;
        pKeAcquireGuardedMutex             DrvImpKeAcquireGuardedMutex;
        pDbgPrintEx                        DrvImpDbgPrintEx;
        pRtlCompareUnicodeString           DrvImpRtlCompareUnicodeString;
        pRtlFreeUnicodeString              DrvImpRtlFreeUnicodeString;
        pPsGetProcessImageFileName         DrvImpPsGetProcessImageFileName;
} DRIVER_IMPORTS, *PDRIVER_IMPORTS;

extern PDRIVER_IMPORTS driver_imports;

#define DRVIMPORTS driver_imports

#define ImpIoGetCurrentIrpStackLocation      DRVIMPORTS->DrvImpIoGetCurrentIrpStackLocation
#define ImpObDereferenceObject               DRVIMPORTS->DrvImpObDereferenceObject
#define ImpPsLookupThreadByThreadId          DRVIMPORTS->DrvImpPsLookupThreadByThreadId
#define ImpMmIsAddressValid                  DRVIMPORTS->DrvImpMmIsAddressValid
#define ImpPsSetCreateProcessNotifyRoutine   DRVIMPORTS->DrvImpPsSetCreateProcessNotifyRoutine
#define ImpPsRemoveCreateThreadNotifyRoutine DRVIMPORTS->DrvImpPsRemoveCreateThreadNotifyRoutine
#define ImpPsGetCurrentThreadId              DRVIMPORTS->DrvImpPsGetCurrentThreadId
#define ImpPsGetProcessId                    DRVIMPORTS->DrvImpPsGetProcessId
#define ImpPsLookupProcessByProcessId        DRVIMPORTS->DrvImpPsLookupProcessByProcessId
#define ImpExEnumHandleTable                 DRVIMPORTS->DrvImpExEnumHandleTable
#define ImpObGetObjectType                   DRVIMPORTS->DrvImpObGetObjectType
#define ImpExfUnblockPushLock                DRVIMPORTS->DrvImpExfUnblockPushLock
#define ImpPsGetProcessImageFileName         DRVIMPORTS->DrvImpPsGetProcessImageFileName
#define Impstrstr                            DRVIMPORTS->DrvImpstrstr
#define ImpRtlInitUnicodeString              DRVIMPORTS->DrvImpRtlInitUnicodeString
#define ImpRtlQueryRegistryValues            DRVIMPORTS->DrvImpRtlQueryRegistryValues
#define ImpMmGetSystemRoutineAddress         DRVIMPORTS->DrvImpMmGetSystemRoutineAddress
#define ImpRtlUnicodeStringToAnsiString      DRVIMPORTS->DrvImpRtlUnicodeStringToAnsiString
#define ImpRtlCopyUnicodeString              DRVIMPORTS->DrvImpRtlCopyUnicodeString
#define ImpRtlFreeAnsiString                 DRVIMPORTS->DrvImpRtlFreeAnsiString
#define ImpKeInitializeGuardedMutex          DRVIMPORTS->DrvImpKeInitializeGuardedMutex
#define ImpIoCreateDevice                    DRVIMPORTS->DrvImpIoCreateDevice
#define ImpIoCreateSymbolicLink              DRVIMPORTS->DrvImpIoCreateSymbolicLink
#define ImpIoDeleteDevice                    DRVIMPORTS->DrvImpIoDeleteDevice
#define ImpIoDeleteSymbolicLink              DRVIMPORTS->DrvImpIoDeleteSymbolicLink
#define ImpObRegisterCallbacks               DRVIMPORTS->DrvImpObRegisterCallbacks
#define ImpObUnRegisterCallbacks             DRVIMPORTS->DrvImpObUnRegisterCallbacks
#define ImpPsSetCreateThreadNotifyRoutine    DRVIMPORTS->DrvImpPsSetCreateThreadNotifyRoutine
#define ImpPsProcessType                     DRVIMPORTS->DrvImpPsProcessType
#define ImpKeRevertToUserAffinityThreadEx    DRVIMPORTS->DrvImpKeRevertToUserAffinityThreadEx
#define ImpKeSetSystemAffinityThreadEx       DRVIMPORTS->DrvImpKeSetSystemAffinityThreadEx
#define Impstrnlen                           DRVIMPORTS->DrvImpstrnlen
#define ImpRtlInitAnsiString                 DRVIMPORTS->DrvImpRtlInitAnsiString
#define ImpRtlAnsiStringToUnicodeString      DRVIMPORTS->DrvImpRtlAnsiStringToUnicodeString
#define ImpIoGetCurrentProcess               DRVIMPORTS->DrvImpIoGetCurrentProcess
#define ImpRtlGetVersion                     DRVIMPORTS->DrvImpRtlGetVersion
#define ImpRtlCompareMemory                  DRVIMPORTS->DrvImpRtlCompareMemory
#define ImpExGetSystemFirmwareTable          DRVIMPORTS->DrvImpExGetSystemFirmwareTable
#define ImpIoAllocateWorkItem                DRVIMPORTS->DrvImpIoAllocateWorkItem
#define ImpIoFreeWorkItem                    DRVIMPORTS->DrvImpIoFreeWorkItem
#define ImpIoQueueWorkItem                   DRVIMPORTS->DrvImpIoQueueWorkItem
#define ImpZwOpenFile                        DRVIMPORTS->DrvImpZwOpenFile
#define ImpZwClose                           DRVIMPORTS->DrvImpZwClose
#define ImpZwCreateSection                   DRVIMPORTS->DrvImpZwCreateSection
#define ImpZwMapViewOfSection                DRVIMPORTS->DrvImpZwMapViewOfSection
#define ImpZwUnmapViewOfSection              DRVIMPORTS->DrvImpZwUnmapViewOfSection
#define ImpMmCopyMemory                      DRVIMPORTS->DrvImpMmCopyMemory
#define ImpZwDeviceIoControlFile             DRVIMPORTS->DrvImpZwDeviceIoControlFile
#define ImpKeStackAttachProcess              DRVIMPORTS->DrvImpKeStackAttachProcess
#define ImpKeUnstackDetachProcess            DRVIMPORTS->DrvImpKeUnstackDetachProcess
#define ImpKeWaitForSingleObject             DRVIMPORTS->DrvImpKeWaitForSingleObject
#define ImpPsCreateSystemThread              DRVIMPORTS->DrvImpPsCreateSystemThread
#define ImpIofCompleteRequest                DRVIMPORTS->DrvImpIofCompleteRequest
#define ImpObReferenceObjectByHandle         DRVIMPORTS->DrvImpObReferenceObjectByHandle
#define ImpPsThreadType                      DRVIMPORTS->DrvImpPsThreadType
#define ImpKeDelayExecutionThread            DRVIMPORTS->DrvImpKeDelayExecutionThread
#define ImpKeRegisterNmiCallback             DRVIMPORTS->DrvImpKeRegisterNmiCallback
#define ImpKeDeregisterNmiCallback           DRVIMPORTS->DrvImpKeDeregisterNmiCallback
#define ImpKeQueryActiveProcessorCount       DRVIMPORTS->DrvImpKeQueryActiveProcessorCount
#define ImpExAcquirePushLockExclusiveEx      DRVIMPORTS->DrvImpExAcquirePushLockExclusiveEx
#define ImpExReleasePushLockExclusiveEx      DRVIMPORTS->DrvImpExReleasePushLockExclusiveEx
#define ImpPsGetThreadId                     DRVIMPORTS->DrvImpPsGetThreadId
#define ImpRtlCaptureStackBackTrace          DRVIMPORTS->DrvImpRtlCaptureStackBackTrace
#define ImpZwOpenDirectoryObject             DRVIMPORTS->DrvImpZwOpenDirectoryObject
#define ImpKeInitializeAffinityEx            DRVIMPORTS->DrvImpKeInitializeAffinityEx
#define ImpKeAddProcessorAffinityEx          DRVIMPORTS->DrvImpKeAddProcessorAffinityEx
#define ImpRtlQueryModuleInformation         DRVIMPORTS->DrvImpRtlQueryModuleInformation
#define ImpKeInitializeApc                   DRVIMPORTS->DrvImpKeInitializeApc
#define ImpKeInsertQueueApc                  DRVIMPORTS->DrvImpKeInsertQueueApc
#define ImpKeGenericCallDpc                  DRVIMPORTS->DrvImpKeGenericCallDpc
#define ImpKeSignalCallDpcDone               DRVIMPORTS->DrvImpKeSignalCallDpcDone
#define ImpMmGetPhysicalMemoryRangesEx2      DRVIMPORTS->DrvImpMmGetPhysicalMemoryRangesEx2
#define ImpMmGetVirtualForPhysical           DRVIMPORTS->DrvImpMmGetVirtualForPhysical
#define ImpObfReferenceObject                DRVIMPORTS->DrvImpObfReferenceObject
#define ImpExFreePoolWithTag                 DRVIMPORTS->DrvImpExFreePoolWithTag
#define ImpExAllocatePool2                   DRVIMPORTS->DrvImpExAllocatePool2
#define ImpKeReleaseGuardedMutex             DRVIMPORTS->DrvImpKeReleaseGuardedMutex
#define ImpKeAcquireGuardedMutex             DRVIMPORTS->DrvImpKeAcquireGuardedMutex
#define ImpDbgPrintEx                        DRVIMPORTS->DrvImpDbgPrintEx
#define ImpRtlCompareUnicodeString           DRVIMPORTS->DrvImpRtlCompareUnicodeString
#define ImpRtlFreeUnicodeString              DRVIMPORTS->DrvImpRtlFreeUnicodeString
#define ImpPsGetProcessImageFileName         DRVIMPORTS->DrvImpPsGetProcessImageFileName

NTSTATUS
ResolveNtImports();

#endif