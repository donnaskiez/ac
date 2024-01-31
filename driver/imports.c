#include "imports.h"

#include "common.h"
#include "driver.h"
#include "crypt.h"
#include <stdarg.h>

PVOID
FindDriverBaseNoApi(_In_ PDRIVER_OBJECT DriverObject, _In_ PWCH Name)
{
        PKLDR_DATA_TABLE_ENTRY first = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;

        /* first entry contains invalid data, 2nd entry is the kernel */
        PKLDR_DATA_TABLE_ENTRY entry =
            ((PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection)->InLoadOrderLinks.Flink->Flink;

        while (entry->InLoadOrderLinks.Flink != first)
        {
                /* todo: write our own unicode string comparison function, since the entire point of
                 * this is to find exports with no exports. */
                if (!wcscmp(entry->BaseDllName.Buffer, Name))
                {
                        return entry->DllBase;
                }

                entry = entry->InLoadOrderLinks.Flink;
        }

        return NULL;
}

PVOID
ImpResolveNtImport(PDRIVER_OBJECT DriverObject, PCZPSTR ExportName)
{
        PVOID                    image_base           = NULL;
        PIMAGE_DOS_HEADER        dos_header           = NULL;
        PLOCAL_NT_HEADER         nt_header            = NULL;
        PIMAGE_OPTIONAL_HEADER64 optional_header      = NULL;
        PIMAGE_DATA_DIRECTORY    data_dir             = NULL;
        PIMAGE_EXPORT_DIRECTORY  export_dir           = NULL;
        PUINT32                  export_name_table    = NULL;
        PCHAR                    name                 = NULL;
        PUINT16                  ordinals_table       = NULL;
        PUINT32                  export_addr_table    = NULL;
        UINT32                   ordinal              = 0;
        PVOID                    target_function_addr = 0;
        UINT32                   export_offset        = 0;

        image_base = FindDriverBaseNoApi(DriverObject, L"ntoskrnl.exe");

        if (!image_base)
        {
                DEBUG_ERROR("FindDriverBaseNoApi failed with no status");
                return NULL;
        }

        /*
         * todo: add comment explaining this shit also this ugly af
         */
        dos_header      = (PIMAGE_DOS_HEADER)image_base;
        nt_header       = (struct _IMAGE_NT_HEADERS64*)((UINT64)image_base + dos_header->e_lfanew);
        optional_header = (PIMAGE_OPTIONAL_HEADER64)&nt_header->OptionalHeader;

        data_dir = (PIMAGE_DATA_DIRECTORY) &
                   (optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
        export_dir = (PIMAGE_EXPORT_DIRECTORY)((UINT64)image_base + data_dir->VirtualAddress);

        export_name_table = (PUINT32)((UINT64)image_base + export_dir->AddressOfNames);
        ordinals_table    = (PUINT16)((UINT64)image_base + export_dir->AddressOfNameOrdinals);
        export_addr_table = (PUINT32)((UINT64)image_base + export_dir->AddressOfFunctions);

        for (INT index = 0; index < export_dir->NumberOfNames; index++)
        {
                name = (PCHAR)((UINT64)image_base + export_name_table[index]);

                if (strcmp(name, ExportName))
                        continue;

                ordinal              = ordinals_table[index];
                export_offset        = export_addr_table[ordinal];
                target_function_addr = (PVOID)((UINT64)image_base + export_offset);
                return target_function_addr;
        }

        return NULL;
}

/*
 * The strings in this array need to be hashed at compile time, then we can use the same hash
 * function to compare when we walk the export table.
 */
#define NT_IMPORT_MAX_LENGTH 128
#define NT_IMPORT_COUNT      79

CHAR NT_IMPORTS[NT_IMPORT_COUNT][NT_IMPORT_MAX_LENGTH] = {"ObDereferenceObject",
                                                          "PsLookupThreadByThreadId",
                                                          "MmIsAddressValid",
                                                          "PsSetCreateProcessNotifyRoutine",
                                                          "PsRemoveCreateThreadNotifyRoutine",
                                                          "PsGetCurrentThreadId",
                                                          "PsGetProcessId",
                                                          "PsLookupProcessByProcessId",
                                                          "ExEnumHandleTable",
                                                          "ObGetObjectType",
                                                          "ExfUnblockPushLock",
                                                          "PsGetProcessImageFileName",
                                                          "strstr",
                                                          "RtlInitUnicodeString",
                                                          "RtlQueryRegistryValues",
                                                          "MmGetSystemRoutineAddress",
                                                          "RtlUnicodeStringToAnsiString",
                                                          "RtlCopyUnicodeString",
                                                          "RtlFreeAnsiString",
                                                          "KeInitializeGuardedMutex",
                                                          "IoCreateDevice",
                                                          "IoCreateSymbolicLink",
                                                          "IoDeleteDevice",
                                                          "IoDeleteSymbolicLink",
                                                          "ObRegisterCallbacks",
                                                          "ObUnRegisterCallbacks",
                                                          "PsSetCreateThreadNotifyRoutine",
                                                          "KeRevertToUserAffinityThreadEx",
                                                          "KeSetSystemAffinityThreadEx",
                                                          "strnlen",
                                                          "RtlInitAnsiString",
                                                          "RtlAnsiStringToUnicodeString",
                                                          "IoGetCurrentProcess",
                                                          "RtlGetVersion",
                                                          "RtlCompareMemory",
                                                          "ExGetSystemFirmwareTable",
                                                          "IoAllocateWorkItem",
                                                          "IoFreeWorkItem",
                                                          "IoQueueWorkItem",
                                                          "ZwOpenFile",
                                                          "ZwClose",
                                                          "ZwCreateSection",
                                                          "ZwMapViewOfSection",
                                                          "ZwUnmapViewOfSection",
                                                          "MmCopyMemory",
                                                          "ZwDeviceIoControlFile",
                                                          "KeStackAttachProcess",
                                                          "KeUnstackDetachProcess",
                                                          "KeWaitForSingleObject",
                                                          "PsCreateSystemThread",
                                                          "IofCompleteRequest",
                                                          "ObReferenceObjectByHandle",
                                                          "KeDelayExecutionThread",
                                                          "KeRegisterNmiCallback",
                                                          "KeDeregisterNmiCallback",
                                                          "KeQueryActiveProcessorCount",
                                                          "ExAcquirePushLockExclusiveEx",
                                                          "ExReleasePushLockExclusiveEx",
                                                          "PsGetThreadId",
                                                          "RtlCaptureStackBackTrace",
                                                          "ZwOpenDirectoryObject",
                                                          "KeInitializeAffinityEx",
                                                          "KeAddProcessorAffinityEx",
                                                          "RtlQueryModuleInformation",
                                                          "KeInitializeApc",
                                                          "KeInsertQueueApc",
                                                          "KeGenericCallDpc",
                                                          "KeSignalCallDpcDone",
                                                          "MmGetPhysicalMemoryRangesEx2",
                                                          "MmGetVirtualForPhysical",
                                                          "ObfReferenceObject",
                                                          "ExFreePoolWithTag",
                                                          "ExAllocatePool2",
                                                          "KeReleaseGuardedMutex",
                                                          "KeAcquireGuardedMutex",
                                                          "DbgPrintEx",
                                                          "RtlCompareUnicodeString",
                                                          "RtlFreeUnicodeString",
                                                          "PsGetProcessImageFileName"};

DRIVER_IMPORTS driver_imports = {0};

NTSTATUS
ImpResolveDynamicImports(_In_ PDRIVER_OBJECT DriverObject)
{
        PUINT64 imports_array = (PUINT64)&driver_imports;

        for (UINT32 index = 0; index < NT_IMPORT_COUNT; index++)
        {
                imports_array[index] = ImpResolveNtImport(DriverObject, NT_IMPORTS[index]);

                if (!imports_array[index])
                        return STATUS_UNSUCCESSFUL;
        }

        CryptEncryptImportsArray(&driver_imports, IMPORTS_LENGTH);

        return STATUS_SUCCESS;
}

VOID
ImpObDereferenceObject(_In_ PVOID Object)
{
        pObDereferenceObject impObDereferenceObject =
            (pObDereferenceObject)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, OB_DEREFERENCE_OBJECT_INDEX);

        impObDereferenceObject(Object);
}

NTSTATUS
ImpPsLookupThreadByThreadId(_In_ HANDLE ThreadId, _Out_ PETHREAD* Thread)
{
        pPsLookupThreadByThreadId impPsLookupThreadByThreadId =
            (pPsLookupThreadByThreadId)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, PS_LOOKUP_THREAD_BY_THREAD_ID_INDEX);

        return impPsLookupThreadByThreadId(ThreadId, Thread);
}

BOOLEAN
ImpMmIsAddressValid(_In_ PVOID VirtualAddress)
{
        pMmIsAddressValid impMmIsAddressValid = (pMmIsAddressValid)CryptDecryptImportsArrayEntry(
            &driver_imports, IMPORTS_LENGTH, MM_IS_ADDRESS_VALID_INDEX);

        return impMmIsAddressValid(VirtualAddress);
}

NTSTATUS
ImpPsSetCreateProcessNotifyRoutine(_In_ PCREATE_PROCESS_NOTIFY_ROUTINE NotifyRoutine,
                                   _In_ BOOLEAN                        Remove)
{
        pPsSetCreateProcessNotifyRoutine impPsSetCreateProcessNotifyRoutine =
            (pPsSetCreateProcessNotifyRoutine)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, PS_SET_CREATE_PROCESS_NOTIFY_ROUTINE_INDEX);

        return impPsSetCreateProcessNotifyRoutine(NotifyRoutine, Remove);
}

NTSTATUS
ImpPsRemoveCreateThreadNotifyRoutine(_In_ PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine)
{
        pPsRemoveCreateThreadNotifyRoutine impPsRemoveCreateThreadNotifyRoutine =
            (pPsRemoveCreateThreadNotifyRoutine)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, PS_REMOVE_CREATE_THREAD_NOTIFY_ROUTINE_INDEX);

        return impPsRemoveCreateThreadNotifyRoutine(NotifyRoutine);
}

HANDLE
ImpPsGetCurrentThreadId()
{
        pPsGetCurrentThreadId impPsGetCurrentThreadId =
            (pPsGetCurrentThreadId)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, PS_GET_CURRENT_THREAD_ID_INDEX);

        return impPsGetCurrentThreadId();
}

HANDLE
ImpPsGetProcessId(_In_ PEPROCESS Process)
{
        pPsGetProcessId impPsGetProcessId = (pPsGetProcessId)CryptDecryptImportsArrayEntry(
            &driver_imports, IMPORTS_LENGTH, PS_GET_PROCESS_ID_INDEX);

        return impPsGetProcessId(Process);
}

NTSTATUS
ImpPsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Out_ PEPROCESS* Process)
{
        pPsLookupProcessByProcessId impPsLookupProcessByProcessId =
            (pPsLookupProcessByProcessId)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, PS_LOOKUP_PROCESS_BY_PROCESS_ID_INDEX);

        return impPsLookupProcessByProcessId(ProcessId, Process);
}

PVOID
ImpExEnumHandleTable(_In_ PHANDLE_TABLE HandleTable,
                     _In_ PVOID         Callback,
                     _In_opt_ PVOID     Context,
                     _Out_opt_ PHANDLE  Handle)
{
        pExEnumHandleTable impExEnumHandleTable = (pExEnumHandleTable)CryptDecryptImportsArrayEntry(
            &driver_imports, IMPORTS_LENGTH, EX_ENUM_HANDLE_TABLE_INDEX);

        return impExEnumHandleTable(HandleTable, Callback, Context, Handle);
}

POBJECT_TYPE
ImpObGetObjectType(_In_ PVOID Object)
{
        pObGetObjectType impObGetObjectType = (pObGetObjectType)CryptDecryptImportsArrayEntry(
            &driver_imports, IMPORTS_LENGTH, OB_GET_OBJECT_TYPE_INDEX);

        return impObGetObjectType(Object);
}

VOID
ImpExfUnblockPushLock(_In_ PEX_PUSH_LOCK PushLock, _In_ PVOID WaitBlock)
{
        pExfUnblockPushLock impExfUnblockPushLock =
            (pExfUnblockPushLock)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, EXF_UNBLOCK_PUSH_LOCK_INDEX);

        impExfUnblockPushLock(PushLock, WaitBlock);
}

LPCSTR
ImpPsGetProcessImageFileName(_In_ PEPROCESS Process)
{
        pPsGetProcessImageFileName impPsGetProcessImageFileName =
            (pPsGetProcessImageFileName)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, PS_GET_PROCESS_IMAGE_FILE_NAME_INDEX);

        return impPsGetProcessImageFileName(Process);
}

INT
ImpStrStr(_In_ CHAR* haystack, _In_ CHAR* needle)
{
        pstrstr impStrStr =
            (pstrstr)CryptDecryptImportsArrayEntry(&driver_imports, IMPORTS_LENGTH, STRSTR_INDEX);

        return impStrStr(haystack, needle);
}

VOID
ImpRtlInitUnicodeString(_In_ PUNICODE_STRING DestinationString, _In_ PCWSTR SourceString)
{
        pRtlInitUnicodeString impRtlInitUnicodeString =
            (pRtlInitUnicodeString)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, RTL_INIT_UNICODE_STRING_INDEX);

        impRtlInitUnicodeString(DestinationString, SourceString);
}

NTSTATUS
ImpRtlQueryRegistryValues(_In_ ULONG                     RelativeTo,
                          _In_ PCWSTR                    Path,
                          _In_ PRTL_QUERY_REGISTRY_TABLE QueryTable,
                          _In_opt_ void*                 Context,
                          _In_ void*                     Environment)
{
        pRtlQueryRegistryValues impRtlQueryRegistryValues =
            (pRtlQueryRegistryValues)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, RTL_QUERY_REGISTRY_VALUES_INDEX);

        return impRtlQueryRegistryValues(RelativeTo, Path, QueryTable, Context, Environment);
}

PVOID
ImpMmGetSystemRoutineAddress(_In_ PUNICODE_STRING SystemRoutineName)
{
        pMmGetSystemRoutineAddress impMmGetSystemRoutineAddress =
            (pMmGetSystemRoutineAddress)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, MM_GET_SYSTEM_ROUTINE_ADDRESS_INDEX);

        return impMmGetSystemRoutineAddress(SystemRoutineName);
}

NTSTATUS
ImpRtlUnicodeStringToAnsiString(_In_ PANSI_STRING     DestinationString,
                                _In_ PCUNICODE_STRING SourceString,
                                _In_ BOOLEAN          AllocateDestinationString)
{
        pRtlUnicodeStringToAnsiString impRtlUnicodeStringToAnsiString =
            (pRtlUnicodeStringToAnsiString)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, RTL_UNICODE_STRING_TO_ANSI_STRING_INDEX);

        return impRtlUnicodeStringToAnsiString(
            DestinationString, SourceString, AllocateDestinationString);
}

VOID
ImpRtlCopyUnicodeString(_In_ PUNICODE_STRING DestinationString, _In_ PCUNICODE_STRING SourceString)
{
        pRtlCopyUnicodeString impRtlCopyUnicodeString =
            (pRtlCopyUnicodeString)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, RTL_COPY_UNICODE_STRING_INDEX);

        impRtlCopyUnicodeString(DestinationString, SourceString);
}

VOID
ImpRtlFreeAnsiString(_In_ PANSI_STRING AnsiString)
{
        pRtlFreeAnsiString impRtlFreeAnsiString = (pRtlFreeAnsiString)CryptDecryptImportsArrayEntry(
            &driver_imports, IMPORTS_LENGTH, RTL_FREE_ANSI_STRING_INDEX);

        impRtlFreeAnsiString(AnsiString);
}

VOID
ImpKeInitializeGuardedMutex(_In_ PKGUARDED_MUTEX GuardedMutex)
{
        pKeInitializeGuardedMutex impKeInitializeGuardedMutex =
            (pKeInitializeGuardedMutex)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, KE_INITIALIZE_GUARDED_MUTEX_INDEX);

        impKeInitializeGuardedMutex(GuardedMutex);
}

NTSTATUS
ImpIoCreateDevice(_In_ PDRIVER_OBJECT      DriverObject,
                  _In_ ULONG               DeviceExtensionSize,
                  _In_opt_ PUNICODE_STRING DeviceName,
                  _In_ DEVICE_TYPE         DeviceType,
                  _In_ ULONG               DeviceCharacteristics,
                  _In_ BOOLEAN             Exclusive,
                  _Out_ PDEVICE_OBJECT*    DeviceObject)
{
        pIoCreateDevice impIoCreateDevice = (pIoCreateDevice)CryptDecryptImportsArrayEntry(
            &driver_imports, IMPORTS_LENGTH, IO_CREATE_DEVICE_INDEX);

        return impIoCreateDevice(DriverObject,
                                 DeviceExtensionSize,
                                 DeviceName,
                                 DeviceType,
                                 DeviceCharacteristics,
                                 Exclusive,
                                 DeviceObject);
}

NTSTATUS
ImpIoCreateSymbolicLink(_In_ PUNICODE_STRING SymbolicLinkName, _In_ PUNICODE_STRING DeviceName)
{
        pIoCreateSymbolicLink impIoCreateSymbolicLink =
            (pIoCreateSymbolicLink)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, IO_CREATE_SYMBOLIC_LINK_INDEX);

        return impIoCreateSymbolicLink(SymbolicLinkName, DeviceName);
}

VOID
ImpIoDeleteDevice(_In_ PDEVICE_OBJECT DeviceObject)
{
        pIoDeleteDevice impIoDeleteDevice = (pIoDeleteDevice)CryptDecryptImportsArrayEntry(
            &driver_imports, IMPORTS_LENGTH, IO_DELETE_DEVICE_INDEX);

        impIoDeleteDevice(DeviceObject);
}

VOID
ImpIoDeleteSymbolicLink(_In_ PUNICODE_STRING SymbolicLinkName)
{
        pIoDeleteSymbolicLink impIoDeleteSymbolicLink =
            (pIoDeleteSymbolicLink)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, IO_DELETE_SYMBOLIC_LINK_INDEX);

        impIoDeleteSymbolicLink(SymbolicLinkName);
}

NTSTATUS
ImpObRegisterCallbacks(_In_ POB_CALLBACK_REGISTRATION CallbackRegistration,
                       _Out_ PVOID*                   RegistrationHandle)
{
        pObRegisterCallbacks impObRegisterCallbacks =
            (pObRegisterCallbacks)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, OB_REGISTER_CALLBACKS_INDEX);

        return impObRegisterCallbacks(CallbackRegistration, RegistrationHandle);
}

VOID
ImpObUnRegisterCallbacks(_In_ PVOID RegistrationHandle)
{
        pObUnRegisterCallbacks impObUnRegisterCallbacks =
            (pObUnRegisterCallbacks)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, OB_UNREGISTER_CALLBACKS_INDEX);

        impObUnRegisterCallbacks(RegistrationHandle);
}

NTSTATUS
ImpPsSetCreateThreadNotifyRoutine(_In_ PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine)
{
        pPsSetCreateThreadNotifyRoutine impPsSetCreateThreadNotifyRoutine =
            (pPsSetCreateThreadNotifyRoutine)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, PS_SET_CREATE_THREAD_NOTIFY_ROUTINE_INDEX);

        return impPsSetCreateThreadNotifyRoutine(NotifyRoutine);
}

VOID
ImpKeRevertToUserAffinityThreadEx(_In_ KAFFINITY Affinity)
{
        pKeRevertToUserAffinityThreadEx impKeRevertToUserAffinityThreadEx =
            (pKeRevertToUserAffinityThreadEx)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, KE_REVERT_TO_USER_AFFINITY_THREAD_EX_INDEX);

        impKeRevertToUserAffinityThreadEx(Affinity);
}

KAFFINITY
ImpKeSetSystemAffinityThreadEx(_In_ KAFFINITY Affinity)
{
        pKeSetSystemAffinityThreadEx impKeSetSystemAffinityThreadEx =
            (pKeSetSystemAffinityThreadEx)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, KE_SET_SYSTEM_AFFINITY_THREAD_EX_INDEX);

        return impKeSetSystemAffinityThreadEx(Affinity);
}

SIZE_T
ImpStrnlen(_In_ CHAR* str, _In_ SIZE_T maxCount)
{
        pstrnlen impStrnlen =
            (pstrnlen)CryptDecryptImportsArrayEntry(&driver_imports, IMPORTS_LENGTH, STRNLEN_INDEX);

        return impStrnlen(str, maxCount);
}

VOID
ImpRtlInitAnsiString(_In_ PANSI_STRING DestinationString, _In_ PCSZ SourceString)
{
        pRtlInitAnsiString impRtlInitAnsiString = (pRtlInitAnsiString)CryptDecryptImportsArrayEntry(
            &driver_imports, IMPORTS_LENGTH, RTL_INIT_ANSI_STRING_INDEX);

        impRtlInitAnsiString(DestinationString, SourceString);
}

NTSTATUS
ImpRtlAnsiStringToUnicodeString(_In_ PUNICODE_STRING DestinationString,
                                _In_ PCANSI_STRING   SourceString,
                                _In_ BOOLEAN         AllocateDestinationString)
{
        pRtlAnsiStringToUnicodeString impRtlAnsiStringToUnicodeString =
            (pRtlAnsiStringToUnicodeString)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, RTL_ANSI_STRING_TO_UNICODE_STRING_INDEX);

        return impRtlAnsiStringToUnicodeString(
            DestinationString, SourceString, AllocateDestinationString);
}

PEPROCESS
ImpIoGetCurrentProcess()
{
        pIoGetCurrentProcess impIoGetCurrentProcess =
            (pIoGetCurrentProcess)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, IO_GET_CURRENT_PROCESS_INDEX);

        return impIoGetCurrentProcess();
}

NTSTATUS
ImpRtlGetVersion(_Out_ PRTL_OSVERSIONINFOW lpVersionInformation)
{
        pRtlGetVersion impRtlGetVersion = (pRtlGetVersion)CryptDecryptImportsArrayEntry(
            &driver_imports, IMPORTS_LENGTH, RTL_GET_VERSION_INDEX);

        return impRtlGetVersion(lpVersionInformation);
}

SIZE_T
ImpRtlCompareMemory(_In_ PVOID Source1, _In_ PVOID Source2, _In_ SIZE_T Length)
{
        pRtlCompareMemory impRtlCompareMemory = (pRtlCompareMemory)CryptDecryptImportsArrayEntry(
            &driver_imports, IMPORTS_LENGTH, RTL_COMPARE_MEMORY_INDEX);

        return impRtlCompareMemory(Source1, Source2, Length);
}

NTSTATUS
ImpExGetSystemFirmwareTable(_In_ ULONG   FirmwareTableProviderSignature,
                            _In_ ULONG   FirmwareTableID,
                            _In_ PVOID   pFirmwareTableBuffer,
                            _In_ ULONG   BufferLength,
                            _Out_ PULONG ReturnLength)
{
        pExGetSystemFirmwareTable impExGetSystemFirmwareTable =
            (pExGetSystemFirmwareTable)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, EX_GET_SYSTEM_FIRMWARE_TABLE_INDEX);

        return impExGetSystemFirmwareTable(FirmwareTableProviderSignature,
                                           FirmwareTableID,
                                           pFirmwareTableBuffer,
                                           BufferLength,
                                           ReturnLength);
}

PIO_WORKITEM
ImpIoAllocateWorkItem(_In_ PDEVICE_OBJECT DeviceObject)
{
        pIoAllocateWorkItem impIoAllocateWorkItem =
            (pIoAllocateWorkItem)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, IO_ALLOCATE_WORK_ITEM_INDEX);

        return impIoAllocateWorkItem(DeviceObject);
}

VOID
ImpIoFreeWorkItem(_In_ PIO_WORKITEM WorkItem)
{
        pIoFreeWorkItem impIoFreeWorkItem = (pIoFreeWorkItem)CryptDecryptImportsArrayEntry(
            &driver_imports, IMPORTS_LENGTH, IO_FREE_WORK_ITEM_INDEX);

        impIoFreeWorkItem(WorkItem);
}

VOID
ImpIoQueueWorkItem(_In_ PIO_WORKITEM         IoWorkItem,
                   _In_ PIO_WORKITEM_ROUTINE WorkerRoutine,
                   _In_ WORK_QUEUE_TYPE      QueueType,
                   _In_opt_ PVOID            Context)
{
        pIoQueueWorkItem impIoQueueWorkItem = (pIoQueueWorkItem)CryptDecryptImportsArrayEntry(
            &driver_imports, IMPORTS_LENGTH, IO_QUEUE_WORK_ITEM_INDEX);

        impIoQueueWorkItem(IoWorkItem, WorkerRoutine, QueueType, Context);
}

NTSTATUS
ImpZwOpenFile(_Out_ PHANDLE           FileHandle,
              _In_ ACCESS_MASK        DesiredAccess,
              _In_ POBJECT_ATTRIBUTES ObjectAttributes,
              _Out_ PIO_STATUS_BLOCK  IoStatusBlock,
              _In_ ULONG              ShareAccess,
              _In_ ULONG              OpenOptions)
{
        pZwOpenFile impZwOpenFile = (pZwOpenFile)CryptDecryptImportsArrayEntry(
            &driver_imports, IMPORTS_LENGTH, ZW_OPEN_FILE_INDEX);

        return impZwOpenFile(
            FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}

NTSTATUS
ImpZwClose(_In_ HANDLE Handle)
{
        pZwClose impZwClose = (pZwClose)CryptDecryptImportsArrayEntry(
            &driver_imports, IMPORTS_LENGTH, ZW_CLOSE_INDEX);

        return impZwClose(Handle);
}

NTSTATUS
ImpZwCreateSection(_Out_ PHANDLE               SectionHandle,
                   _In_ ACCESS_MASK            DesiredAccess,
                   _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
                   _In_opt_ PLARGE_INTEGER     MaximumSize,
                   _In_ ULONG                  SectionPageProtection,
                   _In_ ULONG                  AllocationAttributes,
                   _In_opt_ HANDLE             FileHandle)
{
        pZwCreateSection impZwCreateSection = (pZwCreateSection)CryptDecryptImportsArrayEntry(
            &driver_imports, IMPORTS_LENGTH, ZW_CREATE_SECTION_INDEX);

        return impZwCreateSection(SectionHandle,
                                  DesiredAccess,
                                  ObjectAttributes,
                                  MaximumSize,
                                  SectionPageProtection,
                                  AllocationAttributes,
                                  FileHandle);
}

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
                      _In_ ULONG                 Win32Protect)
{
        pZwMapViewOfSection impZwMapViewOfSection =
            (pZwMapViewOfSection)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, ZW_MAP_VIEW_OF_SECTION_INDEX);

        return impZwMapViewOfSection(SectionHandle,
                                     ProcessHandle,
                                     BaseAddress,
                                     ZeroBits,
                                     CommitSize,
                                     SectionOffset,
                                     ViewSize,
                                     InheritDisposition,
                                     AllocationType,
                                     Win32Protect);
}

NTSTATUS
ImpZwUnmapViewOfSection(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress)
{
        pZwUnmapViewOfSection impZwUnmapViewOfSection =
            (pZwUnmapViewOfSection)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, ZW_UNMAP_VIEW_OF_SECTION_INDEX);

        return impZwUnmapViewOfSection(ProcessHandle, BaseAddress);
}

NTSTATUS
ImpMmCopyMemory(_In_ PVOID           TargetAddress,
                _In_ MM_COPY_ADDRESS SourceAddress,
                _In_ SIZE_T          NumberOfBytes,
                _In_ ULONG           Flags,
                _Out_ PSIZE_T        NumberOfBytesTransferred)
{
        pMmCopyMemory impMmCopyMemory = (pMmCopyMemory)CryptDecryptImportsArrayEntry(
            &driver_imports, IMPORTS_LENGTH, MM_COPY_MEMORY_INDEX);

        return impMmCopyMemory(
            TargetAddress, SourceAddress, NumberOfBytes, Flags, NumberOfBytesTransferred);
}

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
                         _In_ ULONG               OutputBufferLength)
{
        pZwDeviceIoControlFile impZwDeviceIoControlFile =
            (pZwDeviceIoControlFile)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, ZW_DEVICE_IO_CONTROL_FILE_INDEX);

        return impZwDeviceIoControlFile(FileHandle,
                                        Event,
                                        ApcRoutine,
                                        ApcContext,
                                        IoStatusBlock,
                                        IoControlCode,
                                        InputBuffer,
                                        InputBufferLength,
                                        OutputBuffer,
                                        OutputBufferLength);
}

VOID
ImpKeStackAttachProcess(_In_ PRKPROCESS Process, _Out_ PKAPC_STATE ApcState)
{
        pKeStackAttachProcess impKeStackAttachProcess =
            (pKeStackAttachProcess)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, KE_STACK_ATTACH_PROCESS_INDEX);

        impKeStackAttachProcess(Process, ApcState);
}

VOID
ImpKeUnstackDetachProcess(_In_ PKAPC_STATE ApcState)
{
        pKeUnstackDetachProcess impKeUnstackDetachProcess =
            (pKeUnstackDetachProcess)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, KE_UNSTACK_DETACH_PROCESS_INDEX);

        impKeUnstackDetachProcess(ApcState);
}

NTSTATUS
ImpKeWaitForSingleObject(_In_ PVOID           Object,
                         _In_ KWAIT_REASON    WaitReason,
                         _In_ KPROCESSOR_MODE WaitMode,
                         _In_ BOOLEAN         Alertable,
                         _In_ PLARGE_INTEGER  Timeout)
{
        pKeWaitForSingleObject impKeWaitForSingleObject =
            (pKeWaitForSingleObject)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, KE_WAIT_FOR_SINGLE_OBJECT_INDEX);

        return impKeWaitForSingleObject(Object, WaitReason, WaitMode, Alertable, Timeout);
}

NTSTATUS
ImpPsCreateSystemThread(_Out_ PHANDLE               ThreadHandle,
                        _In_ ULONG                  DesiredAccess,
                        _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
                        _In_opt_ HANDLE             ProcessHandle,
                        _Out_opt_ PCLIENT_ID        ClientId,
                        _In_ PKSTART_ROUTINE        StartRoutine,
                        _In_opt_ PVOID              StartContext)
{
        pPsCreateSystemThread impPsCreateSystemThread =
            (pPsCreateSystemThread)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, PS_CREATE_SYSTEM_THREAD_INDEX);

        return impPsCreateSystemThread(ThreadHandle,
                                       DesiredAccess,
                                       ObjectAttributes,
                                       ProcessHandle,
                                       ClientId,
                                       StartRoutine,
                                       StartContext);
}

VOID
ImpIofCompleteRequest(_In_ PIRP Irp, _In_ CCHAR PriorityBoost)
{
        pIofCompleteRequest impIofCompleteRequest =
            (pIofCompleteRequest)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, IOF_COMPLETE_REQUEST_INDEX);

        impIofCompleteRequest(Irp, PriorityBoost);
}

NTSTATUS
ImpObReferenceObjectByHandle(_In_ HANDLE                          Handle,
                             _In_ ACCESS_MASK                     DesiredAccess,
                             _In_opt_ POBJECT_TYPE                ObjectType,
                             _In_ KPROCESSOR_MODE                 AccessMode,
                             _Out_ PVOID*                         Object,
                             _Out_opt_ POBJECT_HANDLE_INFORMATION HandleInformation)
{
        pObReferenceObjectByHandle impObReferenceObjectByHandle =
            (pObReferenceObjectByHandle)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, OB_REFERENCE_OBJECT_BY_HANDLE_INDEX);

        return impObReferenceObjectByHandle(
            Handle, DesiredAccess, ObjectType, AccessMode, Object, HandleInformation);
}

NTSTATUS
ImpKeDelayExecutionThread(_In_ KPROCESSOR_MODE WaitMode,
                          _In_ BOOLEAN         Alertable,
                          _In_ PLARGE_INTEGER  Interval)
{
        pKeDelayExecutionThread impKeDelayExecutionThread =
            (pKeDelayExecutionThread)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, KE_DELAY_EXECUTION_THREAD_INDEX);

        return impKeDelayExecutionThread(WaitMode, Alertable, Interval);
}

PVOID
ImpKeRegisterNmiCallback(_In_ PVOID CallbackRoutine, _In_opt_ PVOID Context)
{
        pKeRegisterNmiCallback impKeRegisterNmiCallback =
            (pKeRegisterNmiCallback)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, KE_REGISTER_NMI_CALLBACK_INDEX);

        return impKeRegisterNmiCallback(CallbackRoutine, Context);
}

NTSTATUS
ImpKeDeregisterNmiCallback(_In_ PVOID Handle)
{
        pKeDeregisterNmiCallback impKeDeregisterNmiCallback =
            (pKeDeregisterNmiCallback)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, KE_DEREGISTER_NMI_CALLBACK_INDEX);

        return impKeDeregisterNmiCallback(Handle);
}

ULONG
ImpKeQueryActiveProcessorCount(_In_ PKAFFINITY ActiveProcessors)
{
        pKeQueryActiveProcessorCount impKeQueryActiveProcessorCount =
            (pKeQueryActiveProcessorCount)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, KE_QUERY_ACTIVE_PROCESSOR_COUNT_INDEX);

        return impKeQueryActiveProcessorCount(ActiveProcessors);
}

VOID
ImpExAcquirePushLockExclusiveEx(_Inout_ PEX_PUSH_LOCK PushLock, _In_ ULONG Flags)
{
        pExAcquirePushLockExclusiveEx impExAcquirePushLockExclusiveEx =
            (pExAcquirePushLockExclusiveEx)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, EX_ACQUIRE_PUSH_LOCK_EXCLUSIVE_EX_INDEX);

        impExAcquirePushLockExclusiveEx(PushLock, Flags);
}

VOID
ImpExReleasePushLockExclusiveEx(_Inout_ PEX_PUSH_LOCK PushLock, _In_ ULONG Flags)
{
        pExReleasePushLockExclusiveEx impExReleasePushLockExclusiveEx =
            (pExReleasePushLockExclusiveEx)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, EX_RELEASE_PUSH_LOCK_EXCLUSIVE_EX_INDEX);

        impExReleasePushLockExclusiveEx(PushLock, Flags);
}

HANDLE
ImpPsGetThreadId(_In_ PETHREAD Thread)
{
        pPsGetThreadId impPsGetThreadId = (pPsGetThreadId)CryptDecryptImportsArrayEntry(
            &driver_imports, IMPORTS_LENGTH, PS_GET_THREAD_ID_INDEX);

        return impPsGetThreadId(Thread);
}

USHORT
ImpRtlCaptureStackBackTrace(_In_ ULONG       FramesToSkip,
                            _In_ ULONG       FramesToCapture,
                            _Out_ PVOID*     BackTrace,
                            _Out_opt_ PULONG BackTraceHash)
{
        pRtlCaptureStackBackTrace impRtlCaptureStackBackTrace =
            (pRtlCaptureStackBackTrace)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, RTL_CAPTURE_STACK_BACK_TRACE_INDEX);

        return impRtlCaptureStackBackTrace(FramesToSkip, FramesToCapture, BackTrace, BackTraceHash);
}

NTSTATUS
ImpZwOpenDirectoryObject(_Out_ PHANDLE           DirectoryHandle,
                         _In_ ACCESS_MASK        DesiredAccess,
                         _In_ POBJECT_ATTRIBUTES ObjectAttributes)
{
        pZwOpenDirectoryObject impZwOpenDirectoryObject =
            (pZwOpenDirectoryObject)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, ZW_OPEN_DIRECTORY_OBJECT_INDEX);

        return impZwOpenDirectoryObject(DirectoryHandle, DesiredAccess, ObjectAttributes);
}

VOID
ImpKeInitializeAffinityEx(_In_ PKAFFINITY_EX AffinityMask)
{
        pKeInitializeAffinityEx impKeInitializeAffinityEx =
            (pKeInitializeAffinityEx)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, KE_INITIALIZE_AFFINITY_EX_INDEX);

        impKeInitializeAffinityEx(AffinityMask);
}

VOID
ImpKeAddProcessorAffinityEx(_In_ PKAFFINITY_EX Affinity, _In_ INT CoreNumber)
{
        pKeAddProcessorAffinityEx impKeAddProcessorAffinityEx =
            (pKeAddProcessorAffinityEx)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, KE_ADD_PROCESSOR_AFFINITY_EX_INDEX);

        impKeAddProcessorAffinityEx(Affinity, CoreNumber);
}

NTSTATUS
ImpRtlQueryModuleInformation(_Inout_ ULONG* InformationLength,
                             _In_ ULONG     SizePerModule,
                             _In_ PVOID     InformationBuffer)
{
        pRtlQueryModuleInformation impRtlQueryModuleInformation =
            (pRtlQueryModuleInformation)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, RTL_QUERY_MODULE_INFORMATION_INDEX);

        return impRtlQueryModuleInformation(InformationLength, SizePerModule, InformationBuffer);
}

VOID
ImpKeInitializeApc(_In_ PKAPC             Apc,
                   _In_ PKTHREAD          Thread,
                   _In_ KAPC_ENVIRONMENT  Environment,
                   _In_ PKKERNEL_ROUTINE  KernelRoutine,
                   _In_ PKRUNDOWN_ROUTINE RundownRoutine,
                   _In_ PKNORMAL_ROUTINE  NormalRoutine,
                   _In_ KPROCESSOR_MODE   ApcMode,
                   _In_ PVOID             NormalContext)
{
        pKeInitializeApc impKeInitializeApc = (pKeInitializeApc)CryptDecryptImportsArrayEntry(
            &driver_imports, IMPORTS_LENGTH, KE_INITIALIZE_APC_INDEX);

        impKeInitializeApc(Apc,
                           Thread,
                           Environment,
                           KernelRoutine,
                           RundownRoutine,
                           NormalRoutine,
                           ApcMode,
                           NormalContext);
}

BOOLEAN
ImpKeInsertQueueApc(_In_ PKAPC     Apc,
                    _In_ PVOID     SystemArgument1,
                    _In_ PVOID     SystemArgument2,
                    _In_ KPRIORITY Increment)
{
        pKeInsertQueueApc impKeInsertQueueApc = (pKeInsertQueueApc)CryptDecryptImportsArrayEntry(
            &driver_imports, IMPORTS_LENGTH, KE_INSERT_QUEUE_APC_INDEX);

        return impKeInsertQueueApc(Apc, SystemArgument1, SystemArgument2, Increment);
}

VOID
ImpKeGenericCallDpc(_In_ PKDEFERRED_ROUTINE DpcRoutine, _In_ PVOID Context)
{
        pKeGenericCallDpc impKeGenericCallDpc = (pKeGenericCallDpc)CryptDecryptImportsArrayEntry(
            &driver_imports, IMPORTS_LENGTH, KE_GENERIC_CALL_DPC_INDEX);

        impKeGenericCallDpc(DpcRoutine, Context);
}

VOID
ImpKeSignalCallDpcDone(_In_ PVOID SystemArgument1)
{
        pKeSignalCallDpcDone impKeSignalCallDpcDone =
            (pKeSignalCallDpcDone)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, KE_SIGNAL_CALL_DPC_DONE_INDEX);

        impKeSignalCallDpcDone(SystemArgument1);
}

PPHYSICAL_MEMORY_RANGE
ImpMmGetPhysicalMemoryRangesEx2(_In_ PVOID PartitionObject, _In_ ULONG Flags)
{
        pMmGetPhysicalMemoryRangesEx2 impMmGetPhysicalMemoryRangesEx2 =
            (pMmGetPhysicalMemoryRangesEx2)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, MM_GET_PHYSICAL_MEMORY_RANGES_EX2_INDEX);

        return impMmGetPhysicalMemoryRangesEx2(PartitionObject, Flags);
}

PVOID
ImpMmGetVirtualForPhysical(_In_ PHYSICAL_ADDRESS PhysicalAddress)
{
        pMmGetVirtualForPhysical impMmGetVirtualForPhysical =
            (pMmGetVirtualForPhysical)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, MM_GET_VIRTUAL_FOR_PHYSICAL_INDEX);

        return impMmGetVirtualForPhysical(PhysicalAddress);
}

LONG_PTR
ImpObfReferenceObject(_In_ PVOID Object)
{
        pObfReferenceObject impObfReferenceObject =
            (pObfReferenceObject)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, OBF_REFERENCE_OBJECT_INDEX);

        return impObfReferenceObject(Object);
}

VOID
ImpExFreePoolWithTag(_In_ PVOID P, _In_ ULONG Tag)
{
        pExFreePoolWithTag impExFreePoolWithTag = (pExFreePoolWithTag)CryptDecryptImportsArrayEntry(
            &driver_imports, IMPORTS_LENGTH, EX_FREE_POOL_WITH_TAG_INDEX);

        impExFreePoolWithTag(P, Tag);
}

PVOID
ImpExAllocatePool2(_In_ POOL_FLAGS Flags, _In_ SIZE_T NumberOfBytes, _In_ ULONG Tag)
{
        pExAllocatePool2 impExAllocatePool2 = (pExAllocatePool2)CryptDecryptImportsArrayEntry(
            &driver_imports, IMPORTS_LENGTH, EX_ALLOCATE_POOL2_INDEX);

        return impExAllocatePool2(Flags, NumberOfBytes, Tag);
}

VOID
ImpKeReleaseGuardedMutex(_In_ PKGUARDED_MUTEX GuardedMutex)
{
        pKeReleaseGuardedMutex impKeReleaseGuardedMutex =
            (pKeReleaseGuardedMutex)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, KE_RELEASE_GUARDED_MUTEX_INDEX);

        impKeReleaseGuardedMutex(GuardedMutex);
}

VOID
ImpKeAcquireGuardedMutex(_In_ PKGUARDED_MUTEX GuardedMutex)
{
        pKeAcquireGuardedMutex impKeAcquireGuardedMutex =
            (pKeAcquireGuardedMutex)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, KE_ACQUIRE_GUARDED_MUTEX_INDEX);

        impKeAcquireGuardedMutex(GuardedMutex);
}

ULONG
ImpDbgPrintEx(_In_ ULONG ComponentId, _In_ ULONG Level, _In_ PCSTR Format, ...)
{
        pDbgPrintEx impDbgPrintEx = (pDbgPrintEx)CryptDecryptImportsArrayEntry(
            &driver_imports, IMPORTS_LENGTH, DBG_PRINT_EX_INDEX);

        va_list args;
        va_start(args, Format);
        ULONG result = impDbgPrintEx(ComponentId, Level, Format, args);
        va_end(args);

        return result;
}

LONG
ImpRtlCompareUnicodeString(_In_ PCUNICODE_STRING String1,
                           _In_ PCUNICODE_STRING String2,
                           _In_ BOOLEAN          CaseInSensitive)
{
        pRtlCompareUnicodeString impRtlCompareUnicodeString =
            (pRtlCompareUnicodeString)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, RTL_COMPARE_UNICODE_STRING_INDEX);

        return impRtlCompareUnicodeString(String1, String2, CaseInSensitive);
}

VOID
ImpRtlFreeUnicodeString(_In_ PUNICODE_STRING UnicodeString)
{
        pRtlFreeUnicodeString impRtlFreeUnicodeString =
            (pRtlFreeUnicodeString)CryptDecryptImportsArrayEntry(
                &driver_imports, IMPORTS_LENGTH, RTL_FREE_UNICODE_STRING_INDEX);

        impRtlFreeUnicodeString(UnicodeString);
}