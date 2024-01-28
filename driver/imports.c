#include "imports.h"

#include "common.h"
#include "driver.h"

DRIVER_IMPORTS driver_imports = {0};

PVOID
FindDriverBaseNoApi(_In_ PDRIVER_OBJECT DriverObject, _In_ PWCH Name)
{
        PKLDR_DATA_TABLE_ENTRY first  = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;

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
FindNtExport(PDRIVER_OBJECT DriverObject, PCZPSTR ExportName)
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

        if (!ExportName)
                return NULL;

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

                ordinal       = ordinals_table[index];
                export_offset = export_addr_table[ordinal];

                target_function_addr = (PVOID)((UINT64)image_base + export_offset);

                DEBUG_VERBOSE("Function: %s, Address: %llx", name, target_function_addr);

                return target_function_addr;
        }

        return NULL;
}

NTSTATUS
ResolveDynamicImports(_In_ PDRIVER_OBJECT DriverObject)
{
        // clang-format off
        driver_imports.DrvImpObDereferenceObject               = FindNtExport(DriverObject, "ObDereferenceObject");
        driver_imports.DrvImpPsGetProcessImageFileName         = FindNtExport(DriverObject, "PsGetProcessImageFileName");
        driver_imports.DrvImpPsSetCreateProcessNotifyRoutine   = FindNtExport(DriverObject, "PsSetCreateProcessNotifyRoutine");
        driver_imports.DrvImpPsRemoveCreateThreadNotifyRoutine = FindNtExport(DriverObject, "PsRemoveCreateThreadNotifyRoutine");
        driver_imports.DrvImpPsGetCurrentThreadId              = FindNtExport(DriverObject, "PsGetCurrentThreadId");
        driver_imports.DrvImpPsGetProcessId                    = FindNtExport(DriverObject, "PsGetProcessId");
        driver_imports.DrvImpPsLookupProcessByProcessId        = FindNtExport(DriverObject, "PsLookupProcessByProcessId");
        driver_imports.DrvImpExEnumHandleTable                 = FindNtExport(DriverObject, "ExEnumHandleTable");
        driver_imports.DrvImpObGetObjectType                   = FindNtExport(DriverObject, "ObGetObjectType");
        driver_imports.DrvImpExfUnblockPushLock                = FindNtExport(DriverObject, "ExfUnblockPushLock");
        driver_imports.DrvImpstrstr                            = FindNtExport(DriverObject, "strstr");
        driver_imports.DrvImpRtlInitUnicodeString              = FindNtExport(DriverObject, "RtlInitUnicodeString");
        driver_imports.DrvImpMmGetSystemRoutineAddress         = FindNtExport(DriverObject, "MmGetSystemRoutineAddress");
        driver_imports.DrvImpRtlUnicodeStringToAnsiString      = FindNtExport(DriverObject, "RtlUnicodeStringToAnsiString");
        driver_imports.DrvImpRtlCopyUnicodeString              = FindNtExport(DriverObject, "RtlCopyUnicodeString");
        driver_imports.DrvImpRtlFreeAnsiString                 = FindNtExport(DriverObject, "RtlFreeAnsiString");
        driver_imports.DrvImpKeInitializeGuardedMutex          = FindNtExport(DriverObject, "KeInitializeGuardedMutex");
        driver_imports.DrvImpIoCreateDevice                    = FindNtExport(DriverObject, "IoCreateDevice");
        driver_imports.DrvImpIoCreateSymbolicLink              = FindNtExport(DriverObject, "IoCreateSymbolicLink");
        driver_imports.DrvImpIoDeleteDevice                    = FindNtExport(DriverObject, "IoDeleteDevice");
        driver_imports.DrvImpIoDeleteSymbolicLink              = FindNtExport(DriverObject, "IoDeleteSymbolicLink");
        driver_imports.DrvImpObRegisterCallbacks               = FindNtExport(DriverObject, "ObRegisterCallbacks");
        driver_imports.DrvImpObUnRegisterCallbacks             = FindNtExport(DriverObject, "ObUnRegisterCallbacks");
        driver_imports.DrvImpPsSetCreateThreadNotifyRoutine    = FindNtExport(DriverObject, "PsSetCreateThreadNotifyRoutine");
        driver_imports.DrvImpKeRevertToUserAffinityThreadEx    = FindNtExport(DriverObject, "KeRevertToUserAffinityThreadEx");
        driver_imports.DrvImpKeSetSystemAffinityThreadEx       = FindNtExport(DriverObject, "KeSetSystemAffinityThreadEx");
        driver_imports.DrvImpstrnlen                           = FindNtExport(DriverObject, "strnlen");
        driver_imports.DrvImpRtlInitAnsiString                 = FindNtExport(DriverObject, "RtlInitAnsiString");
        driver_imports.DrvImpRtlAnsiStringToUnicodeString      = FindNtExport(DriverObject, "RtlAnsiStringToUnicodeString");
        driver_imports.DrvImpIoGetCurrentProcess               = FindNtExport(DriverObject, "IoGetCurrentProcess");
        driver_imports.DrvImpRtlGetVersion                     = FindNtExport(DriverObject, "RtlGetVersion");
        driver_imports.DrvImpRtlCompareMemory                  = FindNtExport(DriverObject, "RtlCompareMemory");
        driver_imports.DrvImpExGetSystemFirmwareTable          = FindNtExport(DriverObject, "ExGetSystemFirmwareTable");
        driver_imports.DrvImpIoAllocateWorkItem                = FindNtExport(DriverObject, "IoAllocateWorkItem");
        driver_imports.DrvImpIoFreeWorkItem                    = FindNtExport(DriverObject, "IoFreeWorkItem");
        driver_imports.DrvImpIoQueueWorkItem                   = FindNtExport(DriverObject, "IoQueueWorkItem");
        driver_imports.DrvImpZwOpenFile                        = FindNtExport(DriverObject, "ZwOpenFile");
        driver_imports.DrvImpZwClose                           = FindNtExport(DriverObject, "ZwClose");
        driver_imports.DrvImpZwCreateSection                   = FindNtExport(DriverObject, "ZwCreateSection");
        driver_imports.DrvImpZwMapViewOfSection                = FindNtExport(DriverObject, "ZwMapViewOfSection");
        driver_imports.DrvImpZwUnmapViewOfSection              = FindNtExport(DriverObject, "ZwUnmapViewOfSection");
        driver_imports.DrvImpMmCopyMemory                      = FindNtExport(DriverObject, "MmCopyMemory");
        driver_imports.DrvImpZwDeviceIoControlFile             = FindNtExport(DriverObject, "ZwDeviceIoControlFile");
        driver_imports.DrvImpKeStackAttachProcess              = FindNtExport(DriverObject, "KeStackAttachProcess");
        driver_imports.DrvImpKeUnstackDetachProcess            = FindNtExport(DriverObject, "KeUnstackDetachProcess");
        driver_imports.DrvImpKeWaitForSingleObject             = FindNtExport(DriverObject, "KeWaitForSingleObject");
        driver_imports.DrvImpPsCreateSystemThread              = FindNtExport(DriverObject, "PsCreateSystemThread");
        driver_imports.DrvImpIofCompleteRequest                = FindNtExport(DriverObject, "IofCompleteRequest");
        driver_imports.DrvImpObReferenceObjectByHandle         = FindNtExport(DriverObject, "ObReferenceObjectByHandle");
        driver_imports.DrvImpKeDelayExecutionThread            = FindNtExport(DriverObject, "KeDelayExecutionThread");
        driver_imports.DrvImpKeRegisterNmiCallback             = FindNtExport(DriverObject, "KeRegisterNmiCallback");
        driver_imports.DrvImpKeDeregisterNmiCallback           = FindNtExport(DriverObject, "KeDeregisterNmiCallback");
        driver_imports.DrvImpKeQueryActiveProcessorCount       = FindNtExport(DriverObject, "KeQueryActiveProcessorCount");
        driver_imports.DrvImpExAcquirePushLockExclusiveEx      = FindNtExport(DriverObject, "ExAcquirePushLockExclusiveEx");
        driver_imports.DrvImpExReleasePushLockExclusiveEx      = FindNtExport(DriverObject, "ExReleasePushLockExclusiveEx");
        driver_imports.DrvImpPsGetThreadId                     = FindNtExport(DriverObject, "PsGetThreadId");
        driver_imports.DrvImpRtlCaptureStackBackTrace          = FindNtExport(DriverObject, "RtlCaptureStackBackTrace");
        driver_imports.DrvImpZwOpenDirectoryObject             = FindNtExport(DriverObject, "ZwOpenDirectoryObject");
        driver_imports.DrvImpKeInitializeAffinityEx            = FindNtExport(DriverObject, "KeInitializeAffinityEx");
        driver_imports.DrvImpKeAddProcessorAffinityEx          = FindNtExport(DriverObject, "KeAddProcessorAffinityEx");
        driver_imports.DrvImpRtlQueryModuleInformation         = FindNtExport(DriverObject, "RtlQueryModuleInformation");
        driver_imports.DrvImpKeInitializeApc                   = FindNtExport(DriverObject, "KeInitializeApc");
        driver_imports.DrvImpKeInsertQueueApc                  = FindNtExport(DriverObject, "KeInsertQueueApc");
        driver_imports.DrvImpKeGenericCallDpc                  = FindNtExport(DriverObject, "KeGenericCallDpc");
        driver_imports.DrvImpKeSignalCallDpcDone               = FindNtExport(DriverObject, "KeSignalCallDpcDone");
        driver_imports.DrvImpMmGetPhysicalMemoryRangesEx2      = FindNtExport(DriverObject, "MmGetPhysicalMemoryRangesEx2");
        driver_imports.DrvImpMmGetVirtualForPhysical           = FindNtExport(DriverObject, "MmGetVirtualForPhysical");
        driver_imports.DrvImpObfReferenceObject                = FindNtExport(DriverObject, "ObfReferenceObject");
        driver_imports.DrvImpExFreePoolWithTag                 = FindNtExport(DriverObject, "ExFreePoolWithTag");
        driver_imports.DrvImpExAllocatePool2                   = FindNtExport(DriverObject, "ExAllocatePool2");
        driver_imports.DrvImpKeReleaseGuardedMutex             = FindNtExport(DriverObject, "KeReleaseGuardedMutex");
        driver_imports.DrvImpKeAcquireGuardedMutex             = FindNtExport(DriverObject, "KeAcquireGuardedMutex");
        driver_imports.DrvImpDbgPrintEx                        = FindNtExport(DriverObject, "DbgPrintEx");
        driver_imports.DrvImpRtlCompareUnicodeString           = FindNtExport(DriverObject, "RtlCompareUnicodeString");
        driver_imports.DrvImpRtlFreeUnicodeString              = FindNtExport(DriverObject, "RtlFreeUnicodeString");
        driver_imports.DrvImpPsLookupThreadByThreadId          = FindNtExport(DriverObject, "PsLookupThreadByThreadId");
        driver_imports.DrvImpMmIsAddressValid                  = FindNtExport(DriverObject, "MmIsAddressValid");

        DEBUG_VERBOSE("DrvImpObDereferenceObject);               %llx", (UINT64)driver_imports.DrvImpObDereferenceObject);               
        DEBUG_VERBOSE("DrvImpPsGetProcessImageFileName);         %llx", (UINT64)driver_imports.DrvImpPsGetProcessImageFileName);         
        DEBUG_VERBOSE("DrvImpPsSetCreateProcessNotifyRoutine);   %llx", (UINT64)driver_imports.DrvImpPsSetCreateProcessNotifyRoutine);   
        DEBUG_VERBOSE("DrvImpPsRemoveCreateThreadNotifyRoutine); %llx", (UINT64)driver_imports.DrvImpPsRemoveCreateThreadNotifyRoutine); 
        DEBUG_VERBOSE("DrvImpPsGetCurrentThreadId);              %llx", (UINT64)driver_imports.DrvImpPsGetCurrentThreadId);              
        DEBUG_VERBOSE("DrvImpPsGetProcessId);                    %llx", (UINT64)driver_imports.DrvImpPsGetProcessId);                    
        DEBUG_VERBOSE("DrvImpPsLookupProcessByProcessId);%llx", (UINT64)driver_imports.DrvImpPsLookupProcessByProcessId);
        DEBUG_VERBOSE("DrvImpExEnumHandleTable);%llx", (UINT64)driver_imports.DrvImpExEnumHandleTable);
        DEBUG_VERBOSE("DrvImpObGetObjectType);%llx", (UINT64)driver_imports.DrvImpObGetObjectType);
        DEBUG_VERBOSE("DrvImpExfUnblockPushLock);%llx", (UINT64)driver_imports.DrvImpExfUnblockPushLock);
        DEBUG_VERBOSE("DrvImpstrstr);%llx", (UINT64)driver_imports.DrvImpstrstr);
        DEBUG_VERBOSE("DrvImpRtlInitUnicodeString);%llx", (UINT64)driver_imports.DrvImpRtlInitUnicodeString);
        DEBUG_VERBOSE("DrvImpMmGetSystemRoutineAddress);%llx", (UINT64)driver_imports.DrvImpMmGetSystemRoutineAddress);
        DEBUG_VERBOSE("DrvImpRtlUnicodeStringToAnsiString);%llx", (UINT64)driver_imports.DrvImpRtlUnicodeStringToAnsiString);
        DEBUG_VERBOSE("DrvImpRtlCopyUnicodeString);%llx", (UINT64)driver_imports.DrvImpRtlCopyUnicodeString);
        DEBUG_VERBOSE("DrvImpRtlFreeAnsiString);%llx", (UINT64)driver_imports.DrvImpRtlFreeAnsiString);
        DEBUG_VERBOSE("DrvImpKeInitializeGuardedMutex);%llx", (UINT64)driver_imports.DrvImpKeInitializeGuardedMutex);
        DEBUG_VERBOSE("DrvImpIoCreateDevice);%llx", (UINT64)driver_imports.DrvImpIoCreateDevice);
        DEBUG_VERBOSE("DrvImpIoCreateSymbolicLink);%llx", (UINT64)driver_imports.DrvImpIoCreateSymbolicLink);
        DEBUG_VERBOSE("DrvImpIoDeleteDevice);%llx", (UINT64)driver_imports.DrvImpIoDeleteDevice);
        DEBUG_VERBOSE("DrvImpIoDeleteSymbolicLink);%llx", (UINT64)driver_imports.DrvImpIoDeleteSymbolicLink);
        DEBUG_VERBOSE("DrvImpObRegisterCallbacks);%llx", (UINT64)driver_imports.DrvImpObRegisterCallbacks);
        DEBUG_VERBOSE("DrvImpObUnRegisterCallbacks);%llx", (UINT64)driver_imports.DrvImpObUnRegisterCallbacks);
        DEBUG_VERBOSE("DrvImpPsSetCreateThreadNotifyRoutine);%llx", (UINT64)driver_imports.DrvImpPsSetCreateThreadNotifyRoutine);
        DEBUG_VERBOSE("DrvImpKeRevertToUserAffinityThreadEx);%llx", (UINT64)driver_imports.DrvImpKeRevertToUserAffinityThreadEx);
        DEBUG_VERBOSE("DrvImpKeSetSystemAffinityThreadEx);%llx", (UINT64)driver_imports.DrvImpKeSetSystemAffinityThreadEx);
        DEBUG_VERBOSE("DrvImpstrnlen     );%llx", (UINT64)driver_imports.DrvImpstrnlen     );
        DEBUG_VERBOSE("DrvImpRtlInitAnsiString);%llx", (UINT64)driver_imports.DrvImpRtlInitAnsiString);
        DEBUG_VERBOSE("DrvImpRtlAnsiStringToUnicodeString);%llx", (UINT64)driver_imports.DrvImpRtlAnsiStringToUnicodeString);
        DEBUG_VERBOSE("DrvImpIoGetCurrentProcess);%llx", (UINT64)driver_imports.DrvImpIoGetCurrentProcess);
        DEBUG_VERBOSE("DrvImpRtlGetVersion);%llx", (UINT64)driver_imports.DrvImpRtlGetVersion);
        DEBUG_VERBOSE("DrvImpRtlCompareMemory);%llx", (UINT64)driver_imports.DrvImpRtlCompareMemory);
        DEBUG_VERBOSE("DrvImpExGetSystemFirmwareTable);%llx", (UINT64)driver_imports.DrvImpExGetSystemFirmwareTable);
        DEBUG_VERBOSE("DrvImpIoAllocateWorkItem);%llx", (UINT64)driver_imports.DrvImpIoAllocateWorkItem);
        DEBUG_VERBOSE("DrvImpIoFreeWorkItem);%llx", (UINT64)driver_imports.DrvImpIoFreeWorkItem);
        DEBUG_VERBOSE("DrvImpIoQueueWorkItem);%llx", (UINT64)driver_imports.DrvImpIoQueueWorkItem);
        DEBUG_VERBOSE("DrvImpZwOpenFile  );%llx", (UINT64)driver_imports.DrvImpZwOpenFile  );
        DEBUG_VERBOSE("DrvImpZwClose     );%llx", (UINT64)driver_imports.DrvImpZwClose     );
        DEBUG_VERBOSE("DrvImpZwCreateSection);%llx", (UINT64)driver_imports.DrvImpZwCreateSection);
        DEBUG_VERBOSE("DrvImpZwMapViewOfSection);%llx", (UINT64)driver_imports.DrvImpZwMapViewOfSection);
        DEBUG_VERBOSE("DrvImpZwUnmapViewOfSection);%llx", (UINT64)driver_imports.DrvImpZwUnmapViewOfSection);
        DEBUG_VERBOSE("DrvImpMmCopyMemory);%llx", (UINT64)driver_imports.DrvImpMmCopyMemory);
        DEBUG_VERBOSE("DrvImpZwDeviceIoControlFile);%llx", (UINT64)driver_imports.DrvImpZwDeviceIoControlFile);
        DEBUG_VERBOSE("DrvImpKeStackAttachProcess);%llx", (UINT64)driver_imports.DrvImpKeStackAttachProcess);
        DEBUG_VERBOSE("DrvImpKeUnstackDetachProcess);%llx", (UINT64)driver_imports.DrvImpKeUnstackDetachProcess);
        DEBUG_VERBOSE("DrvImpKeWaitForSingleObject);%llx", (UINT64)driver_imports.DrvImpKeWaitForSingleObject);
        DEBUG_VERBOSE("DrvImpPsCreateSystemThread);%llx", (UINT64)driver_imports.DrvImpPsCreateSystemThread);
        DEBUG_VERBOSE("DrvImpIofCompleteRequest);%llx", (UINT64)driver_imports.DrvImpIofCompleteRequest);
        DEBUG_VERBOSE("DrvImpObReferenceObjectByHandle);%llx", (UINT64)driver_imports.DrvImpObReferenceObjectByHandle);
        DEBUG_VERBOSE("DrvImpKeDelayExecutionThread);%llx", (UINT64)driver_imports.DrvImpKeDelayExecutionThread);
        DEBUG_VERBOSE("DrvImpKeRegisterNmiCallback);%llx", (UINT64)driver_imports.DrvImpKeRegisterNmiCallback);
        DEBUG_VERBOSE("DrvImpKeDeregisterNmiCallback);%llx", (UINT64)driver_imports.DrvImpKeDeregisterNmiCallback);
        DEBUG_VERBOSE("DrvImpKeQueryActiveProcessorCount);%llx", (UINT64)driver_imports.DrvImpKeQueryActiveProcessorCount);
        DEBUG_VERBOSE("DrvImpExAcquirePushLockExclusiveEx);%llx", (UINT64)driver_imports.DrvImpExAcquirePushLockExclusiveEx);
        DEBUG_VERBOSE("DrvImpExReleasePushLockExclusiveEx);%llx", (UINT64)driver_imports.DrvImpExReleasePushLockExclusiveEx);
        DEBUG_VERBOSE("DrvImpPsGetThreadId);%llx", (UINT64)driver_imports.DrvImpPsGetThreadId);
        DEBUG_VERBOSE("DrvImpRtlCaptureStackBackTrace);%llx", (UINT64)driver_imports.DrvImpRtlCaptureStackBackTrace);
        DEBUG_VERBOSE("DrvImpZwOpenDirectoryObject);%llx", (UINT64)driver_imports.DrvImpZwOpenDirectoryObject);
        DEBUG_VERBOSE("DrvImpKeInitializeAffinityEx);%llx", (UINT64)driver_imports.DrvImpKeInitializeAffinityEx);
        DEBUG_VERBOSE("DrvImpKeAddProcessorAffinityEx);%llx", (UINT64)driver_imports.DrvImpKeAddProcessorAffinityEx);
        DEBUG_VERBOSE("DrvImpRtlQueryModuleInformation);%llx", (UINT64)driver_imports.DrvImpRtlQueryModuleInformation);
        DEBUG_VERBOSE("DrvImpKeInitializeApc);%llx", (UINT64)driver_imports.DrvImpKeInitializeApc);
        DEBUG_VERBOSE("DrvImpKeInsertQueueApc);%llx", (UINT64)driver_imports.DrvImpKeInsertQueueApc);
        DEBUG_VERBOSE("DrvImpKeGenericCallDpc);%llx", (UINT64)driver_imports.DrvImpKeGenericCallDpc);
        DEBUG_VERBOSE("DrvImpKeSignalCallDpcDone);%llx", (UINT64)driver_imports.DrvImpKeSignalCallDpcDone);
        DEBUG_VERBOSE("DrvImpMmGetPhysicalMemoryRangesEx2);%llx", (UINT64)driver_imports.DrvImpMmGetPhysicalMemoryRangesEx2);
        DEBUG_VERBOSE("DrvImpMmGetVirtualForPhysical);%llx", (UINT64)driver_imports.DrvImpMmGetVirtualForPhysical);
        DEBUG_VERBOSE("DrvImpObfReferenceObject);%llx", (UINT64)driver_imports.DrvImpObfReferenceObject);
        DEBUG_VERBOSE("DrvImpExFreePoolWithTag);%llx", (UINT64)driver_imports.DrvImpExFreePoolWithTag);
        DEBUG_VERBOSE("DrvImpExAllocatePool2);%llx", (UINT64)driver_imports.DrvImpExAllocatePool2);
        DEBUG_VERBOSE("DrvImpKeReleaseGuardedMutex);%llx", (UINT64)driver_imports.DrvImpKeReleaseGuardedMutex);
        DEBUG_VERBOSE("DrvImpKeAcquireGuardedMutex);%llx", (UINT64)driver_imports.DrvImpKeAcquireGuardedMutex);
        DEBUG_VERBOSE("DrvImpDbgPrintEx  );%llx", (UINT64)driver_imports.DrvImpDbgPrintEx  );
        DEBUG_VERBOSE("DrvImpRtlCompareUnicodeString);%llx", (UINT64)driver_imports.DrvImpRtlCompareUnicodeString);
        DEBUG_VERBOSE("DrvImpRtlFreeUnicodeString);%llx", (UINT64)driver_imports.DrvImpRtlFreeUnicodeString);
        DEBUG_VERBOSE("DrvImpPsLookupThreadByThreadId);%llx", (UINT64)driver_imports.DrvImpPsLookupThreadByThreadId);
        DEBUG_VERBOSE("DrvImpIoGetCurrentIrpStackLocation);%llx", (UINT64)driver_imports.DrvImpIoGetCurrentIrpStackLocation);
        DEBUG_VERBOSE("DrvImpMmIsAddressValid);                  %llx", (UINT64)driver_imports.DrvImpMmIsAddressValid);                  

        if (!driver_imports.DrvImpObDereferenceObject) return STATUS_UNSUCCESSFUL;
        if (!driver_imports.DrvImpPsGetProcessImageFileName) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpPsSetCreateProcessNotifyRoutine) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpPsRemoveCreateThreadNotifyRoutine) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpPsGetCurrentThreadId) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpPsGetProcessId) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpPsLookupProcessByProcessId) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpExEnumHandleTable) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpObGetObjectType) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpExfUnblockPushLock) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpstrstr) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpRtlInitUnicodeString) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpMmGetSystemRoutineAddress) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpRtlUnicodeStringToAnsiString) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpRtlCopyUnicodeString) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpRtlFreeAnsiString) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpKeInitializeGuardedMutex) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpIoCreateDevice) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpIoCreateSymbolicLink) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpIoDeleteDevice) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpIoDeleteSymbolicLink) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpObRegisterCallbacks) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpObUnRegisterCallbacks) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpPsSetCreateThreadNotifyRoutine) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpKeRevertToUserAffinityThreadEx) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpKeSetSystemAffinityThreadEx) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpstrnlen) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpRtlInitAnsiString) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpRtlAnsiStringToUnicodeString) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpIoGetCurrentProcess) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpRtlGetVersion) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpRtlCompareMemory) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpExGetSystemFirmwareTable) return STATUS_UNSUCCESSFUL; 
        if (!driver_imports.DrvImpIoAllocateWorkItem) return STATUS_UNSUCCESSFUL;
        if (!driver_imports.DrvImpIoFreeWorkItem) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpIoQueueWorkItem) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpZwOpenFile) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpZwClose) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpZwCreateSection) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpZwMapViewOfSection) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpZwUnmapViewOfSection) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpMmCopyMemory) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpZwDeviceIoControlFile) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpKeStackAttachProcess) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpKeUnstackDetachProcess) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpKeWaitForSingleObject) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpPsCreateSystemThread) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpIofCompleteRequest) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpObReferenceObjectByHandle) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpKeDelayExecutionThread) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpKeRegisterNmiCallback) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpKeDeregisterNmiCallback) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpKeQueryActiveProcessorCount) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpExAcquirePushLockExclusiveEx) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpExReleasePushLockExclusiveEx) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpPsGetThreadId) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpRtlCaptureStackBackTrace) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpZwOpenDirectoryObject) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpKeInitializeAffinityEx) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpKeAddProcessorAffinityEx) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpRtlQueryModuleInformation) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpKeInitializeApc) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpKeInsertQueueApc) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpKeGenericCallDpc) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpKeSignalCallDpcDone) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpMmGetPhysicalMemoryRangesEx2) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpMmGetVirtualForPhysical) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpObfReferenceObject) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpExFreePoolWithTag) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpExAllocatePool2) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpKeReleaseGuardedMutex) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpKeAcquireGuardedMutex) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpDbgPrintEx) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpRtlCompareUnicodeString) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpRtlFreeUnicodeString) return STATUS_UNSUCCESSFUL;     
        if (!driver_imports.DrvImpPsLookupThreadByThreadId) return STATUS_UNSUCCESSFUL;          
        if (!driver_imports.DrvImpMmIsAddressValid) return STATUS_UNSUCCESSFUL;
        // clang-format on

        return STATUS_SUCCESS;
}