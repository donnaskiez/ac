#include "imports.h"

#include "common.h"
#include "driver.h"

#define EPROCESS_SECTION_BASE_OFFSET 0x520

#define IMAGE_DIRECTORY_ENTRY_EXPORT         0
#define IMAGE_DIRECTORY_ENTRY_IMPORT         1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE       2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION      3
#define IMAGE_DIRECTORY_ENTRY_SECURITY       4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC      5
#define IMAGE_DIRECTORY_ENTRY_DEBUG          6
#define IMAGE_DIRECTORY_ENTRY_COPYRIGHT      7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR      8 /* (MIPS GP) */
#define IMAGE_DIRECTORY_ENTRY_TLS            9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11
#define IMAGE_DIRECTORY_ENTRY_IAT            12 /* Import Address Table */
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14

PDRIVER_IMPORTS driver_imports = NULL;

VOID
FreeDriverImportsStructure()
{
        if (driver_imports)
                ExFreePoolWithTag(driver_imports, POOL_TAG_INTEGRITY);
}

PVOID
FindDriverBaseNoApi(_In_ PWCH Name)
{
        PDRIVER_OBJECT         driver = GetDriverObject();
        PKLDR_DATA_TABLE_ENTRY first  = (PKLDR_DATA_TABLE_ENTRY)driver->DriverSection;

        /* first entry contains invalid data, 2nd entry is the kernel */
        PKLDR_DATA_TABLE_ENTRY entry =
            ((PKLDR_DATA_TABLE_ENTRY)driver->DriverSection)->InLoadOrderLinks.Flink->Flink;

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

void*
FindNtExport(const char* ExportName)
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

        image_base = FindDriverBaseNoApi(L"ntoskrnl.exe");

        if (!image_base)
        {
                DEBUG_ERROR("FindDriverBaseNoApi failed with no status");
                return NULL;
        }

        /*
         * todo: add comment explaining this shit
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
ResolveNtImports()
{
        NTSTATUS status = STATUS_UNSUCCESSFUL;

        /* todo fix! */
        driver_imports =
            ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(DRIVER_IMPORTS), POOL_TAG_INTEGRITY);

        if (!driver_imports)
                return STATUS_MEMORY_NOT_ALLOCATED;

        // clang-format off
        driver_imports->DrvImpObDereferenceObject               = FindNtExport("ObDereferenceObject");
        driver_imports->DrvImpPsGetProcessImageFileName         = FindNtExport("PsGetProcessImageFileName");
        driver_imports->DrvImpPsSetCreateProcessNotifyRoutine   = FindNtExport("PsSetCreateProcessNotifyRoutine");
        driver_imports->DrvImpPsRemoveCreateThreadNotifyRoutine = FindNtExport("PsRemoveCreateThreadNotifyRoutine");
        driver_imports->DrvImpPsGetCurrentThreadId              = FindNtExport("PsGetCurrentThreadId");
        driver_imports->DrvImpPsGetProcessId                    = FindNtExport("PsGetProcessId");
        driver_imports->DrvImpPsLookupProcessByProcessId        = FindNtExport("PsLookupProcessByProcessId");
        driver_imports->DrvImpExEnumHandleTable                 = FindNtExport("ExEnumHandleTable");
        driver_imports->DrvImpObGetObjectType                   = FindNtExport("ObGetObjectType");
        driver_imports->DrvImpExfUnblockPushLock                = FindNtExport("ExfUnblockPushLock");
        driver_imports->DrvImpstrstr                            = FindNtExport("strstr");
        driver_imports->DrvImpRtlInitUnicodeString              = FindNtExport("RtlInitUnicodeString");
        driver_imports->DrvImpMmGetSystemRoutineAddress         = FindNtExport("MmGetSystemRoutineAddress");
        driver_imports->DrvImpRtlUnicodeStringToAnsiString      = FindNtExport("RtlUnicodeStringToAnsiString");
        driver_imports->DrvImpRtlCopyUnicodeString              = FindNtExport("RtlCopyUnicodeString");
        driver_imports->DrvImpRtlFreeAnsiString                 = FindNtExport("RtlFreeAnsiString");
        driver_imports->DrvImpKeInitializeGuardedMutex          = FindNtExport("KeInitializeGuardedMutex");
        driver_imports->DrvImpIoCreateDevice                    = FindNtExport("IoCreateDevice");
        driver_imports->DrvImpIoCreateSymbolicLink              = FindNtExport("IoCreateSymbolicLink");
        driver_imports->DrvImpIoDeleteDevice                    = FindNtExport("IoDeleteDevice");
        driver_imports->DrvImpIoDeleteSymbolicLink              = FindNtExport("IoDeleteSymbolicLink");
        driver_imports->DrvImpObRegisterCallbacks               = FindNtExport("ObRegisterCallbacks");
        driver_imports->DrvImpObUnRegisterCallbacks             = FindNtExport("ObUnRegisterCallbacks");
        driver_imports->DrvImpPsSetCreateThreadNotifyRoutine    = FindNtExport("PsSetCreateThreadNotifyRoutine");
        driver_imports->DrvImpKeRevertToUserAffinityThreadEx    = FindNtExport("KeRevertToUserAffinityThreadEx");
        driver_imports->DrvImpKeSetSystemAffinityThreadEx       = FindNtExport("KeSetSystemAffinityThreadEx");
        driver_imports->DrvImpstrnlen                           = FindNtExport("strnlen");
        driver_imports->DrvImpRtlInitAnsiString                 = FindNtExport("RtlInitAnsiString");
        driver_imports->DrvImpRtlAnsiStringToUnicodeString      = FindNtExport("RtlAnsiStringToUnicodeString");
        driver_imports->DrvImpIoGetCurrentProcess               = FindNtExport("IoGetCurrentProcess");
        driver_imports->DrvImpRtlGetVersion                     = FindNtExport("RtlGetVersion");
        driver_imports->DrvImpRtlCompareMemory                  = FindNtExport("RtlCompareMemory");
        driver_imports->DrvImpExGetSystemFirmwareTable          = FindNtExport("ExGetSystemFirmwareTable");
        driver_imports->DrvImpIoAllocateWorkItem                = FindNtExport("IoAllocateWorkItem");
        driver_imports->DrvImpIoFreeWorkItem                    = FindNtExport("IoFreeWorkItem");
        driver_imports->DrvImpIoQueueWorkItem                   = FindNtExport("IoQueueWorkItem");
        driver_imports->DrvImpZwOpenFile                        = FindNtExport("ZwOpenFile");
        driver_imports->DrvImpZwClose                           = FindNtExport("ZwClose");
        driver_imports->DrvImpZwCreateSection                   = FindNtExport("ZwCreateSection");
        driver_imports->DrvImpZwMapViewOfSection                = FindNtExport("ZwMapViewOfSection");
        driver_imports->DrvImpZwUnmapViewOfSection              = FindNtExport("ZwUnmapViewOfSection");
        driver_imports->DrvImpMmCopyMemory                      = FindNtExport("MmCopyMemory");
        driver_imports->DrvImpZwDeviceIoControlFile             = FindNtExport("ZwDeviceIoControlFile");
        driver_imports->DrvImpKeStackAttachProcess              = FindNtExport("KeStackAttachProcess");
        driver_imports->DrvImpKeUnstackDetachProcess            = FindNtExport("KeUnstackDetachProcess");
        driver_imports->DrvImpKeWaitForSingleObject             = FindNtExport("KeWaitForSingleObject");
        driver_imports->DrvImpPsCreateSystemThread              = FindNtExport("PsCreateSystemThread");
        driver_imports->DrvImpIofCompleteRequest                = FindNtExport("IofCompleteRequest");
        driver_imports->DrvImpObReferenceObjectByHandle         = FindNtExport("ObReferenceObjectByHandle");
        driver_imports->DrvImpKeDelayExecutionThread            = FindNtExport("KeDelayExecutionThread");
        driver_imports->DrvImpKeRegisterNmiCallback             = FindNtExport("KeRegisterNmiCallback");
        driver_imports->DrvImpKeDeregisterNmiCallback           = FindNtExport("KeDeregisterNmiCallback");
        driver_imports->DrvImpKeQueryActiveProcessorCount       = FindNtExport("KeQueryActiveProcessorCount");
        driver_imports->DrvImpExAcquirePushLockExclusiveEx      = FindNtExport("ExAcquirePushLockExclusiveEx");
        driver_imports->DrvImpExReleasePushLockExclusiveEx      = FindNtExport("ExReleasePushLockExclusiveEx");
        driver_imports->DrvImpPsGetThreadId                     = FindNtExport("PsGetThreadId");
        driver_imports->DrvImpRtlCaptureStackBackTrace          = FindNtExport("RtlCaptureStackBackTrace");
        driver_imports->DrvImpZwOpenDirectoryObject             = FindNtExport("ZwOpenDirectoryObject");
        driver_imports->DrvImpKeInitializeAffinityEx            = FindNtExport("KeInitializeAffinityEx");
        driver_imports->DrvImpKeAddProcessorAffinityEx          = FindNtExport("KeAddProcessorAffinityEx");
        driver_imports->DrvImpRtlQueryModuleInformation         = FindNtExport("RtlQueryModuleInformation");
        driver_imports->DrvImpKeInitializeApc                   = FindNtExport("KeInitializeApc");
        driver_imports->DrvImpKeInsertQueueApc                  = FindNtExport("KeInsertQueueApc");
        driver_imports->DrvImpKeGenericCallDpc                  = FindNtExport("KeGenericCallDpc");
        driver_imports->DrvImpKeSignalCallDpcDone               = FindNtExport("KeSignalCallDpcDone");
        driver_imports->DrvImpMmGetPhysicalMemoryRangesEx2      = FindNtExport("MmGetPhysicalMemoryRangesEx2");
        driver_imports->DrvImpMmGetVirtualForPhysical           = FindNtExport("MmGetVirtualForPhysical");
        driver_imports->DrvImpObfReferenceObject                = FindNtExport("ObfReferenceObject");
        driver_imports->DrvImpExFreePoolWithTag                 = FindNtExport("ExFreePoolWithTag");
        driver_imports->DrvImpExAllocatePool2                   = FindNtExport("ExAllocatePool2");
        driver_imports->DrvImpKeReleaseGuardedMutex             = FindNtExport("KeReleaseGuardedMutex");
        driver_imports->DrvImpKeAcquireGuardedMutex             = FindNtExport("KeAcquireGuardedMutex");
        driver_imports->DrvImpDbgPrintEx                        = FindNtExport("DbgPrintEx");
        driver_imports->DrvImpRtlCompareUnicodeString           = FindNtExport("RtlCompareUnicodeString");
        driver_imports->DrvImpRtlFreeUnicodeString              = FindNtExport("RtlFreeUnicodeString");
        driver_imports->DrvImpPsLookupThreadByThreadId          = FindNtExport("PsLookupThreadByThreadId");
        driver_imports->DrvImpIoGetCurrentIrpStackLocation      = FindNtExport("IoGetCurrentIrpStackLocation");
        driver_imports->DrvImpMmIsAddressValid                  = FindNtExport("MmIsAddressValid");
        // clang-format on

        return STATUS_SUCCESS;
}