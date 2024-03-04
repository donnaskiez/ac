#include "modules.h"

#include "callbacks.h"
#include "driver.h"
#include "io.h"
#include "ia32.h"
#include "imports.h"
#include "apc.h"
#include "thread.h"

#define WHITELISTED_MODULE_TAG 'whte'

#define NMI_DELAY 200 * 10000

#define WHITELISTED_MODULE_COUNT 11
#define MODULE_MAX_STRING_SIZE   256

#define NTOSKRNL 0
#define CLASSPNP 1
#define WDF01000 2

/*
 * The modules seen in the array below have been seen to commonly hook other drivers'
 * IOCTL dispatch routines. Its possible to see this by using WinObjEx64 and checking which
 * module each individual dispatch routine lies in. These modules are then addded to the list
 * (in addition to either the driver itself or ntoskrnl) which is seen as a valid region
 * for a drivers dispatch routine to lie within.
 */
CHAR WHITELISTED_MODULES[WHITELISTED_MODULE_COUNT][MODULE_MAX_STRING_SIZE] = {"ntoskrnl.exe",
                                                                              "CLASSPNP.SYS",
                                                                              "Wdf01000.sys",
                                                                              "HIDCLASS.SYS",
                                                                              "storport.sys",
                                                                              "dxgkrnl.sys",
                                                                              "ndis.sys",
                                                                              "ks.sys",
                                                                              "portcls.sys",
                                                                              "rdbss.sys",
                                                                              "LXCORE.SYS"};

#define MODULE_REPORT_DRIVER_NAME_BUFFER_SIZE 128

#define REASON_NO_BACKING_MODULE      1
#define REASON_INVALID_IOCTL_DISPATCH 2

#define SYSTEM_IDLE_PROCESS_ID 0
#define SYSTEM_PROCESS_ID      4
#define SVCHOST_PROCESS_ID     8

typedef struct _WHITELISTED_REGIONS
{
        UINT64 base;
        UINT64 end;

} WHITELISTED_REGIONS, *PWHITELISTED_REGIONS;

typedef struct _NMI_POOLS
{
        PVOID thread_data_pool;
        PVOID stack_frames;
        PVOID nmi_context;

} NMI_POOLS, *PNMI_POOLS;

typedef struct _MODULE_VALIDATION_FAILURE_HEADER
{
        INT module_count;

} MODULE_VALIDATION_FAILURE_HEADER, *PMODULE_VALIDATION_FAILURE_HEADER;

typedef struct _NMI_CONTEXT
{
        UINT64  interrupted_rip;
        UINT64  interrupted_rsp;
        UINT64  kthread;
        UINT32  callback_count;
        BOOLEAN user_thread;

} NMI_CONTEXT, *PNMI_CONTEXT;

typedef struct _INVALID_DRIVER
{
        struct _INVALID_DRIVER* next;
        INT                     reason;
        PDRIVER_OBJECT          driver;

} INVALID_DRIVER, *PINVALID_DRIVER;

typedef struct _INVALID_DRIVERS_HEAD
{
        PINVALID_DRIVER first_entry;
        INT             count;

} INVALID_DRIVERS_HEAD, *PINVALID_DRIVERS_HEAD;

STATIC
NTSTATUS
PopulateWhitelistedModuleBuffer(_Inout_ PVOID Buffer, _In_ PSYSTEM_MODULES SystemModules);

STATIC
NTSTATUS
ValidateDriverIOCTLDispatchRegion(_In_ PDRIVER_OBJECT       Driver,
                                  _In_ PSYSTEM_MODULES      Modules,
                                  _In_ PWHITELISTED_REGIONS WhitelistedRegions,
                                  _Out_ PBOOLEAN            Flag);

STATIC
VOID
InitDriverList(_Inout_ PINVALID_DRIVERS_HEAD ListHead);

STATIC
NTSTATUS
AddDriverToList(_Inout_ PINVALID_DRIVERS_HEAD InvalidDriversHead,
                _In_ PDRIVER_OBJECT           Driver,
                _In_ INT                      Reason);

STATIC
VOID
RemoveInvalidDriverFromList(_Inout_ PINVALID_DRIVERS_HEAD InvalidDriversHead);

STATIC
VOID
EnumerateInvalidDrivers(_In_ PINVALID_DRIVERS_HEAD InvalidDriversHead);

STATIC
NTSTATUS
ValidateDriverObjectHasBackingModule(_In_ PSYSTEM_MODULES ModuleInformation,
                                     _In_ PDRIVER_OBJECT  DriverObject,
                                     _Out_ PBOOLEAN       Result);

STATIC
NTSTATUS
ValidateDriverObjects(_In_ PSYSTEM_MODULES          SystemModules,
                      _Inout_ PINVALID_DRIVERS_HEAD InvalidDriverListHead);

STATIC
NTSTATUS
AnalyseNmiData(_In_ PNMI_CONTEXT NmiContext, _In_ PSYSTEM_MODULES SystemModules);

STATIC
NTSTATUS
LaunchNonMaskableInterrupt();

STATIC
VOID
ApcRundownRoutine(_In_ PRKAPC Apc);

STATIC
VOID
ApcKernelRoutine(_In_ PRKAPC                                     Apc,
                 _Inout_ _Deref_pre_maybenull_ PKNORMAL_ROUTINE* NormalRoutine,
                 _Inout_ _Deref_pre_maybenull_ PVOID*            NormalContext,
                 _Inout_ _Deref_pre_maybenull_ PVOID*            SystemArgument1,
                 _Inout_ _Deref_pre_maybenull_ PVOID*            SystemArgument2);

STATIC
VOID
ApcNormalRoutine(_In_opt_ PVOID NormalContext,
                 _In_opt_ PVOID SystemArgument1,
                 _In_opt_ PVOID SystemArgument2);

STATIC
VOID
ValidateThreadViaKernelApcCallback(_In_ PTHREAD_LIST_ENTRY ThreadListEntry,
                                   _Inout_opt_ PVOID       Context);

#ifdef ALLOC_PRAGMA
#        pragma alloc_text(PAGE, FindSystemModuleByName)
#        pragma alloc_text(PAGE, PopulateWhitelistedModuleBuffer)
#        pragma alloc_text(PAGE, ValidateDriverIOCTLDispatchRegion)
#        pragma alloc_text(PAGE, InitDriverList)
#        pragma alloc_text(PAGE, AddDriverToList)
#        pragma alloc_text(PAGE, RemoveInvalidDriverFromList)
#        pragma alloc_text(PAGE, EnumerateInvalidDrivers)
#        pragma alloc_text(PAGE, ValidateDriverObjectHasBackingModule)
#        pragma alloc_text(PAGE, GetSystemModuleInformation)
#        pragma alloc_text(PAGE, ValidateDriverObjects)
#        pragma alloc_text(PAGE, HandleValidateDriversIOCTL)
#        pragma alloc_text(PAGE, IsInstructionPointerInInvalidRegion)
#        pragma alloc_text(PAGE, AnalyseNmiData)
#        pragma alloc_text(PAGE, LaunchNonMaskableInterrupt)
#        pragma alloc_text(PAGE, HandleNmiIOCTL)
#        pragma alloc_text(PAGE, ApcRundownRoutine)
#        pragma alloc_text(PAGE, ApcKernelRoutine)
#        pragma alloc_text(PAGE, ApcNormalRoutine)
#        pragma alloc_text(PAGE, FlipKThreadMiscFlagsFlag)
#        pragma alloc_text(PAGE, ValidateThreadsViaKernelApc)
#        pragma alloc_text(PAGE, ValidateThreadViaKernelApcCallback)
#endif

/*
 * This returns a reference to an entry in the system modules array retrieved via
 * GetSystemModuleInformation. It's important to remember we don't free the modules once we retrieve
 * this reference, and instead only free them when we are done using it.
 */
PRTL_MODULE_EXTENDED_INFO
FindSystemModuleByName(_In_ LPCSTR ModuleName, _In_ PSYSTEM_MODULES SystemModules)
{
        PAGED_CODE();

        if (!ModuleName || !SystemModules)
                return NULL;

        for (INT index = 0; index < SystemModules->module_count; index++)
        {
                PRTL_MODULE_EXTENDED_INFO system_module =
                    (PRTL_MODULE_EXTENDED_INFO)((uintptr_t)SystemModules->address +
                                                index * sizeof(RTL_MODULE_EXTENDED_INFO));

                if (strstr(system_module->FullPathName, ModuleName))
                {
                        return system_module;
                }
        }

        return NULL;
}

STATIC
NTSTATUS
PopulateWhitelistedModuleBuffer(_Inout_ PVOID Buffer, _In_ PSYSTEM_MODULES SystemModules)
{
        PAGED_CODE();

        if (!Buffer || !SystemModules)
                return STATUS_INVALID_PARAMETER;

        for (INT index = 0; index < WHITELISTED_MODULE_COUNT; index++)
        {
                LPCSTR name = WHITELISTED_MODULES[index];

                PRTL_MODULE_EXTENDED_INFO module = FindSystemModuleByName(name, SystemModules);

                /* not everyone will contain all whitelisted modules */
                if (!module)
                        continue;

                WHITELISTED_REGIONS region = {0};
                region.base                = (UINT64)module->ImageBase;
                region.end                 = region.base + module->ImageSize;

                RtlCopyMemory((UINT64)Buffer + index * sizeof(WHITELISTED_REGIONS),
                              &region,
                              sizeof(WHITELISTED_REGIONS));
        }

        return STATUS_SUCCESS;
}

STATIC
NTSTATUS
ValidateDriverIOCTLDispatchRegion(_In_ PDRIVER_OBJECT       Driver,
                                  _In_ PSYSTEM_MODULES      Modules,
                                  _In_ PWHITELISTED_REGIONS WhitelistedRegions,
                                  _Out_ PBOOLEAN            Flag)
{
        PAGED_CODE();

        if (!Modules || !Driver || !Flag || !WhitelistedRegions)
                return STATUS_INVALID_PARAMETER;

        UINT64 dispatch_function = 0;
        UINT64 module_base       = 0;
        UINT64 module_end        = 0;

        *Flag = TRUE;

        dispatch_function = Driver->MajorFunction[IRP_MJ_DEVICE_CONTROL];

        if (dispatch_function == NULL)
                return STATUS_SUCCESS;

        for (INT index = 0; index < Modules->module_count; index++)
        {
                PRTL_MODULE_EXTENDED_INFO system_module =
                    (PRTL_MODULE_EXTENDED_INFO)((uintptr_t)Modules->address +
                                                index * sizeof(RTL_MODULE_EXTENDED_INFO));

                if (system_module->ImageBase != Driver->DriverStart)
                        continue;

                /* make sure our driver has a device object which is required for IOCTL */
                if (Driver->DeviceObject == NULL)
                        return STATUS_SUCCESS;

                module_base = (UINT64)system_module->ImageBase;
                module_end  = module_base + system_module->ImageSize;

                /* firstly, check if its inside its own module */
                if (dispatch_function >= module_base && dispatch_function <= module_end)
                        return STATUS_SUCCESS;

                /*
                 * The WDF framework and other low level drivers often hook the dispatch routines
                 * when initiating the respective config of their framework or system. With a bit of
                 * digging you can view the drivers reponsible for the hooks. What this means is
                 * that there will be legit drivers with dispatch routines that point outside of
                 * ntoskrnl and their own memory region. So, I have formed a list which contains the
                 * drivers that perform these hooks and we iteratively check if the dispatch routine
                 * is contained within one of these whitelisted regions. A note on how to imrpove
                 * this is the fact that a code cave can be used inside a whitelisted region which
                 * then jumps to an invalid region such as a manually mapped driver. So in the
                 * future we should implement a function which checks for standard hook
                 * implementations like mov rax jmp rax etc.
                 */
                for (INT index = 0; index < WHITELISTED_MODULE_COUNT; index++)
                {
                        if (dispatch_function >= WhitelistedRegions[index].base &&
                            dispatch_function <= WhitelistedRegions[index].end)
                                return STATUS_SUCCESS;
                }

                DEBUG_WARNING("Driver with invalid dispatch routine found: %s",
                              system_module->FullPathName);

                *Flag = FALSE;
                return STATUS_SUCCESS;
        }

        return STATUS_SUCCESS;
}

STATIC
VOID
InitDriverList(_Inout_ PINVALID_DRIVERS_HEAD ListHead)
{
        PAGED_CODE();

        ListHead->count       = 0;
        ListHead->first_entry = NULL;
}

STATIC
NTSTATUS
AddDriverToList(_Inout_ PINVALID_DRIVERS_HEAD InvalidDriversHead,
                _In_ PDRIVER_OBJECT           Driver,
                _In_ INT                      Reason)
{
        PAGED_CODE();

        PINVALID_DRIVER new_entry = ImpExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(INVALID_DRIVER), INVALID_DRIVER_LIST_ENTRY_POOL);

        if (!new_entry)
                return STATUS_MEMORY_NOT_ALLOCATED;

        new_entry->driver               = Driver;
        new_entry->reason               = Reason;
        new_entry->next                 = InvalidDriversHead->first_entry;
        InvalidDriversHead->first_entry = new_entry;

        return STATUS_SUCCESS;
}

STATIC
VOID
RemoveInvalidDriverFromList(_Inout_ PINVALID_DRIVERS_HEAD InvalidDriversHead)
{
        PAGED_CODE();

        if (InvalidDriversHead->first_entry)
        {
                PINVALID_DRIVER entry           = InvalidDriversHead->first_entry;
                InvalidDriversHead->first_entry = InvalidDriversHead->first_entry->next;
                ImpExFreePoolWithTag(entry, INVALID_DRIVER_LIST_ENTRY_POOL);
        }
}

STATIC
VOID
EnumerateInvalidDrivers(_In_ PINVALID_DRIVERS_HEAD InvalidDriversHead)
{
        PAGED_CODE();

        PINVALID_DRIVER entry = InvalidDriversHead->first_entry;

        while (entry != NULL)
        {
                DEBUG_VERBOSE("Invalid Driver: %wZ", entry->driver->DriverName);
                entry = entry->next;
        }
}

STATIC
NTSTATUS
ValidateDriverObjectHasBackingModule(_In_ PSYSTEM_MODULES ModuleInformation,
                                     _In_ PDRIVER_OBJECT  DriverObject,
                                     _Out_ PBOOLEAN       Result)
{
        PAGED_CODE();

        if (!ModuleInformation || !DriverObject || !Result)
                return STATUS_INVALID_PARAMETER;

        for (INT i = 0; i < ModuleInformation->module_count; i++)
        {
                PRTL_MODULE_EXTENDED_INFO system_module =
                    (PRTL_MODULE_EXTENDED_INFO)((uintptr_t)ModuleInformation->address +
                                                i * sizeof(RTL_MODULE_EXTENDED_INFO));

                if (system_module->ImageSize == 0 || system_module->ImageBase == 0)
                        return STATUS_INVALID_MEMBER;

                if (system_module->ImageBase == DriverObject->DriverStart)
                {
                        *Result = TRUE;
                        return STATUS_SUCCESS;
                }
        }

        DEBUG_WARNING("Driver found with no backing system image at address: %llx",
                      (UINT64)DriverObject->DriverStart);

        *Result = FALSE;
        return STATUS_SUCCESS;
}

// https://imphash.medium.com/windows-process-internals-a-few-concepts-to-know-before-jumping-on-memory-forensics-part-3-4a0e195d947b
NTSTATUS
GetSystemModuleInformation(_Out_ PSYSTEM_MODULES ModuleInformation)
{
        PAGED_CODE();

        if (!ModuleInformation)
                return STATUS_INVALID_PARAMETER;

        ULONG    size   = 0;
        NTSTATUS status = STATUS_UNSUCCESSFUL;

        /*
         * query system module information without an output buffer to get
         * number of bytes required to store all module info structures
         */
        status = RtlQueryModuleInformation(&size, sizeof(RTL_MODULE_EXTENDED_INFO), NULL);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("RtlQueryModuleInformation failed with status %x", status);
                return status;
        }

        /* Allocate a pool equal to the output size of RtlQueryModuleInformation */
        PRTL_MODULE_EXTENDED_INFO driver_information =
            ExAllocatePool2(POOL_FLAG_NON_PAGED, size, SYSTEM_MODULES_POOL);

        if (!driver_information)
        {
                DEBUG_ERROR("Failed to allocate pool LOL");
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        /* Query the modules again this time passing a pointer to the allocated buffer */
        status =
            RtlQueryModuleInformation(&size, sizeof(RTL_MODULE_EXTENDED_INFO), driver_information);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("RtlQueryModuleInformation 2 failed with status %x", status);
                ExFreePoolWithTag(driver_information, SYSTEM_MODULES_POOL);
                return STATUS_ABANDONED;
        }

        ModuleInformation->address      = driver_information;
        ModuleInformation->module_count = size / sizeof(RTL_MODULE_EXTENDED_INFO);

        return status;
}

/* TODO: this function needs to be rewritten. Infact, this entire file needs to be rewritten. */
STATIC
NTSTATUS
ValidateDriverObjects(_In_ PSYSTEM_MODULES          SystemModules,
                      _Inout_ PINVALID_DRIVERS_HEAD InvalidDriverListHead)
{
        PAGED_CODE();

        if (!SystemModules || !InvalidDriverListHead)
                return STATUS_INVALID_PARAMETER;

        HANDLE            handle                     = NULL;
        OBJECT_ATTRIBUTES attributes                 = {0};
        PVOID             directory                  = {0};
        UNICODE_STRING    directory_name             = {0};
        PVOID             whitelisted_regions_buffer = NULL;
        NTSTATUS          status                     = STATUS_UNSUCCESSFUL;
        POBJECT_DIRECTORY directory_object           = NULL;

        ImpRtlInitUnicodeString(&directory_name, L"\\Driver");

        InitializeObjectAttributes(&attributes, &directory_name, OBJ_CASE_INSENSITIVE, NULL, NULL);

        status = ImpZwOpenDirectoryObject(&handle, DIRECTORY_ALL_ACCESS, &attributes);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ZwOpenDirectoryObject failed with status %x", status);
                return status;
        }

        status = ImpObReferenceObjectByHandle(
            handle, DIRECTORY_ALL_ACCESS, NULL, KernelMode, &directory, NULL);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ObReferenceObjectByHandle failed with status %x", status);
                ImpZwClose(handle);
                return status;
        }

        /*
         * Windows organises its drivers in object directories (not the same as
         * files directories). For the driver directory, there are 37 entries,
         * each driver is hashed and indexed. If there is a driver with a duplicate
         * index, it is inserted into same index in a linked list using the
         * _OBJECT_DIRECTORY_ENTRY struct. So to enumerate all drivers we visit
         * each entry in the hashmap, enumerate all objects in the linked list
         * at entry j then we increment the hashmap index i. The motivation behind
         * this is that when a driver is accessed, it is brought to the first index
         * in the linked list, so drivers that are accessed the most can be
         * accessed quickly
         */

        directory_object = (POBJECT_DIRECTORY)directory;

        ImpExAcquirePushLockExclusiveEx(&directory_object->Lock, NULL);

        whitelisted_regions_buffer =
            ImpExAllocatePool2(POOL_FLAG_NON_PAGED,
                               WHITELISTED_MODULE_COUNT * MODULE_MAX_STRING_SIZE,
                               WHITELISTED_MODULE_TAG);

        if (!whitelisted_regions_buffer)
                goto end;

        status = PopulateWhitelistedModuleBuffer(whitelisted_regions_buffer, SystemModules);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("PopulateWhitelistedModuleBuffer failed with status %x", status);
                goto end;
        }

        for (INT index = 0; index < NUMBER_HASH_BUCKETS; index++)
        {
                POBJECT_DIRECTORY_ENTRY entry = directory_object->HashBuckets[index];

                if (!entry)
                        continue;

                POBJECT_DIRECTORY_ENTRY sub_entry = entry;

                while (sub_entry)
                {
                        BOOLEAN        flag           = FALSE;
                        PDRIVER_OBJECT current_driver = sub_entry->Object;

                        /* validate driver has backing module */

                        status = ValidateDriverObjectHasBackingModule(
                            SystemModules, current_driver, &flag);

                        if (!NT_SUCCESS(status))
                        {
                                DEBUG_ERROR(
                                    "ValidateDriverObjectHasBackingModule failed with status %x",
                                    status);
                                goto end;
                        }

                        if (!flag)
                        {
                                status = AddDriverToList(InvalidDriverListHead,
                                                         current_driver,
                                                         REASON_NO_BACKING_MODULE);

                                if (!NT_SUCCESS(status))
                                        DEBUG_ERROR("AddDriverToList failed with status %x",
                                                    status);
                                else
                                        InvalidDriverListHead->count += 1;
                        }

                        /* validate drivers IOCTL dispatch routines */

                        status = ValidateDriverIOCTLDispatchRegion(
                            current_driver, SystemModules, whitelisted_regions_buffer, &flag);

                        if (!NT_SUCCESS(status))
                        {
                                DEBUG_ERROR(
                                    "ValidateDriverIOCTLDispatchRegion failed with status %x",
                                    status);
                                goto end;
                        }

                        if (!flag)
                        {
                                status = AddDriverToList(InvalidDriverListHead,
                                                         current_driver,
                                                         REASON_INVALID_IOCTL_DISPATCH);

                                if (!NT_SUCCESS(status))
                                        DEBUG_ERROR("AddDriverToList failed with status %x",
                                                    status);
                                else
                                        InvalidDriverListHead->count += 1;
                        }

                        sub_entry = sub_entry->ChainLink;
                }
        }

end:
        if (whitelisted_regions_buffer)
                ImpExFreePoolWithTag(whitelisted_regions_buffer, WHITELISTED_MODULE_TAG);

        ImpExReleasePushLockExclusiveEx(&directory_object->Lock, 0);
        ImpObDereferenceObject(directory);
        ImpZwClose(handle);

        return STATUS_SUCCESS;
}

NTSTATUS
HandleValidateDriversIOCTL()
{
        PAGED_CODE();

        NTSTATUS                         status         = STATUS_UNSUCCESSFUL;
        ULONG                            buffer_size    = 0;
        SYSTEM_MODULES                   system_modules = {0};
        MODULE_VALIDATION_FAILURE_HEADER header         = {0};
        PINVALID_DRIVERS_HEAD            head           = NULL;

        /* Fix annoying visual studio linting error */
        RtlZeroMemory(&system_modules, sizeof(SYSTEM_MODULES));

        status = GetSystemModuleInformation(&system_modules);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("GetSystemModuleInformation failed with status %x", status);
                return status;
        }

        head = ImpExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(INVALID_DRIVERS_HEAD), INVALID_DRIVER_LIST_HEAD_POOL);

        if (!head)
        {
                ImpExFreePoolWithTag(system_modules.address, SYSTEM_MODULES_POOL);
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        /*
         * Use a linked list here so that so we have easy access to the invalid drivers
         * which we can then use to copy the drivers logic for further analysis in
         * identifying drivers specifically used for the purpose of cheating
         */

        InitDriverList(head);

        status = ValidateDriverObjects(&system_modules, head);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ValidateDriverObjects failed with status %x", status);
                goto end;
        }

        header.module_count = head->count >= MODULE_VALIDATION_FAILURE_MAX_REPORT_COUNT
                                  ? MODULE_VALIDATION_FAILURE_MAX_REPORT_COUNT
                                  : head->count;

        if (head->count > 0)
        {
                DEBUG_VERBOSE("System has an invalid driver count of: %i", head->count);

                for (INT index = 0; index < head->count; index++)
                {
                        /* make sure we free any non reported modules */
                        if (index >= MODULE_VALIDATION_FAILURE_MAX_REPORT_COUNT)
                        {
                                RemoveInvalidDriverFromList(head);
                                continue;
                        }

                        PMODULE_VALIDATION_FAILURE report =
                            ImpExAllocatePool2(POOL_FLAG_NON_PAGED,
                                               sizeof(MODULE_VALIDATION_FAILURE),
                                               POOL_TAG_INTEGRITY);

                        if (!report)
                                continue;

                        report->report_code         = REPORT_MODULE_VALIDATION_FAILURE;
                        report->report_type         = head->first_entry->reason;
                        report->driver_base_address = head->first_entry->driver->DriverStart;
                        report->driver_size         = head->first_entry->driver->DriverSize;

                        ANSI_STRING string   = {0};
                        string.Length        = 0;
                        string.MaximumLength = MODULE_REPORT_DRIVER_NAME_BUFFER_SIZE;
                        string.Buffer        = &report->driver_name;

                        status = ImpRtlUnicodeStringToAnsiString(
                            &string, &head->first_entry->driver->DriverName, FALSE);

                        /* still continue if we fail to get the driver name */
                        if (!NT_SUCCESS(status))
                                DEBUG_ERROR("RtlUnicodeStringToAnsiString failed with status %x",
                                            status);

                        status = IrpQueueCompleteIrp(report, sizeof(MODULE_VALIDATION_FAILURE));

                        if (!NT_SUCCESS(status))
                        {
                                DEBUG_ERROR("IrpQueueCompleteIrp failed with status %x", status);
                                continue;
                        }

                        RemoveInvalidDriverFromList(head);
                }
        }
        else
        {
                DEBUG_INFO("Found no invalid drivers on the system.");
        }

end:
        ImpExFreePoolWithTag(head, INVALID_DRIVER_LIST_HEAD_POOL);
        ImpExFreePoolWithTag(system_modules.address, SYSTEM_MODULES_POOL);

        return status;
}

/*
 * TODO: this probably doesnt need to return an NTSTATUS, we can just return a boolean and remove
 * the out variable.
 */
NTSTATUS
IsInstructionPointerInInvalidRegion(_In_ UINT64          RIP,
                                    _In_ PSYSTEM_MODULES SystemModules,
                                    _Out_ PBOOLEAN       Result)
{
        PAGED_CODE();

        if (!RIP || !SystemModules || !Result)
                return STATUS_INVALID_PARAMETER;

        /* Note that this does not check for HAL or PatchGuard Execution */
        for (INT i = 0; i < SystemModules->module_count; i++)
        {
                PRTL_MODULE_EXTENDED_INFO system_module =
                    (PRTL_MODULE_EXTENDED_INFO)((uintptr_t)SystemModules->address +
                                                i * sizeof(RTL_MODULE_EXTENDED_INFO));

                UINT64 base = (UINT64)system_module->ImageBase;
                UINT64 end  = base + system_module->ImageSize;

                if (RIP >= base && RIP <= end)
                {
                        *Result = TRUE;
                        return STATUS_SUCCESS;
                }
        }

        *Result = FALSE;
        return STATUS_SUCCESS;
}

NTSTATUS
IsInstructionPointerInsideModule(_In_ UINT64                    Rip,
                                 _In_ PRTL_MODULE_EXTENDED_INFO Module,
                                 _Out_ PBOOLEAN                 Result)
{
        PAGED_CODE();

        if (!Rip || !Module || !Result)
                return STATUS_INVALID_PARAMETER;

        UINT64 base = (UINT64)Module->ImageBase;
        UINT64 end  = base + Module->ImageSize;

        if (Rip >= base && Rip <= end)
        {
                *Result = TRUE;
                return STATUS_SUCCESS;
        }

        *Result = FALSE;
        return STATUS_SUCCESS;
}

/*
 * todo: i think we should split this function up into each analysis i.e one for the interrupted
 * rip, one for the cid etc.
 */
STATIC
NTSTATUS
AnalyseNmiData(_In_ PNMI_CONTEXT NmiContext, _In_ PSYSTEM_MODULES SystemModules)
{
        PAGED_CODE();

        NTSTATUS status = STATUS_UNSUCCESSFUL;
        BOOLEAN  flag   = FALSE;

        if (!NmiContext || !SystemModules)
                return STATUS_INVALID_PARAMETER;

        for (INT core = 0; core < ImpKeQueryActiveProcessorCount(0); core++)
        {
                /* Make sure our NMIs were run  */
                if (!NmiContext[core].callback_count)
                {
                        PNMI_CALLBACK_FAILURE report = ImpExAllocatePool2(
                            POOL_FLAG_NON_PAGED, sizeof(NMI_CALLBACK_FAILURE), REPORT_POOL_TAG);

                        if (!report)
                                return STATUS_INSUFFICIENT_RESOURCES;

                        report->report_code        = REPORT_NMI_CALLBACK_FAILURE;
                        report->kthread_address    = NULL;
                        report->invalid_rip        = NULL;
                        report->were_nmis_disabled = TRUE;

                        status = IrpQueueCompleteIrp(report, sizeof(NMI_CALLBACK_FAILURE));

                        if (!NT_SUCCESS(status))
                        {
                                DEBUG_ERROR("IrpQueueCompleteIrp failed with status %x", status);
                                return status;
                        }

                        return STATUS_SUCCESS;
                }

                DEBUG_VERBOSE("Analysing Nmi Data for: cpu number: %i callback count: %lx",
                              core,
                              NmiContext[core].callback_count);

                /*
                 * Our NMI callback allows us to interrupt every running thread on each core. Now it
                 * is common practice for malicious programs to either unlink their thread from the
                 * KTHREAD linked list or remove their threads entry from the PspCidTable or both.
                 * Now the reason an unlinked thread can still be scheduled is because the scheduler
                 * keeps a seperate list that it uses to schedule threads. It then places these
                 * threads in the KPRCB in either the CurrentThread, IdleThread or NextThread.
                 *
                 * Since you can't just set a threads affinity to enumerate over all cores and read
                 * the KPCRB->CurrentThread (since it will just show your thread) we have to
                 * interrupt the thread. So below we are validating that the thread is indeed in our
                 * own threads list using our callback routine and then using PsGetThreadId
                 *
                 * I also want to integrate a way to SAFELY determine whether a thread has been
                 * removed from the KTHREADs linked list, maybe PsGetNextProcess ?
                 */

                if (!ValidateThreadsPspCidTableEntry(NmiContext[core].kthread))
                {
                        DEBUG_WARNING("Thread: %llx was not found in the pspcid table.",
                                      NmiContext[core].kthread);

                        PHIDDEN_SYSTEM_THREAD_REPORT report =
                            ImpExAllocatePool2(POOL_FLAG_NON_PAGED,
                                               sizeof(HIDDEN_SYSTEM_THREAD_REPORT),
                                               REPORT_POOL_TAG);

                        if (!report)
                                continue;

                        report->report_code          = REPORT_HIDDEN_SYSTEM_THREAD;
                        report->found_in_kthreadlist = FALSE; // wip
                        report->found_in_pspcidtable = FALSE;
                        report->thread_id            = ImpPsGetThreadId(NmiContext[core].kthread);
                        report->thread_address       = NmiContext[core].kthread;

                        RtlCopyMemory(
                            report->thread, NmiContext[core].kthread, sizeof(report->thread));

                        if (!NT_SUCCESS(
                                IrpQueueCompleteIrp(report, sizeof(HIDDEN_SYSTEM_THREAD_REPORT))))
                        {
                                DEBUG_ERROR("IrpQueueCompleteIrp failed with no status.");
                                continue;
                        }
                }
                else
                {
                        DEBUG_VERBOSE("Thread: %llx was found in PspCidTable",
                                      NmiContext[core].kthread);
                }

                if (NmiContext[core].user_thread)
                        continue;

                status = IsInstructionPointerInInvalidRegion(
                    NmiContext[core].interrupted_rip, SystemModules, &flag);

                if (!NT_SUCCESS(status))
                {
                        DEBUG_ERROR("IsInstructionPointerInInvalidRegion failed with status %x",
                                    status);
                        continue;
                }

                if (!flag)
                {
                        PNMI_CALLBACK_FAILURE report =
                            ImpExAllocatePool2(POOL_FLAG_NON_PAGED,
                                               sizeof(HIDDEN_SYSTEM_THREAD_REPORT),
                                               REPORT_POOL_TAG);

                        report->report_code        = REPORT_NMI_CALLBACK_FAILURE;
                        report->kthread_address    = NmiContext[core].kthread;
                        report->invalid_rip        = NmiContext[core].interrupted_rip;
                        report->were_nmis_disabled = FALSE;

                        status = IrpQueueCompleteIrp(report, sizeof(HIDDEN_SYSTEM_THREAD_REPORT));

                        if (!NT_SUCCESS(status))
                        {
                                DEBUG_ERROR("IrpQueueCompleteIrp failed with status %x", status);
                                return status;
                        }

                        return STATUS_SUCCESS;
                }
        }

        return STATUS_SUCCESS;
}

STATIC
BOOLEAN
NmiCallback(_Inout_opt_ PVOID Context, _In_ BOOLEAN Handled)
{
        UNREFERENCED_PARAMETER(Handled);

        PNMI_CONTEXT           nmi_context   = (PNMI_CONTEXT)Context;
        ULONG                  proc_num      = KeGetCurrentProcessorNumber();
        UINT64                 kpcr          = 0;
        TASK_STATE_SEGMENT_64* tss           = NULL;
        PMACHINE_FRAME         machine_frame = NULL;

        /*
         * To find the IRETQ frame (MACHINE_FRAME) we need to find the top of the NMI ISR stack.
         * This is stored at TSS->Ist[3]. To find the TSS, we can read it from KPCR->TSS_BASE. Once
         * we have our TSS, we can read the value at TSS->Ist[3] which points to the top of the ISR
         * stack, and subtract the size of the MACHINE_FRAME struct. Allowing us read the
         * interrupted RIP.
         *
         * The reason this is needed is because RtlCaptureStackBackTrace is not safe to run
         * at IRQL = HIGH_LEVEL, hence we need to manually unwind the ISR stack to find the
         * interrupted rip.
         */
        kpcr          = __readmsr(IA32_GS_BASE);
        tss           = *(TASK_STATE_SEGMENT_64**)(kpcr + KPCR_TSS_BASE_OFFSET);
        machine_frame = tss->Ist3 - sizeof(MACHINE_FRAME);

        if (machine_frame->rip <= WINDOWS_USERMODE_MAX_ADDRESS)
                nmi_context[proc_num].user_thread = TRUE;

        nmi_context[proc_num].interrupted_rip = machine_frame->rip;
        nmi_context[proc_num].interrupted_rsp = machine_frame->rsp;
        nmi_context[proc_num].kthread         = PsGetCurrentThread();
        nmi_context[proc_num].callback_count += 1;

        DEBUG_VERBOSE(
            "[NMI CALLBACK]: Core Number: %lx, Interrupted RIP: %llx, Interrupted RSP: %llx",
            proc_num,
            machine_frame->rip,
            machine_frame->rsp);

        return TRUE;
}

#define NMI_DELAY_TIME 200 * 10000

STATIC
NTSTATUS
LaunchNonMaskableInterrupt()
{
        PAGED_CODE();

        PKAFFINITY_EX ProcAffinityPool =
            ImpExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAFFINITY_EX), PROC_AFFINITY_POOL);

        if (!ProcAffinityPool)
                return STATUS_MEMORY_NOT_ALLOCATED;

        LARGE_INTEGER delay = {0};
        delay.QuadPart -= NMI_DELAY_TIME;

        for (ULONG core = 0; core < ImpKeQueryActiveProcessorCount(0); core++)
        {
                ImpKeInitializeAffinityEx(ProcAffinityPool);
                ImpKeAddProcessorAffinityEx(ProcAffinityPool, core);

                DEBUG_VERBOSE("Sending NMI");
                HalSendNMI(ProcAffinityPool);

                /*
                 * Only a single NMI can be active at any given time, so arbitrarily
                 * delay execution  to allow time for the NMI to be processed
                 */
                ImpKeDelayExecutionThread(KernelMode, FALSE, &delay);
        }

        ImpExFreePoolWithTag(ProcAffinityPool, PROC_AFFINITY_POOL);

        return STATUS_SUCCESS;
}

NTSTATUS
HandleNmiIOCTL()
{
        PAGED_CODE();

        NTSTATUS       status          = STATUS_UNSUCCESSFUL;
        PVOID          callback_handle = NULL;
        SYSTEM_MODULES system_modules  = {0};
        PNMI_CONTEXT   nmi_context     = NULL;

        if (IsNmiInProgress())
                return STATUS_ALREADY_COMMITTED;

        status = ValidateHalDispatchTables();

        /* do we continue ? probably. */
        if (!NT_SUCCESS(status))
                DEBUG_ERROR("ValidateHalDispatchTables failed with status %x", status);

        nmi_context = ImpExAllocatePool2(POOL_FLAG_NON_PAGED,
                                         ImpKeQueryActiveProcessorCount(0) * sizeof(NMI_CONTEXT),
                                         NMI_CONTEXT_POOL);

        if (!nmi_context)
        {
                UnsetNmiInProgressFlag();
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        /*
         * We want to register and unregister our callback each time so it becomes harder
         * for people to hook our callback and get up to some funny business
         */
        callback_handle = ImpKeRegisterNmiCallback(NmiCallback, nmi_context);

        if (!callback_handle)
        {
                DEBUG_ERROR("KeRegisterNmiCallback failed with no status.");
                ImpExFreePoolWithTag(nmi_context, NMI_CONTEXT_POOL);
                UnsetNmiInProgressFlag();
                return STATUS_UNSUCCESSFUL;
        }

        /*
         * We query the system modules each time since they can potentially
         * change at any time
         */
        status = GetSystemModuleInformation(&system_modules);

        if (!NT_SUCCESS(status))
        {
                ImpKeDeregisterNmiCallback(callback_handle);
                ImpExFreePoolWithTag(nmi_context, NMI_CONTEXT_POOL);
                DEBUG_ERROR("Error retriving system module information");
                UnsetNmiInProgressFlag();
                return status;
        }

        status = LaunchNonMaskableInterrupt();

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("Error running NMI callbacks");
                ImpKeDeregisterNmiCallback(callback_handle);
                ImpExFreePoolWithTag(system_modules.address, SYSTEM_MODULES_POOL);
                ImpExFreePoolWithTag(nmi_context, NMI_CONTEXT_POOL);
                UnsetNmiInProgressFlag();
                return status;
        }

        status = AnalyseNmiData(nmi_context, &system_modules);

        if (!NT_SUCCESS(status))
                DEBUG_ERROR("Error analysing nmi data");

        ImpExFreePoolWithTag(system_modules.address, SYSTEM_MODULES_POOL);
        ImpExFreePoolWithTag(nmi_context, NMI_CONTEXT_POOL);
        ImpKeDeregisterNmiCallback(callback_handle);

        UnsetNmiInProgressFlag();
        return status;
}

/*
 * The RundownRoutine is executed if the thread terminates before the APC was delivered to
 * user mode.
 */
STATIC
VOID
ApcRundownRoutine(_In_ PRKAPC Apc)
{
        PAGED_CODE();

        FreeApcAndDecrementApcCount(Apc, APC_CONTEXT_ID_STACKWALK);
}

/*
 * The KernelRoutine is executed in kernel mode at APC_LEVEL before the APC is delivered.
 * This is also where we want to free our APC object.
 */
STATIC
VOID
ApcKernelRoutine(_In_ PRKAPC                                     Apc,
                 _Inout_ _Deref_pre_maybenull_ PKNORMAL_ROUTINE* NormalRoutine,
                 _Inout_ _Deref_pre_maybenull_ PVOID*            NormalContext,
                 _Inout_ _Deref_pre_maybenull_ PVOID*            SystemArgument1,
                 _Inout_ _Deref_pre_maybenull_ PVOID*            SystemArgument2)
{
        PAGED_CODE();

        NTSTATUS               status            = STATUS_UNSUCCESSFUL;
        PVOID                  buffer            = NULL;
        INT                    frames_captured   = 0;
        UINT64                 stack_frame       = 0;
        BOOLEAN                flag              = FALSE;
        PAPC_STACKWALK_CONTEXT context           = NULL;
        PTHREAD_LIST_ENTRY     thread_list_entry = NULL;

        context = (PAPC_STACKWALK_CONTEXT)Apc->NormalContext;

        FindThreadListEntryByThreadAddress(KeGetCurrentThread(), &thread_list_entry);

        if (!thread_list_entry)
                return;

        buffer = ImpExAllocatePool2(POOL_FLAG_NON_PAGED, STACK_FRAME_POOL_SIZE, POOL_TAG_APC);

        if (!buffer)
                goto free;

        frames_captured =
            ImpRtlCaptureStackBackTrace(NULL, STACK_FRAME_POOL_SIZE / sizeof(UINT64), buffer, NULL);

        if (!frames_captured)
                goto free;

        for (INT index = 0; index < frames_captured; index++)
        {
                stack_frame = *(UINT64*)((UINT64)buffer + index * sizeof(UINT64));

                /*
                 * Apc->NormalContext holds the address of our context data structure that
                 * we passed into KeInitializeApc as the last argument.
                 */
                status = IsInstructionPointerInInvalidRegion(stack_frame, context->modules, &flag);

                if (!NT_SUCCESS(status))
                {
                        DEBUG_ERROR("IsInstructionPointerInInvalidRegion failed with status %x",
                                    status);
                        goto free;
                }

                if (flag == FALSE)
                {
                        PAPC_STACKWALK_REPORT report = ImpExAllocatePool2(
                            POOL_FLAG_NON_PAGED, sizeof(APC_STACKWALK_REPORT), REPORT_POOL_TAG);

                        if (!report)
                                goto free;

                        report->report_code     = REPORT_APC_STACKWALK;
                        report->kthread_address = (UINT64)KeGetCurrentThread();
                        report->invalid_rip     = stack_frame;

                        if (!NT_SUCCESS(IrpQueueCompleteIrp(report, sizeof(APC_STACKWALK_REPORT))))
                        {
                                DEBUG_ERROR("IrpQueueCompleteIrp failed with no status.");
                                continue;
                        }
                }
        }

free:

        if (buffer)
                ImpExFreePoolWithTag(buffer, POOL_TAG_APC);

        FreeApcAndDecrementApcCount(Apc, APC_CONTEXT_ID_STACKWALK);

        thread_list_entry->apc        = NULL;
        thread_list_entry->apc_queued = FALSE;
}

/*
 * The NormalRoutine is executed in user mode when the APC is delivered.
 */
STATIC
VOID
ApcNormalRoutine(_In_opt_ PVOID NormalContext,
                 _In_opt_ PVOID SystemArgument1,
                 _In_opt_ PVOID SystemArgument2)
{
        PAGED_CODE();
}

#define THREAD_STATE_TERMINATED 4
#define THREAD_STATE_WAIT       5
#define THREAD_STATE_INIT       0

STATIC
VOID
ValidateThreadViaKernelApcCallback(_In_ PTHREAD_LIST_ENTRY ThreadListEntry,
                                   _Inout_opt_ PVOID       Context)
{
        PAGED_CODE();

        PKAPC                  apc           = NULL;
        BOOLEAN                apc_status    = FALSE;
        PLONG                  flags         = NULL;
        PCHAR                  previous_mode = NULL;
        PUCHAR                 state         = NULL;
        BOOLEAN                apc_queueable = FALSE;
        LPCSTR                 process_name  = NULL;
        PAPC_STACKWALK_CONTEXT context       = (PAPC_STACKWALK_CONTEXT)Context;

        process_name = ImpPsGetProcessImageFileName(ThreadListEntry->owning_process);

        /*
         * Its possible to set the KThread->ApcQueueable flag to false ensuring that no APCs
         * can be queued to the thread, as KeInsertQueueApc will check this flag before
         * queueing an APC so lets make sure we flip this before before queueing ours. Since
         * we filter out any system threads this should be fine... c:
         */
        flags         = (PLONG)((UINT64)ThreadListEntry->thread + KTHREAD_MISC_FLAGS_OFFSET);
        previous_mode = (PCHAR)((UINT64)ThreadListEntry->thread + KTHREAD_PREVIOUS_MODE_OFFSET);
        state         = (PUCHAR)((UINT64)ThreadListEntry->thread + KTHREAD_STATE_OFFSET);

        /*
         * For now, lets only check for system threads. However, we also want to check for threads
         * executing in kernel mode, i.e KTHREAD->PreviousMode == UserMode.
         */
        if (ThreadListEntry->owning_process != PsInitialSystemProcess)
                return;

        if (ThreadListEntry->thread == KeGetCurrentThread() || !ThreadListEntry->thread)
                return;

        DEBUG_VERBOSE("Validating thread: %llx, process name: %s via kernel APC stackwalk.",
                      ThreadListEntry->thread,
                      process_name);

        SetFlag(*flags, KTHREAD_MISC_FLAGS_ALERTABLE);
        SetFlag(*flags, KTHREAD_MISC_FLAGS_APC_QUEUEABLE);

        apc = (PKAPC)ImpExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), POOL_TAG_APC);

        if (!apc)
                return;

        ImpKeInitializeApc(apc,
                           ThreadListEntry->thread,
                           OriginalApcEnvironment,
                           ApcKernelRoutine,
                           ApcRundownRoutine,
                           ApcNormalRoutine,
                           KernelMode,
                           Context);

        apc_status = ImpKeInsertQueueApc(apc, NULL, NULL, IO_NO_INCREMENT);

        if (!apc_status)
        {
                DEBUG_ERROR("KeInsertQueueApc failed with no status.");
                ImpExFreePoolWithTag(apc, POOL_TAG_APC);
                return;
        }

        ThreadListEntry->apc        = apc;
        ThreadListEntry->apc_queued = TRUE;

        IncrementApcCount(APC_CONTEXT_ID_STACKWALK);
}

/*
 * Since NMIs are only executed on the thread that is running on each logical core, it makes
 * sense to make use of APCs that, while can be masked off, provide us to easily issue a
 * callback routine to threads we want a stack trace of. Hence by utilising both APCs and
 * NMIs we get excellent coverage of the entire system.
 */
NTSTATUS
ValidateThreadsViaKernelApc()
{
        PAGED_CODE();

        NTSTATUS               status  = STATUS_UNSUCCESSFUL;
        PAPC_STACKWALK_CONTEXT context = NULL;

        /* First, ensure we dont already have an ongoing operation */
        GetApcContext(&context, APC_CONTEXT_ID_STACKWALK);

        if (context)
        {
                DEBUG_WARNING("Existing APC_STACKWALK operation already in progress.");
                return STATUS_SUCCESS;
        }

        context =
            ImpExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(APC_STACKWALK_CONTEXT), POOL_TAG_APC);

        if (!context)
                return STATUS_MEMORY_NOT_ALLOCATED;

        context->header.context_id = APC_CONTEXT_ID_STACKWALK;
        context->modules =
            ImpExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(SYSTEM_MODULES), POOL_TAG_APC);

        if (!context->modules)
        {
                ImpExFreePoolWithTag(context, POOL_TAG_APC);
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        status = GetSystemModuleInformation(context->modules);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("GetSystemModuleInformation failed with status %x", status);
                ImpExFreePoolWithTag(context->modules, POOL_TAG_APC);
                ImpExFreePoolWithTag(context, POOL_TAG_APC);
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        InsertApcContext(context);

        context->header.allocation_in_progress = TRUE;
        EnumerateThreadListWithCallbackRoutine(ValidateThreadViaKernelApcCallback, context);
        context->header.allocation_in_progress = FALSE;

        return status;
}

VOID
FreeApcStackwalkApcContextInformation(_Inout_ PAPC_STACKWALK_CONTEXT Context)
{
        if (Context->modules->address)
                ImpExFreePoolWithTag(Context->modules->address, SYSTEM_MODULES_POOL);

        if (Context->modules)
                ImpExFreePoolWithTag(Context->modules, POOL_TAG_APC);
}

#define DPC_STACKWALK_STACKFRAME_COUNT 10

/* the first 3 frames are isr handlers which we dont care about */
#define DPC_STACKWALK_FRAMES_TO_SKIP 3

typedef struct _DPC_CONTEXT
{
        UINT64           stack_frame[DPC_STACKWALK_STACKFRAME_COUNT];
        UINT16           frames_captured;
        volatile BOOLEAN executed;

} DPC_CONTEXT, *PDPC_CONTEXT;

VOID
DpcStackwalkCallbackRoutine(_In_ PKDPC     Dpc,
                            _In_opt_ PVOID DeferredContext,
                            _In_opt_ PVOID SystemArgument1,
                            _In_opt_ PVOID SystemArgument2)
{
        PDPC_CONTEXT context = &((PDPC_CONTEXT)DeferredContext)[KeGetCurrentProcessorNumber()];

        context->frames_captured = ImpRtlCaptureStackBackTrace(DPC_STACKWALK_FRAMES_TO_SKIP,
                                                               DPC_STACKWALK_STACKFRAME_COUNT,
                                                               &context->stack_frame,
                                                               NULL);
        InterlockedExchange(&context->executed, TRUE);
        ImpKeSignalCallDpcDone(SystemArgument1);

        DEBUG_VERBOSE("Executed DPC on core: %lx, with %lx frames captured.",
                      KeGetCurrentProcessorNumber(),
                      context->frames_captured);
}

STATIC
BOOLEAN
CheckForDpcCompletion(_In_ PDPC_CONTEXT Context)
{
        for (UINT32 index = 0; index < ImpKeQueryActiveProcessorCount(0); index++)
        {
                if (!InterlockedExchange(&Context[index].executed, Context[index].executed))
                        return FALSE;
        }

        return TRUE;
}

STATIC
NTSTATUS
ValidateDpcCapturedStack(_In_ PSYSTEM_MODULES Modules, _In_ PDPC_CONTEXT Context)
{
        NTSTATUS              status = STATUS_UNSUCCESSFUL;
        BOOLEAN               flag   = FALSE;
        PDPC_STACKWALK_REPORT report = NULL;

        for (UINT32 core = 0; core < ImpKeQueryActiveProcessorCount(0); core++)
        {
                for (UINT32 frame = 0; frame < Context[core].frames_captured; frame++)
                {
                        status = IsInstructionPointerInInvalidRegion(
                            Context[core].stack_frame[frame], Modules, &flag);

                        if (!NT_SUCCESS(status))
                        {
                                DEBUG_ERROR(
                                    "IsInstructionPointerInInvalidRegion failed with status %x",
                                    status);
                                continue;
                        }

                        if (!flag)
                        {
                                report = ImpExAllocatePool2(POOL_FLAG_NON_PAGED,
                                                            sizeof(DPC_STACKWALK_REPORT),
                                                            REPORT_POOL_TAG);

                                if (!report)
                                        continue;

                                report->report_code     = REPORT_DPC_STACKWALK;
                                report->kthread_address = PsGetCurrentThread();
                                report->invalid_rip     = Context[core].stack_frame[frame];

                                // RtlCopyMemory(report->driver,
                                //               (UINT64)Context[core].stack_frame[frame] - 0x50,
                                //               APC_STACKWALK_BUFFER_SIZE);

                                if (!NT_SUCCESS(
                                        IrpQueueCompleteIrp(report, sizeof(DPC_STACKWALK_REPORT))))
                                {
                                        DEBUG_ERROR("IrpQueueCompleteIrp failed with no status.");
                                        continue;
                                }
                        }
                }
        }

        return status;
}

/*
 * Lets use DPCs as another form of stackwalking rather then inter-process interrupts
 * because DPCs run at IRQL = DISPATCH_LEVEL, allowing us to use functions such as
 * RtlCaptureStackBackTrace whereas IPIs run at IRQL = IPI_LEVEL. DPCs are also harder
 * to mask compared to APCs which can be masked with the flip of a bit in the KTHREAD
 * structure.
 */
NTSTATUS
DispatchStackwalkToEachCpuViaDpc()
{
        NTSTATUS       status  = STATUS_UNSUCCESSFUL;
        PDPC_CONTEXT   context = NULL;
        SYSTEM_MODULES modules = {0};

        context = ImpExAllocatePool2(POOL_FLAG_NON_PAGED,
                                     ImpKeQueryActiveProcessorCount(0) * sizeof(DPC_CONTEXT),
                                     POOL_TAG_DPC);

        if (!context)
                return STATUS_MEMORY_NOT_ALLOCATED;

        status = GetSystemModuleInformation(&modules);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("GetSystemModuleInformation failed with status %x", status);
                goto end;
        }

        /* KeGenericCallDpc will queue a DPC to each processor with importance =
         * HighImportance. This means our DPC will be inserted into the front of the DPC
         * queue and executed immediately.*/
        ImpKeGenericCallDpc(DpcStackwalkCallbackRoutine, context);

        while (!CheckForDpcCompletion(context))
                YieldProcessor();

        status = ValidateDpcCapturedStack(&modules, context);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ValidateDpcCapturedStack failed with status %x", status);
                goto end;
        }

        DEBUG_VERBOSE("Finished validating cores via dpc");
end:

        if (modules.address)
                ImpExFreePoolWithTag(modules.address, SYSTEM_MODULES_POOL);
        if (context)
                ImpExFreePoolWithTag(context, POOL_TAG_DPC);

        return status;
}

/* todo: walk the chain of pointers to prevent jmp chaining */
STATIC
NTSTATUS
ValidateTableDispatchRoutines(_In_ PVOID*          Base,
                              _In_ UINT32          Entries,
                              _In_ PSYSTEM_MODULES Modules,
                              _Out_ PVOID*         Routine)
{
        NTSTATUS status = STATUS_UNSUCCESSFUL;
        BOOLEAN  flag   = FALSE;

        for (UINT32 index = 0; index < Entries; index++)
        {
                if (!Base[index])
                        continue;

                status = IsInstructionPointerInInvalidRegion(Base[index], Modules, &flag);

                if (!NT_SUCCESS(status))
                {
                        DEBUG_ERROR("IsInstructionPointerInInvalidRegion failed with status %x",
                                    status);
                        continue;
                }

                if (!flag)
                        *Routine = Base[index];
        }

        return status;
}

/*
 * windows version info: https://www.techthoughts.info/windows-version-numbers/
 *
 * sizes:
 * https://www.vergiliusproject.com/kernels/x64/Windows%2011/22H2%20(2022%20Update)/HAL_PRIVATE_DISPATCH
 */
#define HAL_PRIVATE_DISPATCH_W11_22H2_SIZE 0x4f0
#define HAL_PRIVATE_DISPATCH_W10_22H2_SIZE 0x4b0

#define WINDOWS_10_MAX_BUILD_NUMBER 19045

STATIC
UINT32
GetHalPrivateDispatchTableRoutineCount(_In_ PRTL_OSVERSIONINFOW VersionInfo)
{
        if (VersionInfo->dwBuildNumber <= WINDOWS_10_MAX_BUILD_NUMBER)
                return (HAL_PRIVATE_DISPATCH_W10_22H2_SIZE / sizeof(UINT64)) - 1;
        else
                return (HAL_PRIVATE_DISPATCH_W11_22H2_SIZE / sizeof(UINT64)) - 1;
}

STATIC
NTSTATUS
ValidateHalPrivateDispatchTable(_Out_ PVOID* Routine, _In_ PSYSTEM_MODULES Modules)
{
        NTSTATUS           status  = STATUS_UNSUCCESSFUL;
        PVOID              table   = NULL;
        UNICODE_STRING     string  = RTL_CONSTANT_STRING(L"HalPrivateDispatchTable");
        PVOID*             base    = NULL;
        RTL_OSVERSIONINFOW os_info = {0};
        UINT32             count   = 0;

        DEBUG_VERBOSE("Validating HalPrivateDispatchTable.");

        table = ImpMmGetSystemRoutineAddress(&string);

        if (!table)
                return status;

        status = GetOsVersionInformation(&os_info);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("GetOsVersionInformation failed with status %x", status);
                return status;
        }

        base  = (UINT64)table + sizeof(UINT64);
        count = GetHalPrivateDispatchTableRoutineCount(&os_info);

        status = ValidateTableDispatchRoutines(base, count, Modules, Routine);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ValidateTableDispatchRoutines failed with status %x", status);
                return status;
        }

        return status;
}

STATIC
NTSTATUS
ValidateHalDispatchTable(_Out_ PVOID* Routine, _In_ PSYSTEM_MODULES Modules)
{
        NTSTATUS status = STATUS_UNSUCCESSFUL;
        BOOLEAN  flag   = FALSE;

        *Routine = NULL;

        DEBUG_VERBOSE("Validating HalDispatchTable.");

        /*
         * Since windows exports all the function pointers inside the HalDispatchTable, we may
         * aswell make use of them and validate it this way. While it definitely is ugly, it is the
         * safest way to do it.
         *
         * What if there are 2 invalid routines? hmm.. tink.
         */
        status = IsInstructionPointerInInvalidRegion(HalQuerySystemInformation, Modules, &flag);

        if (!flag && NT_SUCCESS(status))
                *Routine = HalQuerySystemInformation;
        else
                return status;

        status = IsInstructionPointerInInvalidRegion(HalSetSystemInformation, Modules, &flag);

        if (!flag && NT_SUCCESS(status))
                *Routine = HalSetSystemInformation;
        else
                return status;

        status = IsInstructionPointerInInvalidRegion(HalQueryBusSlots, Modules, &flag);

        if (!flag && NT_SUCCESS(status))
                *Routine = HalQueryBusSlots;
        else
                return status;

        status = IsInstructionPointerInInvalidRegion(HalReferenceHandlerForBus, Modules, &flag);

        if (!flag && NT_SUCCESS(status))
                *Routine = HalReferenceHandlerForBus;
        else
                return status;

        status = IsInstructionPointerInInvalidRegion(HalReferenceBusHandler, Modules, &flag);

        if (!flag && NT_SUCCESS(status))
                *Routine = HalReferenceBusHandler;
        else
                return status;

        status = IsInstructionPointerInInvalidRegion(HalDereferenceBusHandler, Modules, &flag);

        if (!flag && NT_SUCCESS(status))
                *Routine = HalDereferenceBusHandler;
        else
                return status;

        status = IsInstructionPointerInInvalidRegion(HalInitPnpDriver, Modules, &flag);

        if (!flag && NT_SUCCESS(status))
                *Routine = HalInitPnpDriver;
        else
                return status;

        status = IsInstructionPointerInInvalidRegion(HalInitPowerManagement, Modules, &flag);

        if (!flag && NT_SUCCESS(status))
                *Routine = HalInitPowerManagement;
        else
                return status;

        status = IsInstructionPointerInInvalidRegion(HalGetDmaAdapter, Modules, &flag);

        if (!flag && NT_SUCCESS(status))
                *Routine = HalGetDmaAdapter;
        else
                return status;

        status = IsInstructionPointerInInvalidRegion(HalGetInterruptTranslator, Modules, &flag);

        if (!flag && NT_SUCCESS(status))
                *Routine = HalGetInterruptTranslator;
        else
                return status;

        status = IsInstructionPointerInInvalidRegion(HalStartMirroring, Modules, &flag);

        if (!flag && NT_SUCCESS(status))
                *Routine = HalStartMirroring;
        else
                return status;

        status = IsInstructionPointerInInvalidRegion(HalEndMirroring, Modules, &flag);

        if (!flag && NT_SUCCESS(status))
                *Routine = HalEndMirroring;
        else
                return status;

        status = IsInstructionPointerInInvalidRegion(HalMirrorPhysicalMemory, Modules, &flag);

        if (!flag && NT_SUCCESS(status))
                *Routine = HalMirrorPhysicalMemory;
        else
                return status;

        status = IsInstructionPointerInInvalidRegion(HalEndOfBoot, Modules, &flag);

        if (!flag && NT_SUCCESS(status))
                *Routine = HalEndOfBoot;
        else
                return status;

        status = IsInstructionPointerInInvalidRegion(HalMirrorVerify, Modules, &flag);

        if (!flag && NT_SUCCESS(status))
                *Routine = HalMirrorVerify;
        else
                return status;

        status = IsInstructionPointerInInvalidRegion(HalGetCachedAcpiTable, Modules, &flag);

        if (!flag && NT_SUCCESS(status))
                *Routine = HalGetCachedAcpiTable;
        else
                return status;

        status = IsInstructionPointerInInvalidRegion(HalSetPciErrorHandlerCallback, Modules, &flag);

        if (!flag && NT_SUCCESS(status))
                *Routine = HalSetPciErrorHandlerCallback;
        else
                return status;

        status = IsInstructionPointerInInvalidRegion(HalGetPrmCache, Modules, &flag);

        if (!flag && NT_SUCCESS(status))
                *Routine = HalGetPrmCache;

        return status;
}

STATIC
VOID
ReportDataTableInvalidRoutine(_In_ TABLE_ID TableId, _In_ UINT64 Address)
{
        PDATA_TABLE_ROUTINE_REPORT report = ImpExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(DATA_TABLE_ROUTINE_REPORT), REPORT_POOL_TAG);

        if (!report)
                return;

        DEBUG_WARNING(
            "Invalid data table routine found. Table: %lx, Address: %llx", TableId, Address);

        report->address = Address;
        report->id      = TableId;
        report->id      = REPORT_DATA_TABLE_ROUTINE;
        RtlCopyMemory(report->routine, Address, DATA_TABLE_ROUTINE_BUF_SIZE);

        if (!NT_SUCCESS(IrpQueueCompleteIrp(report, sizeof(DATA_TABLE_ROUTINE_REPORT))))
                DEBUG_ERROR("IrpQueueCompleteIrp failed with no status.");
}

NTSTATUS
ValidateHalDispatchTables()
{
        NTSTATUS       status   = STATUS_UNSUCCESSFUL;
        SYSTEM_MODULES modules  = {0};
        PVOID          routine1 = NULL;
        PVOID          routine2 = NULL;

        status = GetSystemModuleInformation(&modules);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("GetSystemModuleInformation failed with status %x", status);
                return status;
        }

        status = ValidateHalDispatchTable(&routine1, &modules);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ValidateHalDispatchTable failed with status %x", status);
                goto end;
        }

        if (routine1)
                ReportDataTableInvalidRoutine(HalDispatch, routine1);
        else
                DEBUG_VERBOSE("HalDispatch dispatch routines are valid.");

        status = ValidateHalPrivateDispatchTable(&routine2, &modules);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ValidateHalPrivateDispatchTable failed with status %x", status);
                goto end;
        }

        if (routine2)
                ReportDataTableInvalidRoutine(HalPrivateDispatch, routine2);
        else
                DEBUG_VERBOSE("HalPrivateDispatch dispatch routines are valid.");

end:
        if (modules.address)
                ImpExFreePoolWithTag(modules.address, SYSTEM_MODULES_POOL);

        return status;
}

NTSTATUS
GetDriverObjectByDriverName(_In_ PUNICODE_STRING DriverName, _Out_ PDRIVER_OBJECT* DriverObject)
{
        HANDLE            handle           = NULL;
        OBJECT_ATTRIBUTES attributes       = {0};
        PVOID             directory        = {0};
        UNICODE_STRING    directory_name   = {0};
        NTSTATUS          status           = STATUS_UNSUCCESSFUL;
        POBJECT_DIRECTORY directory_object = NULL;

        *DriverObject = NULL;

        ImpRtlInitUnicodeString(&directory_name, L"\\Driver");

        InitializeObjectAttributes(&attributes, &directory_name, OBJ_CASE_INSENSITIVE, NULL, NULL);

        status = ImpZwOpenDirectoryObject(&handle, DIRECTORY_ALL_ACCESS, &attributes);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ZwOpenDirectoryObject failed with status %x", status);
                return status;
        }

        status = ImpObReferenceObjectByHandle(
            handle, DIRECTORY_ALL_ACCESS, NULL, KernelMode, &directory, NULL);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ObReferenceObjectByHandle failed with status %x", status);
                ImpZwClose(handle);
                return status;
        }

        directory_object = (POBJECT_DIRECTORY)directory;

        ImpExAcquirePushLockExclusiveEx(&directory_object->Lock, NULL);

        for (INT index = 0; index < NUMBER_HASH_BUCKETS; index++)
        {
                POBJECT_DIRECTORY_ENTRY entry = directory_object->HashBuckets[index];

                if (!entry)
                        continue;

                POBJECT_DIRECTORY_ENTRY sub_entry = entry;

                while (sub_entry)
                {
                        PDRIVER_OBJECT current_driver = sub_entry->Object;

                        if (!RtlCompareUnicodeString(
                                DriverName, &current_driver->DriverName, FALSE))
                        {
                                *DriverObject = current_driver;
                                goto end;
                        }

                        sub_entry = sub_entry->ChainLink;
                }
        }

end:
        ImpExReleasePushLockExclusiveEx(&directory_object->Lock, 0);
        ImpObDereferenceObject(directory);
        ImpZwClose(handle);
        return STATUS_SUCCESS;
}