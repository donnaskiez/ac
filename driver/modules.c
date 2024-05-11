#include "modules.h"

#include "callbacks.h"
#include "driver.h"
#include "io.h"
#include "ia32.h"
#include "imports.h"
#include "apc.h"
#include "thread.h"
#include "pe.h"
#include "crypt.h"

#define WHITELISTED_MODULE_TAG 'whte'

#define NMI_DELAY 200 * 10000

#define WHITELISTED_MODULE_COUNT 11
#define MODULE_MAX_STRING_SIZE   256

#define NTOSKRNL 0
#define CLASSPNP 1
#define WDF01000 2

/*
 * The modules seen in the array below have been seen to commonly hook other
 * drivers' IOCTL dispatch routines. Its possible to see this by using
 * WinObjEx64 and checking which module each individual dispatch routine lies
 * in. These modules are then addded to the list (in addition to either the
 * driver itself or ntoskrnl) which is seen as a valid region for a drivers
 * dispatch routine to lie within.
 */
CHAR WHITELISTED_MODULES[WHITELISTED_MODULE_COUNT][MODULE_MAX_STRING_SIZE] = {
    "ntoskrnl.exe",
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

#define SYSTEM_IDLE_PROCESS_ID 0
#define SYSTEM_PROCESS_ID      4
#define SVCHOST_PROCESS_ID     8

typedef struct _WHITELISTED_REGIONS {
    UINT64 base;
    UINT64 end;

} WHITELISTED_REGIONS, *PWHITELISTED_REGIONS;

typedef struct _NMI_POOLS {
    PVOID thread_data_pool;
    PVOID stack_frames;
    PVOID nmi_context;

} NMI_POOLS, *PNMI_POOLS;

typedef struct _MODULE_VALIDATION_FAILURE_HEADER {
    INT module_count;

} MODULE_VALIDATION_FAILURE_HEADER, *PMODULE_VALIDATION_FAILURE_HEADER;

typedef struct _NMI_CONTEXT {
    UINT64  interrupted_rip;
    UINT64  interrupted_rsp;
    UINT64  kthread;
    UINT32  callback_count;
    BOOLEAN user_thread;

} NMI_CONTEXT, *PNMI_CONTEXT;

STATIC
VOID
PopulateWhitelistedModuleBuffer(_Inout_ PWHITELISTED_REGIONS Whitelist,
                                _In_ PSYSTEM_MODULES         SystemModules);

STATIC
NTSTATUS
ValidateDriverObjectsWrapper(_In_ PSYSTEM_MODULES SystemModules);

STATIC
NTSTATUS
AnalyseNmiData(_In_ PNMI_CONTEXT    NmiContext,
               _In_ PSYSTEM_MODULES SystemModules);

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
                 _Inout_ _Deref_pre_maybenull_ PVOID* SystemArgument1,
                 _Inout_ _Deref_pre_maybenull_ PVOID* SystemArgument2);

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
#    pragma alloc_text(PAGE, FindSystemModuleByName)
#    pragma alloc_text(PAGE, PopulateWhitelistedModuleBuffer)
#    pragma alloc_text(PAGE, GetSystemModuleInformation)
#    pragma alloc_text(PAGE, ValidateDriverObjectsWrapper)
#    pragma alloc_text(PAGE, HandleValidateDriversIOCTL)
#    pragma alloc_text(PAGE, IsInstructionPointerInInvalidRegion)
#    pragma alloc_text(PAGE, AnalyseNmiData)
#    pragma alloc_text(PAGE, LaunchNonMaskableInterrupt)
#    pragma alloc_text(PAGE, HandleNmiIOCTL)
#    pragma alloc_text(PAGE, ApcRundownRoutine)
#    pragma alloc_text(PAGE, ApcKernelRoutine)
#    pragma alloc_text(PAGE, ApcNormalRoutine)
#    pragma alloc_text(PAGE, ValidateThreadsViaKernelApc)
#    pragma alloc_text(PAGE, ValidateThreadViaKernelApcCallback)
#endif

/*
 * This returns a reference to an entry in the system modules array retrieved
 * via GetSystemModuleInformation. It's important to remember we don't free the
 * modules once we retrieve this reference, and instead only free them when we
 * are done using it.
 */
PRTL_MODULE_EXTENDED_INFO
FindSystemModuleByName(_In_ LPCSTR          ModuleName,
                       _In_ PSYSTEM_MODULES SystemModules)
{
    PAGED_CODE();

    if (!ModuleName || !SystemModules)
        return NULL;

    PRTL_MODULE_EXTENDED_INFO modules =
        (PRTL_MODULE_EXTENDED_INFO)SystemModules->address;

    for (INT index = 0; index < SystemModules->module_count; index++) {
        if (strstr(modules[index].FullPathName, ModuleName)) {
            return &modules[index];
        }
    }

    return NULL;
}

STATIC
VOID
PopulateWhitelistedModuleBuffer(_Inout_ PWHITELISTED_REGIONS Whitelist,
                                _In_ PSYSTEM_MODULES         SystemModules)
{
    PAGED_CODE();

    for (INT index = 0; index < WHITELISTED_MODULE_COUNT; index++) {
        LPCSTR entry = WHITELISTED_MODULES[index];

        PRTL_MODULE_EXTENDED_INFO module =
            FindSystemModuleByName(entry, SystemModules);

        /* not everyone will contain all whitelisted modules */
        if (!module)
            continue;

        PWHITELISTED_REGIONS region = &Whitelist[index];
        region->base                = (UINT64)module->ImageBase;
        region->end = (UINT64)module->ImageBase + module->ImageSize;
    }
}

STATIC
UINT64
GetDriverMajorDispatchFunction(_In_ PDRIVER_OBJECT Driver)
{
    return Driver->MajorFunction[IRP_MJ_DEVICE_CONTROL];
}

STATIC
BOOLEAN
DoesDriverHaveInvalidDispatchRoutine(_In_ PDRIVER_OBJECT       Driver,
                                     _In_ PSYSTEM_MODULES      Modules,
                                     _In_ PWHITELISTED_REGIONS Regions)
{
    PAGED_CODE();

    UINT64 dispatch_function = 0;
    UINT64 module_base       = 0;
    UINT64 module_end        = 0;

    dispatch_function = GetDriverMajorDispatchFunction(Driver);

    if (dispatch_function == NULL)
        return FALSE;

    PRTL_MODULE_EXTENDED_INFO module =
        (PRTL_MODULE_EXTENDED_INFO)Modules->address;

    for (INT index = 0; index < Modules->module_count; index++) {
        if (module[index].ImageBase != Driver->DriverStart)
            continue;

        /* make sure our driver has a device object which is required
         * for IOCTL */
        if (Driver->DeviceObject == NULL)
            return FALSE;

        module_base = (UINT64)module[index].ImageBase;
        module_end  = module_base + module[index].ImageSize;

        /* firstly, check if its inside its own module */
        if (dispatch_function >= module_base && dispatch_function <= module_end)
            return FALSE;

        /*
         * The WDF framework and other low level drivers often hook the
         * dispatch routines when initiating the respective config of
         * their framework or system. With a bit of digging you can view
         * the drivers reponsible for the hooks. What this means is that
         * there will be legit drivers with dispatch routines that point
         * outside of ntoskrnl and their own memory region. So, I have
         * formed a list which contains the drivers that perform these
         * hooks and we iteratively check if the dispatch routine is
         * contained within one of these whitelisted regions. A note on
         * how to imrpove this is the fact that a code cave can be used
         * inside a whitelisted region which then jumps to an invalid
         * region such as a manually mapped driver. So in the future we
         * should implement a function which checks for standard hook
         * implementations like mov rax jmp rax etc.
         */
        for (UINT32 index = 0; index < WHITELISTED_MODULE_COUNT; index++) {
            if (dispatch_function >= Regions[index].base &&
                dispatch_function <= Regions[index].end)
                return FALSE;
        }

        DEBUG_WARNING("Driver with invalid dispatch routine found: %s",
                      module[index].FullPathName);

        return TRUE;
    }

    return FALSE;
}

STATIC
BOOLEAN
DoesDriverObjectHaveBackingModule(_In_ PSYSTEM_MODULES ModuleInformation,
                                  _In_ PDRIVER_OBJECT  DriverObject)
{
    PAGED_CODE();

    PRTL_MODULE_EXTENDED_INFO module =
        (PRTL_MODULE_EXTENDED_INFO)ModuleInformation->address;

    for (INT index = 0; index < ModuleInformation->module_count; index++) {
        if (module[index].ImageSize == 0 || module[index].ImageBase == 0)
            return STATUS_INVALID_MEMBER;

        if (module[index].ImageBase == DriverObject->DriverStart) {
            return TRUE;
        }
    }

    DEBUG_WARNING("Driver found with no backing system image at address: %llx",
                  (UINT64)DriverObject->DriverStart);

    return FALSE;
}

FORCEINLINE
STATIC
VOID
InitSystemModulesStructure(_Out_ PSYSTEM_MODULES Modules,
                           _In_ PVOID            Buffer,
                           _In_ INT              Count)
{
    Modules->address      = Buffer;
    Modules->module_count = Count;
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

    status = RtlQueryModuleInformation(
        &size, sizeof(RTL_MODULE_EXTENDED_INFO), NULL);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("RtlQueryModuleInformation failed with status %x", status);
        return status;
    }

    PRTL_MODULE_EXTENDED_INFO buffer =
        ExAllocatePool2(POOL_FLAG_NON_PAGED, size, SYSTEM_MODULES_POOL);

    if (!buffer) {
        DEBUG_ERROR("Failed to allocate pool LOL");
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    status = RtlQueryModuleInformation(
        &size, sizeof(RTL_MODULE_EXTENDED_INFO), buffer);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("RtlQueryModuleInformation 2 failed with status %x",
                    status);
        ExFreePoolWithTag(buffer, SYSTEM_MODULES_POOL);
        return STATUS_ABANDONED;
    }

    InitSystemModulesStructure(
        ModuleInformation, buffer, size / sizeof(RTL_MODULE_EXTENDED_INFO));

    return status;
}

STATIC
VOID
ReportInvalidDriverObject(_In_ PDRIVER_OBJECT Driver, _In_ UINT32 ReportSubType)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UINT32   packet_size =
        CryptRequestRequiredBufferLength(sizeof(MODULE_VALIDATION_FAILURE));

    PMODULE_VALIDATION_FAILURE report = ImpExAllocatePool2(
        POOL_FLAG_NON_PAGED, packet_size, POOL_TAG_INTEGRITY);

    if (!report)
        return;

    INIT_REPORT_PACKET(report, REPORT_MODULE_VALIDATION_FAILURE, ReportSubType);

    report->driver_base_address = Driver->DriverStart;
    report->driver_size         = Driver->DriverSize;

    ANSI_STRING string   = {0};
    string.Length        = 0;
    string.MaximumLength = MODULE_REPORT_DRIVER_NAME_BUFFER_SIZE;
    string.Buffer        = &report->driver_name;

    /* Continue regardless of result */
    ImpRtlUnicodeStringToAnsiString(&string, &Driver->DriverName, FALSE);

    status = CryptEncryptBuffer(report, packet_size);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("CryptEncryptBuffer: %lx", status);
        ImpExFreePoolWithTag(report, REPORT_POOL_TAG);
        return;
    }

    IrpQueueCompletePacket(report, packet_size);
}

FORCEINLINE
STATIC
POBJECT_DIRECTORY_ENTRY
GetNextObject(_In_ POBJECT_DIRECTORY_ENTRY Entry)
{
    return Entry->ChainLink;
}

STATIC
VOID
ValidateDriverObjects(_In_ PSYSTEM_MODULES         Modules,
                      _In_ POBJECT_DIRECTORY_ENTRY Entry,
                      _In_ PWHITELISTED_REGIONS    Whitelist)
{
    NTSTATUS                status = STATUS_UNSUCCESSFUL;
    POBJECT_DIRECTORY_ENTRY entry  = Entry;

    while (entry) {
        PDRIVER_OBJECT driver = entry->Object;

        if (!DoesDriverObjectHaveBackingModule(Modules, driver)) {
            ReportInvalidDriverObject(driver, REPORT_SUBTYPE_NO_BACKING_MODULE);
        }

        if (DoesDriverHaveInvalidDispatchRoutine(driver, Modules, Whitelist)) {
            ReportInvalidDriverObject(driver, REPORT_SUBTYPE_INVALID_DISPATCH);
        }

        entry = GetNextObject(entry);
    }
}

/* TODO: this function needs to be rewritten. Infact, this entire file needs to
 * be rewritten.
 * god this is so bad.
 */
STATIC
NTSTATUS
ValidateDriverObjectsWrapper(_In_ PSYSTEM_MODULES SystemModules)
{
    PAGED_CODE();

    HANDLE               handle           = NULL;
    OBJECT_ATTRIBUTES    attributes       = {0};
    PVOID                directory        = {0};
    UNICODE_STRING       directory_name   = {0};
    PWHITELISTED_REGIONS whitelist        = NULL;
    NTSTATUS             status           = STATUS_UNSUCCESSFUL;
    POBJECT_DIRECTORY    directory_object = NULL;

    ImpRtlInitUnicodeString(&directory_name, L"\\Driver");

    InitializeObjectAttributes(
        &attributes, &directory_name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status =
        ImpZwOpenDirectoryObject(&handle, DIRECTORY_ALL_ACCESS, &attributes);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ZwOpenDirectoryObject failed with status %x", status);
        return status;
    }

    status = ImpObReferenceObjectByHandle(
        handle, DIRECTORY_ALL_ACCESS, NULL, KernelMode, &directory, NULL);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ObReferenceObjectByHandle failed with status %x", status);
        ImpZwClose(handle);
        return status;
    }

    /*
     * Windows organises its drivers in object directories (not the same as
     * files directories). For the driver directory, there are 37 entries,
     * each driver is hashed and indexed. If there is a driver with a
     * duplicate index, it is inserted into same index in a linked list
     * using the _OBJECT_DIRECTORY_ENTRY struct. So to enumerate all drivers
     * we visit each entry in the hashmap, enumerate all objects in the
     * linked list at entry j then we increment the hashmap index i. The
     * motivation behind this is that when a driver is accessed, it is
     * brought to the first index in the linked list, so drivers that are
     * accessed the most can be accessed quickly
     */

    directory_object = (POBJECT_DIRECTORY)directory;

    ImpExAcquirePushLockExclusiveEx(&directory_object->Lock, NULL);

    whitelist = ImpExAllocatePool2(POOL_FLAG_NON_PAGED,
                                   WHITELISTED_MODULE_COUNT *
                                       sizeof(WHITELISTED_REGIONS),
                                   WHITELISTED_MODULE_TAG);

    if (!whitelist)
        goto end;

    PopulateWhitelistedModuleBuffer(whitelist, SystemModules);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("PopulateWhitelistedModuleBuffer failed with status %x",
                    status);
        goto end;
    }

    for (INT index = 0; index < NUMBER_HASH_BUCKETS; index++) {
        POBJECT_DIRECTORY_ENTRY entry = directory_object->HashBuckets[index];
        ValidateDriverObjects(SystemModules, entry, whitelist);
    }

end:
    if (whitelist)
        ImpExFreePoolWithTag(whitelist, WHITELISTED_MODULE_TAG);

    ImpExReleasePushLockExclusiveEx(&directory_object->Lock, 0);
    ImpObDereferenceObject(directory);
    ImpZwClose(handle);

    return STATUS_SUCCESS;
}

NTSTATUS
HandleValidateDriversIOCTL()
{
    PAGED_CODE();

    NTSTATUS       status         = STATUS_UNSUCCESSFUL;
    ULONG          buffer_size    = 0;
    SYSTEM_MODULES system_modules = {0};

    /* Fix annoying visual studio linting error */
    RtlZeroMemory(&system_modules, sizeof(SYSTEM_MODULES));

    status = GetSystemModuleInformation(&system_modules);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("GetSystemModuleInformation failed with status %x", status);
        return status;
    }

    status = ValidateDriverObjectsWrapper(&system_modules);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ValidateDriverObjects failed with status %x", status);
        goto end;
    }

end:

    ImpExFreePoolWithTag(system_modules.address, SYSTEM_MODULES_POOL);
    return status;
}

/*
 * TODO: this probably doesnt need to return an NTSTATUS, we can just return a
 * boolean and remove the out variable.
 */
BOOLEAN
IsInstructionPointerInInvalidRegion(_In_ UINT64          RIP,
                                    _In_ PSYSTEM_MODULES SystemModules)
{
    PAGED_CODE();

    PRTL_MODULE_EXTENDED_INFO modules =
        (PRTL_MODULE_EXTENDED_INFO)SystemModules->address;

    /* Note that this does not check for HAL or PatchGuard Execution */
    for (INT index = 0; index < SystemModules->module_count; index++) {
        UINT64 base = (UINT64)modules[index].ImageBase;
        UINT64 end  = base + modules[index].ImageSize;

        if (RIP >= base && RIP <= end) {
            return FALSE;
        }
    }

    return TRUE;
}

BOOLEAN
IsInstructionPointerInsideSpecifiedModule(_In_ UINT64                    Rip,
                                          _In_ PRTL_MODULE_EXTENDED_INFO Module)
{
    UINT64 base = (UINT64)Module->ImageBase;
    UINT64 end  = base + Module->ImageSize;

    if (Rip >= base && Rip <= end)
        return TRUE;

    return FALSE;
}

STATIC
VOID
ReportNmiBlocking()
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UINT32   packet_size =
        CryptRequestRequiredBufferLength(sizeof(NMI_CALLBACK_FAILURE));

    PNMI_CALLBACK_FAILURE report =
        ImpExAllocatePool2(POOL_FLAG_NON_PAGED, packet_size, REPORT_POOL_TAG);

    if (!report)
        return STATUS_INSUFFICIENT_RESOURCES;

    INIT_REPORT_PACKET(report, REPORT_NMI_CALLBACK_FAILURE, 0);

    report->kthread_address    = NULL;
    report->invalid_rip        = NULL;
    report->were_nmis_disabled = TRUE;

    status = CryptEncryptBuffer(report, packet_size);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("CryptEncryptBuffer: %lx", status);
        ImpExFreePoolWithTag(report, REPORT_POOL_TAG);
        return;
    }

    IrpQueueCompletePacket(report, packet_size);
}

STATIC
VOID
ReportMissingCidTableEntry(_In_ PNMI_CONTEXT Context)
{
    DEBUG_WARNING("Thread: %llx was not found in the pspcid table.",
                  Context->kthread);

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UINT32   packet_size =
        CryptRequestRequiredBufferLength(sizeof(HIDDEN_SYSTEM_THREAD_REPORT));

    PHIDDEN_SYSTEM_THREAD_REPORT report =
        ImpExAllocatePool2(POOL_FLAG_NON_PAGED, packet_size, REPORT_POOL_TAG);

    if (!report)
        return;

    INIT_REPORT_PACKET(report, REPORT_HIDDEN_SYSTEM_THREAD, 0);

    report->found_in_kthreadlist = FALSE; // wip
    report->found_in_pspcidtable = FALSE;
    report->thread_id            = ImpPsGetThreadId(Context->kthread);
    report->thread_address       = Context->kthread;

    RtlCopyMemory(report->thread, Context->kthread, sizeof(report->thread));

    status = CryptEncryptBuffer(report, packet_size);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("CryptEncryptBuffer: %lx", status);
        ImpExFreePoolWithTag(report, REPORT_POOL_TAG);
        return;
    }

    IrpQueueCompletePacket(report, packet_size);
}

STATIC
VOID
ReportInvalidRipFoundDuringNmi(_In_ PNMI_CONTEXT Context)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UINT32   packet_size =
        CryptRequestRequiredBufferLength(sizeof(HIDDEN_SYSTEM_THREAD_REPORT));

    PNMI_CALLBACK_FAILURE report =
        ImpExAllocatePool2(POOL_FLAG_NON_PAGED, packet_size, REPORT_POOL_TAG);

    if (!report)
        return;

    INIT_REPORT_PACKET(report, REPORT_NMI_CALLBACK_FAILURE, 0);

    report->kthread_address    = Context->kthread;
    report->invalid_rip        = Context->interrupted_rip;
    report->were_nmis_disabled = FALSE;

    status = CryptEncryptBuffer(report, packet_size);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("CryptEncryptBuffer: %lx", status);
        ImpExFreePoolWithTag(report, REPORT_POOL_TAG);
        return;
    }

    IrpQueueCompletePacket(report, packet_size);
}

/*
 * todo: i think we should split this function up into each analysis i.e one for
 * the interrupted rip, one for the cid etc.
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

    for (INT core = 0; core < ImpKeQueryActiveProcessorCount(0); core++) {
        /* Make sure our NMIs were run  */
        if (!NmiContext[core].callback_count) {
            ReportNmiBlocking();
            return STATUS_SUCCESS;
        }

        DEBUG_VERBOSE(
            "Analysing Nmi Data for: cpu number: %i callback count: %lx",
            core,
            NmiContext[core].callback_count);

        /*
         * Our NMI callback allows us to interrupt every running thread
         * on each core. Now it is common practice for malicious
         * programs to either unlink their thread from the KTHREAD
         * linked list or remove their threads entry from the
         * PspCidTable or both. Now the reason an unlinked thread can
         * still be scheduled is because the scheduler keeps a seperate
         * list that it uses to schedule threads. It then places these
         * threads in the KPRCB in either the CurrentThread, IdleThread
         * or NextThread.
         *
         * Since you can't just set a threads affinity to enumerate over
         * all cores and read the KPCRB->CurrentThread (since it will
         * just show your thread) we have to interrupt the thread. So
         * below we are validating that the thread is indeed in our own
         * threads list using our callback routine and then using
         * PsGetThreadId
         *
         * I also want to integrate a way to SAFELY determine whether a
         * thread has been removed from the KTHREADs linked list, maybe
         * PsGetNextProcess ?
         */

        if (!DoesThreadHaveValidCidEntry(NmiContext[core].kthread)) {
            ReportMissingCidTableEntry(&NmiContext[core]);
        }

        if (NmiContext[core].user_thread)
            continue;

        if (IsInstructionPointerInInvalidRegion(
                NmiContext[core].interrupted_rip, SystemModules))
            ReportInvalidRipFoundDuringNmi(&NmiContext[core]);
    }

    return STATUS_SUCCESS;
}

FORCEINLINE
STATIC
TASK_STATE_SEGMENT_64*
GetTaskStateSegment(_In_ UINT64 Kpcr)
{
    return *(TASK_STATE_SEGMENT_64**)(Kpcr + KPCR_TSS_BASE_OFFSET);
}

FORCEINLINE
STATIC
PMACHINE_FRAME
GetIsrMachineFrame(_In_ TASK_STATE_SEGMENT_64* TaskStateSegment)
{
    return TaskStateSegment->Ist3 - sizeof(MACHINE_FRAME);
}

FORCEINLINE
STATIC
BOOLEAN
IsUserModeAddress(_In_ UINT64 Rip)
{
    return Rip <= WINDOWS_USERMODE_MAX_ADDRESS ? TRUE : FALSE;
}

STATIC BOOLEAN
NmiCallback(_Inout_opt_ PVOID Context, _In_ BOOLEAN Handled)
{
    UNREFERENCED_PARAMETER(Handled);

    ULONG                  core          = KeGetCurrentProcessorNumber();
    PNMI_CONTEXT           context       = &((PNMI_CONTEXT)Context)[core];
    UINT64                 kpcr          = 0;
    TASK_STATE_SEGMENT_64* tss           = NULL;
    PMACHINE_FRAME         machine_frame = NULL;

    if (!ARGUMENT_PRESENT(Context))
        return TRUE;

    /*
     * To find the IRETQ frame (MACHINE_FRAME) we need to find the top of
     * the NMI ISR stack. This is stored at TSS->Ist[3]. To find the TSS, we
     * can read it from KPCR->TSS_BASE. Once we have our TSS, we can read
     * the value at TSS->Ist[3] which points to the top of the ISR stack,
     * and subtract the size of the MACHINE_FRAME struct. Allowing us read
     * the interrupted RIP.
     *
     * The reason this is needed is because RtlCaptureStackBackTrace is not
     * safe to run at IRQL = HIGH_LEVEL, hence we need to manually unwind
     * the ISR stack to find the interrupted rip.
     */
    kpcr          = __readmsr(IA32_GS_BASE);
    tss           = GetTaskStateSegment(kpcr);
    machine_frame = GetIsrMachineFrame(tss);

    if (IsUserModeAddress(machine_frame->rip))
        context->user_thread = TRUE;

    context->interrupted_rip = machine_frame->rip;
    context->interrupted_rsp = machine_frame->rsp;
    context->kthread         = PsGetCurrentThread();
    context->callback_count++;

    DEBUG_VERBOSE(
        "[NMI CALLBACK]: Core Number: %lx, Interrupted RIP: %llx, Interrupted RSP: %llx",
        core,
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

    PKAFFINITY_EX affinity = ImpExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(KAFFINITY_EX), PROC_AFFINITY_POOL);

    if (!affinity)
        return STATUS_MEMORY_NOT_ALLOCATED;

    LARGE_INTEGER delay = {0};
    delay.QuadPart -= NMI_DELAY_TIME;

    for (ULONG core = 0; core < ImpKeQueryActiveProcessorCount(0); core++) {
        ImpKeInitializeAffinityEx(affinity);
        ImpKeAddProcessorAffinityEx(affinity, core);

        HalSendNMI(affinity);

        /*
         * Only a single NMI can be active at any given time, so
         * arbitrarily delay execution  to allow time for the NMI to be
         * processed
         */
        ImpKeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    ImpExFreePoolWithTag(affinity, PROC_AFFINITY_POOL);
    return STATUS_SUCCESS;
}

NTSTATUS
HandleNmiIOCTL()
{
    PAGED_CODE();

    NTSTATUS       status  = STATUS_UNSUCCESSFUL;
    PVOID          handle  = NULL;
    SYSTEM_MODULES modules = {0};
    PNMI_CONTEXT   context = NULL;

    UINT32 size = ImpKeQueryActiveProcessorCount(0) * sizeof(NMI_CONTEXT);

    if (IsNmiInProgress())
        return STATUS_ALREADY_COMMITTED;

    status = ValidateHalDispatchTables();

    /* do we continue ? probably. */
    if (!NT_SUCCESS(status))
        DEBUG_ERROR("ValidateHalDispatchTables failed with status %x", status);

    context = ImpExAllocatePool2(POOL_FLAG_NON_PAGED, size, NMI_CONTEXT_POOL);

    if (!context) {
        UnsetNmiInProgressFlag();
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    /*
     * We want to register and unregister our callback each time so it
     * becomes harder for people to hook our callback and get up to some
     * funny business
     */
    handle = ImpKeRegisterNmiCallback(NmiCallback, context);

    if (!handle) {
        DEBUG_ERROR("KeRegisterNmiCallback failed with no status.");
        goto end;
    }

    /*
     * We query the system modules each time since they can potentially
     * change at any time
     */
    status = GetSystemModuleInformation(&modules);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("Error retriving system module information");
        goto end;
    }

    status = LaunchNonMaskableInterrupt();

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("Error running NMI callbacks");
        goto end;
    }

    status = AnalyseNmiData(context, &modules);

    if (!NT_SUCCESS(status))
        DEBUG_ERROR("Error analysing nmi data");

end:

    if (modules.address)
        ImpExFreePoolWithTag(modules.address, SYSTEM_MODULES_POOL);

    if (context)
        ImpExFreePoolWithTag(context, NMI_CONTEXT_POOL);

    if (handle)
        ImpKeDeregisterNmiCallback(handle);

    UnsetNmiInProgressFlag();
    return status;
}

/*
 * The RundownRoutine is executed if the thread terminates before the APC was
 * delivered to user mode.
 */
STATIC
VOID
ApcRundownRoutine(_In_ PRKAPC Apc)
{
    PAGED_CODE();
    FreeApcAndDecrementApcCount(Apc, APC_CONTEXT_ID_STACKWALK);
}

STATIC
VOID
ReportApcStackwalkViolation(_In_ UINT64 Rip)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UINT32   packet_size =
        CryptRequestRequiredBufferLength(sizeof(APC_STACKWALK_REPORT));

    PAPC_STACKWALK_REPORT report =
        ImpExAllocatePool2(POOL_FLAG_NON_PAGED, packet_size, REPORT_POOL_TAG);

    if (!report)
        return;

    INIT_REPORT_PACKET(report, REPORT_APC_STACKWALK, 0);

    report->kthread_address = (UINT64)KeGetCurrentThread();
    report->invalid_rip     = Rip;
    // report->driver ?? todo!

    status = CryptEncryptBuffer(report, packet_size);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("CryptEncryptBuffer: %lx", status);
        ImpExFreePoolWithTag(report, REPORT_POOL_TAG);
        return;
    }

    IrpQueueCompletePacket(report, packet_size);
}

/*
 * The KernelRoutine is executed in kernel mode at APC_LEVEL before the APC is
 * delivered. This is also where we want to free our APC object.
 */
STATIC
VOID
ApcKernelRoutine(_In_ PRKAPC                                     Apc,
                 _Inout_ _Deref_pre_maybenull_ PKNORMAL_ROUTINE* NormalRoutine,
                 _Inout_ _Deref_pre_maybenull_ PVOID*            NormalContext,
                 _Inout_ _Deref_pre_maybenull_ PVOID* SystemArgument1,
                 _Inout_ _Deref_pre_maybenull_ PVOID* SystemArgument2)
{
    PAGED_CODE();

    NTSTATUS               status            = STATUS_UNSUCCESSFUL;
    PVOID                  buffer            = NULL;
    INT                    frames_captured   = 0;
    PUINT64                frames            = 0;
    BOOLEAN                flag              = FALSE;
    PAPC_STACKWALK_CONTEXT context           = NULL;
    PTHREAD_LIST_ENTRY     thread_list_entry = NULL;

    context = (PAPC_STACKWALK_CONTEXT)Apc->NormalContext;

    FindThreadListEntryByThreadAddress(KeGetCurrentThread(),
                                       &thread_list_entry);

    if (!thread_list_entry)
        return;

    buffer = ImpExAllocatePool2(
        POOL_FLAG_NON_PAGED, STACK_FRAME_POOL_SIZE, POOL_TAG_APC);

    if (!buffer)
        goto free;

    frames_captured = ImpRtlCaptureStackBackTrace(
        NULL, STACK_FRAME_POOL_SIZE / sizeof(UINT64), buffer, NULL);

    if (!frames_captured)
        goto free;

    for (INT index = 0; index < frames_captured; index++) {
        frames = (PUINT64)buffer;

        /*
         * Apc->NormalContext holds the address of our context data
         * structure that we passed into KeInitializeApc as the last
         * argument.
         */
        if (IsInstructionPointerInInvalidRegion(frames[index],
                                                context->modules))
            ReportApcStackwalkViolation(frames[index]);
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

    if (!ARGUMENT_PRESENT(Context))
        return;

    process_name =
        ImpPsGetProcessImageFileName(ThreadListEntry->owning_process);

    /*
     * Its possible to set the KThread->ApcQueueable flag to false ensuring
     * that no APCs can be queued to the thread, as KeInsertQueueApc will
     * check this flag before queueing an APC so lets make sure we flip this
     * before before queueing ours. Since we filter out any system threads
     * this should be fine... c:
     */
    flags =
        (PLONG)((UINT64)ThreadListEntry->thread + KTHREAD_MISC_FLAGS_OFFSET);
    previous_mode =
        (PCHAR)((UINT64)ThreadListEntry->thread + KTHREAD_PREVIOUS_MODE_OFFSET);
    state = (PUCHAR)((UINT64)ThreadListEntry->thread + KTHREAD_STATE_OFFSET);

    /*
     * For now, lets only check for system threads. However, we also want to
     * check for threads executing in kernel mode, i.e KTHREAD->PreviousMode
     * == UserMode.
     */
    if (ThreadListEntry->owning_process != PsInitialSystemProcess)
        return;

    if (ThreadListEntry->thread == KeGetCurrentThread() ||
        !ThreadListEntry->thread)
        return;

    DEBUG_VERBOSE(
        "Validating thread: %llx, process name: %s via kernel APC stackwalk.",
        ThreadListEntry->thread,
        process_name);

    SetFlag(*flags, KTHREAD_MISC_FLAGS_ALERTABLE);
    SetFlag(*flags, KTHREAD_MISC_FLAGS_APC_QUEUEABLE);

    apc = (PKAPC)ImpExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(KAPC), POOL_TAG_APC);

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

    if (!apc_status) {
        DEBUG_ERROR("KeInsertQueueApc failed with no status.");
        ImpExFreePoolWithTag(apc, POOL_TAG_APC);
        return;
    }

    ThreadListEntry->apc        = apc;
    ThreadListEntry->apc_queued = TRUE;

    IncrementApcCount(APC_CONTEXT_ID_STACKWALK);
}

FORCEINLINE
STATIC
VOID
SetApcAllocationInProgress(_In_ PAPC_STACKWALK_CONTEXT Context)
{
    Context->header.allocation_in_progress = TRUE;
}

UnsetApcAllocationInProgress(_In_ PAPC_STACKWALK_CONTEXT Context)
{
    Context->header.allocation_in_progress = FALSE;
}

/*
 * Since NMIs are only executed on the thread that is running on each logical
 * core, it makes sense to make use of APCs that, while can be masked off,
 * provide us to easily issue a callback routine to threads we want a stack
 * trace of. Hence by utilising both APCs and NMIs we get excellent coverage of
 * the entire system.
 */
NTSTATUS
ValidateThreadsViaKernelApc()
{
    PAGED_CODE();

    NTSTATUS               status  = STATUS_UNSUCCESSFUL;
    PAPC_STACKWALK_CONTEXT context = NULL;

    /* First, ensure we dont already have an ongoing operation */
    GetApcContext(&context, APC_CONTEXT_ID_STACKWALK);

    if (context) {
        DEBUG_WARNING("Existing APC_STACKWALK operation already in progress.");
        return STATUS_SUCCESS;
    }

    context = ImpExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(APC_STACKWALK_CONTEXT), POOL_TAG_APC);

    if (!context)
        return STATUS_MEMORY_NOT_ALLOCATED;

    context->header.context_id = APC_CONTEXT_ID_STACKWALK;
    context->modules           = ImpExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(SYSTEM_MODULES), POOL_TAG_APC);

    if (!context->modules) {
        ImpExFreePoolWithTag(context, POOL_TAG_APC);
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    status = GetSystemModuleInformation(context->modules);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("GetSystemModuleInformation failed with status %x", status);
        ImpExFreePoolWithTag(context->modules, POOL_TAG_APC);
        ImpExFreePoolWithTag(context, POOL_TAG_APC);
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    InsertApcContext(context);

    SetApcAllocationInProgress(context);
    EnumerateThreadListWithCallbackRoutine(ValidateThreadViaKernelApcCallback,
                                           context);
    UnsetApcAllocationInProgress(context);
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

typedef struct _DPC_CONTEXT {
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
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (!ARGUMENT_PRESENT(DeferredContext))
        return;

    PDPC_CONTEXT context =
        &((PDPC_CONTEXT)DeferredContext)[KeGetCurrentProcessorNumber()];

    context->frames_captured =
        ImpRtlCaptureStackBackTrace(DPC_STACKWALK_FRAMES_TO_SKIP,
                                    DPC_STACKWALK_STACKFRAME_COUNT,
                                    &context->stack_frame,
                                    NULL);
    InterlockedExchange(&context->executed, TRUE);

#pragma warning(push)
#pragma warning(disable : C6387)
    ImpKeSignalCallDpcDone(SystemArgument1);
#pragma warning(pop)

    DEBUG_VERBOSE("Executed DPC on core: %lx, with %lx frames captured.",
                  KeGetCurrentProcessorNumber(),
                  context->frames_captured);
}

STATIC
BOOLEAN
CheckForDpcCompletion(_In_ PDPC_CONTEXT Context)
{
    for (UINT32 index = 0; index < ImpKeQueryActiveProcessorCount(0); index++) {
        if (!InterlockedExchange(&Context[index].executed,
                                 Context[index].executed))
            return FALSE;
    }

    return TRUE;
}

STATIC
VOID
ReportDpcStackwalkViolation(_In_ PDPC_CONTEXT Context, _In_ UINT64 Frame)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UINT32   packet_size =
        CryptRequestRequiredBufferLength(sizeof(DPC_STACKWALK_REPORT));

    PDPC_STACKWALK_REPORT report =
        ImpExAllocatePool2(POOL_FLAG_NON_PAGED, packet_size, REPORT_POOL_TAG);

    if (!report)
        return;

    INIT_REPORT_PACKET(report, REPORT_DPC_STACKWALK, 0);

    report->kthread_address = PsGetCurrentThread();
    report->invalid_rip     = Frame;

    // RtlCopyMemory(report->driver,
    //               (UINT64)Context[core].stack_frame[frame]
    //               - 0x50,
    //               APC_STACKWALK_BUFFER_SIZE);

    status = CryptEncryptBuffer(report, packet_size);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("CryptEncryptBuffer: %lx", status);
        ImpExFreePoolWithTag(report, REPORT_POOL_TAG);
        return;
    }

    IrpQueueCompletePacket(report, packet_size);
}

STATIC
VOID
ValidateDpcStackFrame(_In_ PDPC_CONTEXT Context, _In_ PSYSTEM_MODULES Modules)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOLEAN  flag   = FALSE;

    for (UINT32 frame = 0; frame < Context->frames_captured; frame++) {
        UINT64 rip = Context->stack_frame[frame];

        if (IsInstructionPointerInInvalidRegion(rip, Modules))
            ReportDpcStackwalkViolation(Context, rip);
    }
}

STATIC
VOID
ValidateDpcCapturedStack(_In_ PSYSTEM_MODULES Modules,
                         _In_ PDPC_CONTEXT    Context)
{
    BOOLEAN               flag   = FALSE;
    PDPC_STACKWALK_REPORT report = NULL;
    UINT32                count  = ImpKeQueryActiveProcessorCount(0);

    for (UINT32 core = 0; core < count; core++) {
        ValidateDpcStackFrame(&Context[core], Modules);
    }
}

/*
 * Lets use DPCs as another form of stackwalking rather then inter-process
 * interrupts because DPCs run at IRQL = DISPATCH_LEVEL, allowing us to use
 * functions such as RtlCaptureStackBackTrace whereas IPIs run at IRQL =
 * IPI_LEVEL. DPCs are also harder to mask compared to APCs which can be masked
 * with the flip of a bit in the KTHREAD structure.
 */
NTSTATUS
DispatchStackwalkToEachCpuViaDpc()
{
    NTSTATUS       status  = STATUS_UNSUCCESSFUL;
    PDPC_CONTEXT   context = NULL;
    SYSTEM_MODULES modules = {0};
    UINT32 size = ImpKeQueryActiveProcessorCount(0) * sizeof(DPC_CONTEXT);

    context = ImpExAllocatePool2(POOL_FLAG_NON_PAGED, size, POOL_TAG_DPC);

    if (!context)
        return STATUS_MEMORY_NOT_ALLOCATED;

    status = GetSystemModuleInformation(&modules);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("GetSystemModuleInformation failed with status %x", status);
        goto end;
    }

    /* KeGenericCallDpc will queue a DPC to each processor with importance =
     * HighImportance. This means our DPC will be inserted into the front of
     * the DPC queue and executed immediately.*/
    ImpKeGenericCallDpc(DpcStackwalkCallbackRoutine, context);

    while (!CheckForDpcCompletion(context))
        YieldProcessor();

    ValidateDpcCapturedStack(&modules, context);

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

    for (UINT32 index = 0; index < Entries; index++) {
        if (!Base[index])
            continue;

        if (IsInstructionPointerInInvalidRegion(Base[index], Modules))
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
ValidateHalPrivateDispatchTable(_Out_ PVOID*         Routine,
                                _In_ PSYSTEM_MODULES Modules)
{
    NTSTATUS           status = STATUS_UNSUCCESSFUL;
    PVOID              table  = NULL;
    UNICODE_STRING     string = RTL_CONSTANT_STRING(L"HalPrivateDispatchTable");
    PVOID*             base   = NULL;
    RTL_OSVERSIONINFOW os_info = {0};
    UINT32             count   = 0;

    DEBUG_VERBOSE("Validating HalPrivateDispatchTable.");

    table = ImpMmGetSystemRoutineAddress(&string);

    if (!table)
        return status;

    status = GetOsVersionInformation(&os_info);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("GetOsVersionInformation failed with status %x", status);
        return status;
    }

    base  = (UINT64)table + sizeof(UINT64);
    count = GetHalPrivateDispatchTableRoutineCount(&os_info);

    status = ValidateTableDispatchRoutines(base, count, Modules, Routine);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ValidateTableDispatchRoutines failed with status %x",
                    status);
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
     * Since windows exports all the function pointers inside the
     * HalDispatchTable, we may aswell make use of them and validate it this
     * way. While it definitely is ugly, it is the safest way to do it.
     *
     * What if there are 2 invalid routines? hmm.. tink.
     */

    if (IsInstructionPointerInInvalidRegion(HalQuerySystemInformation,
                                            Modules)) {
        *Routine = HalQuerySystemInformation;
        goto end;
    }

    if (IsInstructionPointerInInvalidRegion(HalSetSystemInformation, Modules)) {
        *Routine = HalSetSystemInformation;
        goto end;
    }

    if (IsInstructionPointerInInvalidRegion(HalQueryBusSlots, Modules)) {
        *Routine = HalQueryBusSlots;
        goto end;
    }

    if (IsInstructionPointerInInvalidRegion(HalReferenceHandlerForBus,
                                            Modules)) {
        *Routine = HalReferenceHandlerForBus;
        goto end;
    }

    if (IsInstructionPointerInInvalidRegion(HalReferenceBusHandler, Modules)) {
        *Routine = HalReferenceBusHandler;
        goto end;
    }

    if (IsInstructionPointerInInvalidRegion(HalDereferenceBusHandler,
                                            Modules)) {
        *Routine = HalDereferenceBusHandler;
        goto end;
    }

    if (IsInstructionPointerInInvalidRegion(HalInitPnpDriver, Modules)) {
        *Routine = HalInitPnpDriver;
        goto end;
    }

    if (IsInstructionPointerInInvalidRegion(HalInitPowerManagement, Modules)) {
        *Routine = HalInitPowerManagement;
        goto end;
    }

    if (IsInstructionPointerInInvalidRegion(HalGetDmaAdapter, Modules)) {
        *Routine = HalGetDmaAdapter;
        goto end;
    }

    if (IsInstructionPointerInInvalidRegion(HalGetInterruptTranslator,
                                            Modules)) {
        *Routine = HalGetInterruptTranslator;
        goto end;
    }

    if (IsInstructionPointerInInvalidRegion(HalStartMirroring, Modules)) {
        *Routine = HalStartMirroring;
        goto end;
    }

    if (IsInstructionPointerInInvalidRegion(HalEndMirroring, Modules)) {
        *Routine = HalEndMirroring;
        goto end;
    }

    if (IsInstructionPointerInInvalidRegion(HalMirrorPhysicalMemory, Modules)) {
        *Routine = HalMirrorPhysicalMemory;
        goto end;
    }

    if (IsInstructionPointerInInvalidRegion(HalEndOfBoot, Modules)) {
        *Routine = HalEndOfBoot;
        goto end;
    }

    if (IsInstructionPointerInInvalidRegion(HalMirrorVerify, Modules)) {
        *Routine = HalMirrorVerify;
        goto end;
    }

    if (IsInstructionPointerInInvalidRegion(HalGetCachedAcpiTable, Modules)) {
        *Routine = HalGetCachedAcpiTable;
        goto end;
    }

    if (IsInstructionPointerInInvalidRegion(HalSetPciErrorHandlerCallback,
                                            Modules)) {
        *Routine = HalSetPciErrorHandlerCallback;
        goto end;
    }

    if (IsInstructionPointerInInvalidRegion(HalGetPrmCache, Modules)) {
        *Routine = HalGetPrmCache;
        goto end;
    }

end:
    return status;
}

STATIC
VOID
ReportDataTableInvalidRoutine(_In_ TABLE_ID TableId, _In_ UINT64 Address)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UINT32   packet_size =
        CryptRequestRequiredBufferLength(sizeof(DATA_TABLE_ROUTINE_REPORT));

    PDATA_TABLE_ROUTINE_REPORT report =
        ImpExAllocatePool2(POOL_FLAG_NON_PAGED, packet_size, REPORT_POOL_TAG);

    if (!report)
        return;

    DEBUG_WARNING("Invalid data table routine found. Table: %lx, Address: %llx",
                  TableId,
                  Address);

    INIT_REPORT_PACKET(report, REPORT_DATA_TABLE_ROUTINE, 0);

    report->address  = Address;
    report->table_id = TableId;
    report->index    = 0;
    RtlCopyMemory(report->routine, Address, DATA_TABLE_ROUTINE_BUF_SIZE);

    status = CryptEncryptBuffer(report, packet_size);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("CryptEncryptBuffer: %lx", status);
        ImpExFreePoolWithTag(report, REPORT_POOL_TAG);
        return;
    }

    IrpQueueCompletePacket(report, packet_size);
}

NTSTATUS
ValidateHalDispatchTables()
{
    NTSTATUS       status   = STATUS_UNSUCCESSFUL;
    SYSTEM_MODULES modules  = {0};
    PVOID          routine1 = NULL;
    PVOID          routine2 = NULL;

    status = GetSystemModuleInformation(&modules);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("GetSystemModuleInformation failed with status %x", status);
        return status;
    }

    status = ValidateHalDispatchTable(&routine1, &modules);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ValidateHalDispatchTable failed with status %x", status);
        goto end;
    }

    if (routine1)
        ReportDataTableInvalidRoutine(HalDispatch, routine1);
    else
        DEBUG_VERBOSE("HalDispatch dispatch routines are valid.");

    status = ValidateHalPrivateDispatchTable(&routine2, &modules);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ValidateHalPrivateDispatchTable failed with status %x",
                    status);
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
GetDriverObjectByDriverName(_In_ PUNICODE_STRING  DriverName,
                            _Out_ PDRIVER_OBJECT* DriverObject)
{
    HANDLE            handle           = NULL;
    OBJECT_ATTRIBUTES attributes       = {0};
    PVOID             directory        = {0};
    UNICODE_STRING    directory_name   = {0};
    NTSTATUS          status           = STATUS_UNSUCCESSFUL;
    POBJECT_DIRECTORY directory_object = NULL;

    *DriverObject = NULL;

    ImpRtlInitUnicodeString(&directory_name, L"\\Driver");

    InitializeObjectAttributes(
        &attributes, &directory_name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status =
        ImpZwOpenDirectoryObject(&handle, DIRECTORY_ALL_ACCESS, &attributes);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ZwOpenDirectoryObject failed with status %x", status);
        return status;
    }

    status = ImpObReferenceObjectByHandle(
        handle, DIRECTORY_ALL_ACCESS, NULL, KernelMode, &directory, NULL);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ObReferenceObjectByHandle failed with status %x", status);
        ImpZwClose(handle);
        return status;
    }

    directory_object = (POBJECT_DIRECTORY)directory;

    ImpExAcquirePushLockExclusiveEx(&directory_object->Lock, NULL);

    for (INT index = 0; index < NUMBER_HASH_BUCKETS; index++) {
        POBJECT_DIRECTORY_ENTRY entry = directory_object->HashBuckets[index];

        if (!entry)
            continue;

        POBJECT_DIRECTORY_ENTRY sub_entry = entry;

        while (sub_entry) {
            PDRIVER_OBJECT current_driver = sub_entry->Object;

            if (!RtlCompareUnicodeString(
                    DriverName, &current_driver->DriverName, FALSE)) {
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

PVOID
FindDriverBaseNoApi(_In_ PDRIVER_OBJECT DriverObject, _In_ PWCH Name)
{
    PKLDR_DATA_TABLE_ENTRY first =
        (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;

    /* first entry contains invalid data, 2nd entry is the kernel */
    PKLDR_DATA_TABLE_ENTRY entry =
        ((PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection)
            ->InLoadOrderLinks.Flink->Flink;

    while (entry->InLoadOrderLinks.Flink != first) {
        /* todo: write our own unicode string comparison function, since
         * the entire point of this is to find exports with no exports.
         */
        if (!wcscmp(entry->BaseDllName.Buffer, Name)) {
            return entry->DllBase;
        }

        entry = entry->InLoadOrderLinks.Flink;
    }

    return NULL;
}

STATIC
VOID
ValidateDispatchTableRoutines(_In_ PVOID* Table, _In_ UINT32 Entries)
{
}

PRTL_MODULE_EXTENDED_INFO
FindModuleByName(_In_ PSYSTEM_MODULES Modules, _In_ PCHAR ModuleName)
{
    for (UINT32 index = 0; index < Modules->module_count; index++) {
        PRTL_MODULE_EXTENDED_INFO entry =
            &((PRTL_MODULE_EXTENDED_INFO)(Modules->address))[index];
        if (strstr(entry->FullPathName, ModuleName))
            return entry;
    }

    return NULL;
}

#define KERNEL_LOW_ADDRESS  0xFFFF000000000000
#define KERNEL_HIGH_ADDRESS 0xFFFFFFFFFFFFFFFF

BOOLEAN
IsValidKernelAddress(_In_ UINT64 Address)
{
    if (!(Address >= KERNEL_LOW_ADDRESS && Address <= KERNEL_HIGH_ADDRESS))
        return FALSE;
    if (!MmIsAddressValid(Address))
        return FALSE;

    return TRUE;
}

/*
 * Follows a chain of valid pointers until a pointer is no longer present in the
 * chain, and returns the final pointer. Assumes the argument "Start" contains a
 * valid pointer at its address.
 *
 * The try catch here is also useless. We can work on making this more secure
 * later.
 */
PVOID
FindChainedPointerEnding(_In_ PVOID* Start)
{
    PVOID* current = *Start;
    PVOID  prev    = Start;

    while (IsValidKernelAddress(current)) {
        __try {
            prev    = current;
            current = *current;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return prev;
        }
    }

    return prev;
}

#define WIN32KBASE_DXGKRNL_INTERFACE_FUNC_COUNT 98

// clang-format off
/*
* ffffa135`fa847828  fffff805`5c7ccf60
* ffffa135`fa847828  fffff805`5c7ccf60 dxgkrnl!DXG_GUEST_COMPOSITIONOBJECTCHANNEL::ChannelStarted
* ffffa135`fa847830  fffff805`5c7ccf60 dxgkrnl!DXG_GUEST_COMPOSITIONOBJECTCHANNEL::ChannelStarted
* ffffa135`fa847838  fffff805`5c7e4ca0 dxgkrnl!DxgkProcessCallout
* ffffa135`fa847840  fffff805`5c7b2580 dxgkrnl!DxgkNotifyProcessFreezeCallout
* ffffa135`fa847848  fffff805`5c7b2430 dxgkrnl!DxgkNotifyProcessThawCallout
* ffffa135`fa847850  fffff805`5c7daf30 dxgkrnl!DxgkOpenAdapter
* ffffa135`fa847858  fffff805`5c7ff6e0 dxgkrnl!DxgkEnumAdapters2Impl
* ffffa135`fa847860  fffff805`5c839f00 dxgkrnl!DxgkGetMaximumAdapterCount
* ffffa135`fa847868  fffff805`5c7e37c0 dxgkrnl!DxgkCloseAdapterImpl
* ffffa135`fa847870  fffff805`5c7b3970 dxgkrnl!DxgkDestroyDevice
* ffffa135`fa847878  fffff805`5c7c8370 dxgkrnl!DxgkEscape
* ffffa135`fa847880  fffff805`5c7c58d0 dxgkrnl!DxgkGetPresentHistoryInternal
* ffffa135`fa847888  fffff805`5c9569a0 dxgkrnl!DxgkReleaseProcessVidPnSourceOwners
* ffffa135`fa847890  fffff805`5c8f4de0 dxgkrnl!DxgkPollDisplayChildrenInternal
* ffffa135`fa847898  fffff805`5c837390 dxgkrnl!DxgkFlushPresentHistory
* ffffa135`fa8478a0  fffff805`5c802e00 dxgkrnl!DxgkGetPathsModality
* ffffa135`fa8478a8  fffff805`5c82e7c0 dxgkrnl!DxgkFunctionalizePathsModality
* ffffa135`fa8478b0  fffff805`5c82e6d0 dxgkrnl!DxgkApplyPathsModality
* ffffa135`fa8478b8  fffff805`5c819740 dxgkrnl!DxgkFinalizePathsModality
* ffffa135`fa8478c0  fffff805`5c7b01c0 dxgkrnl!DxgkPersistPathsModality
* ffffa135`fa8478c8  fffff805`5c839d80 dxgkrnl!DxgkFreePathsModality
* ffffa135`fa8478d0  fffff805`5c816870 dxgkrnl!DxgkAugmentCdsj
* ffffa135`fa8478d8  fffff805`5c821270 dxgkrnl!DxgkGetPresentHistoryReadyEvent
* ffffa135`fa8478e0  fffff805`5c806eb0 dxgkrnl!DxgkGetDisplayConfigBufferSizes
* ffffa135`fa8478e8  fffff805`5c8070e0 dxgkrnl!DxgkQueryDisplayConfig
* ffffa135`fa8478f0  fffff805`5c9677d0 dxgkrnl!DxgkHandleForceProjectionMonitor
* ffffa135`fa8478f8  fffff805`5c838f10 dxgkrnl!DxgkUpdateCddDevmodeExtraData
* ffffa135`fa847900  fffff805`5c967ca0 dxgkrnl!DxgkProcessDisplayCalloutBatch
* ffffa135`fa847908  fffff805`5c7f8880 dxgkrnl!DxgkDisplayConfigDeviceInfo
* ffffa135`fa847910  fffff805`5c7e11f0 dxgkrnl!DxgkGetAdapterDeviceDesc
* ffffa135`fa847918  fffff805`5c7e9200 dxgkrnl!DxgkGetMonitorInternalInfo
* ffffa135`fa847920  fffff805`5c82a4f0 dxgkrnl!DxgkBeginTopologyTransition
* ffffa135`fa847928  fffff805`5c829f50 dxgkrnl!DxgkCompleteTopologyTransition
* ffffa135`fa847930  fffff805`5c8f4130 dxgkrnl!DxgkNeedToEnableCddPrimary
* ffffa135`fa847938  fffff805`5c82a090 dxgkrnl!DxgkInvalidateMonitorConnections
* ffffa135`fa847940  fffff805`5c807340 dxgkrnl!DxgkWriteDiagEntry
* ffffa135`fa847948  fffff805`5c815800 dxgkrnl!DxgkGetAdapterDefaultScaling
* ffffa135`fa847950  fffff805`5c816240 dxgkrnl!DxgkConvertDisplayConfigCScalingToDdiScaling
* ffffa135`fa847958  fffff805`5c8397e0 dxgkrnl!DxgkGetGlobalRawmodeFlag
* ffffa135`fa847960  fffff805`5c967e70 dxgkrnl!DxgkSetGlobalRawmodeFlag
* ffffa135`fa847968  fffff805`5c839530 dxgkrnl!DxgkQueryModeListCacheLuid
* ffffa135`fa847970  fffff805`5c826ff0 dxgkrnl!DxgkThreadCallout
* ffffa135`fa847978  fffff805`5c829c40 dxgkrnl!DxgkSessionConnected
* ffffa135`fa847980  fffff805`5c829a60 dxgkrnl!DxgkPreSessionDisconnected
* ffffa135`fa847988  fffff805`5c829b90 dxgkrnl!DxgkSessionDisconnected
* ffffa135`fa847990  fffff805`5c844420 dxgkrnl!DxgkSessionReconnected
* ffffa135`fa847998  fffff805`5c8440f0 dxgkrnl!DxgkGetAdapter
* ffffa135`fa8479a0  fffff805`5c844290 dxgkrnl!DxgkReleaseAdapter
* ffffa135`fa8479a8  fffff805`5c82c200 dxgkrnl!DxgkDesktopSwitch
* ffffa135`fa8479b0  fffff805`5c811860 dxgkrnl!DxgkStatusChangeNotify
* ffffa135`fa8479b8  fffff805`5c928fd0 dxgkrnl!DxgkEnableUnorderedWaitsForDevice
* ffffa135`fa8479c0  fffff805`5c839670 dxgkrnl!DxgkCddVerifyCddDevMode
* ffffa135`fa8479c8  fffff805`5c93bf30 dxgkrnl!DxgkIsVidPnSourceOwnerDwm
* ffffa135`fa8479d0  fffff805`5c8377a0 dxgkrnl!DxgkIsVidPnSourceOwnerExclusive
* ffffa135`fa8479d8  fffff805`5c7f8720 dxgkrnl!DxgkGetMonitorDeviceObject
* ffffa135`fa8479e0  fffff805`5c831680 dxgkrnl!DxgkRegisterDwmProcess
* ffffa135`fa8479e8  fffff805`5c8fa0a0 dxgkrnl!DxgkGetSharedResourceAdapterLuid
* ffffa135`fa8479f0  fffff805`5c8e7590 dxgkrnl!DxgkNotifyMonitorDimming
* ffffa135`fa8479f8  fffff805`5c820d10 dxgkrnl!DxgkGetSharedAllocationObjectType
* ffffa135`fa847a00  fffff805`5c820d20 dxgkrnl!DxgkGetSharedSyncObjectType
* ffffa135`fa847a08  fffff805`5c83b1b0 dxgkrnl!DxgkGetDisplayManagerObjectType
* ffffa135`fa847a10  fffff805`5c93be10 dxgkrnl!DxgkGetProcessInterferenceCount
* ffffa135`fa847a18  fffff805`5c839cd0 dxgkrnl!DxgkGetGpuUsageStatistics
* ffffa135`fa847a20  fffff805`5c815320 dxgkrnl!DxgkUpdateGdiInfo
* ffffa135`fa847a28  fffff805`5c8393d0 dxgkrnl!DxgkSetPresenterViewMode
* ffffa135`fa847a30  fffff805`5c836930 dxgkrnl!DxgkGetPresenterViewMode
* ffffa135`fa847a38  fffff805`5c827820 dxgkrnl!DxgkSetProcessStatus
* ffffa135`fa847a40  fffff805`5c7fa180 dxgkrnl!DxgkConvertLegacyQDCAdapterAndIdToActual
* ffffa135`fa847a48  fffff805`5c81b510 dxgkrnl!DxgkDisplayOnOff
* ffffa135`fa847a50  fffff805`5c815c30 dxgkrnl!DxgkIsVirtualizationDisabledForTarget
* ffffa135`fa847a58  fffff805`5c8378f0 dxgkrnl!DxgkIsSourceInHardwareClone
* ffffa135`fa847a60  fffff805`5c96d7d0 dxgkrnl!DxgkProcessLockScreen
* ffffa135`fa847a68  fffff805`5c964bd0 dxgkrnl!DxgkCopyPathsModality
* ffffa135`fa847a70  fffff805`5c964b30 dxgkrnl!DxgkApplyCdsjToPathsModality
* ffffa135`fa847a78  fffff805`5c979410 dxgkrnl!DxgkUpdateDpiInfoForNewOverride
* ffffa135`fa847a80  fffff805`5c839a00 dxgkrnl!DxgkInitializeDpi
* ffffa135`fa847a88  fffff805`5c839930 dxgkrnl!DxgkGetDpiOverrideForSource
* ffffa135`fa847a90  fffff805`5c980420 dxgkrnl!DxgkGetLegacyDpiInfo
* ffffa135`fa847a98  fffff805`5c94e0e0 dxgkrnl!DxgkWin32kSetPointerPosition
* ffffa135`fa847aa0  fffff805`5c94e240 dxgkrnl!DxgkWin32kSetPointerShape
* ffffa135`fa847aa8  fffff805`5c844730 dxgkrnl!DxgkGetUseHWGPUInRemoteSession
* ffffa135`fa847ab0  fffff805`5c945520 dxgkrnl!DxgkLPMDisplayControl
* ffffa135`fa847ab8  fffff805`5c945470 dxgkrnl!DxgkEnableHighPrecisionBrightness
* ffffa135`fa847ac0  fffff805`5c945640 dxgkrnl!DxgkSetHighPrecisionBrightness
* ffffa135`fa847ac8  fffff805`5c844670 dxgkrnl!DxgkChangeD3RequestsState
* ffffa135`fa847ad0  fffff805`5c836b90 dxgkrnl!DxgkGetMonitorEdid
* ffffa135`fa847ad8  fffff805`5c967620 dxgkrnl!DxgkConvertPathsModalityToDisplayConfig
* ffffa135`fa847ae0  fffff805`5c815d40 dxgkrnl!DxgkConvertDisplayConfigToDevMode
* ffffa135`fa847ae8  fffff805`5c7febd0 dxgkrnl!DxgkDDisplayEnumInternal
* ffffa135`fa847af0  fffff805`5c9677a0 dxgkrnl!DxgkGetMonitorDisplayId
* ffffa135`fa847af8  fffff805`5c964c60 dxgkrnl!DxgkEnumerateModesForPathsModality
* ffffa135`fa847b00  fffff805`5c8f0e70 dxgkrnl!DxgCreateLiveDumpWithWdLogs
* ffffa135`fa847b08  fffff805`5c9818d0 dxgkrnl!DxgkDispMgrReferenceObjectByHandle
* ffffa135`fa847b10  fffff805`5c9818b0 dxgkrnl!DxgkDispMgrIsTargetOwned
* ffffa135`fa847b18  fffff805`5c98bb20 dxgkrnl!DxgkCheckDisplayState
* ffffa135`fa847b20  fffff805`5c8363c0 dxgkrnl!DxgkSetKernelDisplayPolicy
* ffffa135`fa847b28  fffff805`5c839720 dxgkrnl!DxgkSendDisplayBrokerMessage
* ffffa135`fa847b30  fffff805`5c96fb30 dxgkrnl!DxgkGetWddmRemoteSessionGdiViewRange
*/
// clang-format on

STATIC
VOID
ReportWin32kBase_DxgInterfaceViolation(_In_ UINT32 TableIndex,
                                       _In_ UINT64 Address)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UINT32   packet_size =
        CryptRequestRequiredBufferLength(sizeof(DATA_TABLE_ROUTINE_REPORT));

    PDATA_TABLE_ROUTINE_REPORT report =
        ImpExAllocatePool2(POOL_FLAG_NON_PAGED, packet_size, REPORT_POOL_TAG);

    if (!report)
        return;

    INIT_REPORT_PACKET(report, REPORT_DATA_TABLE_ROUTINE, 0);

    report->address  = Address;
    report->table_id = Win32kBase_gDxgInterface;
    report->index    = TableIndex;
    // todo! report->routine = ??
    // todo: maybe get routine by name from index ?

    status = CryptEncryptBuffer(report, packet_size);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("CryptEncryptBuffer: %lx", status);
        ImpExFreePoolWithTag(report, REPORT_POOL_TAG);
        return;
    }

    IrpQueueCompletePacket(report, packet_size);
}

STATIC
NTSTATUS
ValidateWin32kBase_gDxgInterface()
{
    NTSTATUS                  status        = STATUS_UNSUCCESSFUL;
    SYSTEM_MODULES            modules       = {0};
    PRTL_MODULE_EXTENDED_INFO win32kbase    = NULL;
    PRTL_MODULE_EXTENDED_INFO dxgkrnl       = NULL;
    KAPC_STATE                apc           = {0};
    PKPROCESS                 winlogon      = NULL;
    PVOID*                    dxg_interface = NULL;

    status = GetSystemModuleInformation(&modules);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("GetSystemModuleInformation failed %x", status);
        return status;
    }

    win32kbase = FindModuleByName(&modules, "win32kbase.sys");

    if (!win32kbase) {
        status = STATUS_UNSUCCESSFUL;
        goto end;
    }

    EnumerateProcessListWithCallbackRoutine(FindWinLogonProcess, &winlogon);

    if (!winlogon) {
        status = STATUS_UNSUCCESSFUL;
        goto end;
    }

    KeStackAttachProcess(winlogon, &apc);
    dxg_interface = PeFindExportByName(win32kbase->ImageBase, "gDxgkInterface");

    if (!dxg_interface) {
        status = STATUS_UNSUCCESSFUL;
        goto detatch;
    }

    /* The functions in this table reside in dxgkrnl.sys */
    dxgkrnl = FindModuleByName(&modules, "dxgkrnl.sys");

    if (!dxgkrnl) {
        status = STATUS_UNSUCCESSFUL;
        goto detatch;
    }

    /* first 3 qwords are housekeeping. */
    for (UINT32 index = 3; index < WIN32KBASE_DXGKRNL_INTERFACE_FUNC_COUNT + 3;
         index++) {
        if (!dxg_interface[index])
            continue;

        PVOID entry = FindChainedPointerEnding(dxg_interface[index]);

#if DEBUG
        DEBUG_INFO("chain entry test: %p", entry);
        DEBUG_INFO("regular entry: %p", dxg_interface[index]);
#endif

        if (!IsInstructionPointerInsideSpecifiedModule(entry, dxgkrnl)) {
            DEBUG_ERROR("invalid entry!!!");
            ReportWin32kBase_DxgInterfaceViolation(index, entry);
        }
    }

detatch:
    KeUnstackDetachProcess(&apc);

end:
    if (modules.address)
        ExFreePoolWithTag(modules.address, SYSTEM_MODULES_POOL);

    return status;
}

/* todo: win32kEngInterface */
NTSTATUS
ValidateWin32kDispatchTables()
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    status = ValidateWin32kBase_gDxgInterface();

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ValidateWin32kBase_gDxgInterface: %x", status);
        return status;
    }

    return status;
}