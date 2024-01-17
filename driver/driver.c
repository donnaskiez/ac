#include "driver.h"

#include "common.h"
#include "ioctl.h"
#include "callbacks.h"

#include "hv.h"
#include "pool.h"
#include "thread.h"
#include "modules.h"
#include "integrity.h"
#include "imports.h"
#include "apc.h"

STATIC
VOID
DriverUnload(_In_ PDRIVER_OBJECT DriverObject);

_Function_class_(DRIVER_INITIALIZE) _IRQL_requires_same_
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);

STATIC
NTSTATUS
RegistryPathQueryCallbackRoutine(IN PWSTR ValueName,
                                 IN ULONG ValueType,
                                 IN PVOID ValueData,
                                 IN ULONG ValueLength,
                                 IN PVOID Context,
                                 IN PVOID EntryContext);

STATIC
VOID
DrvUnloadUnregisterObCallbacks();

STATIC
VOID
DrvUnloadFreeConfigStrings();

STATIC
VOID
DrvUnloadFreeSymbolicLink();

STATIC
VOID
DrvUnloadFreeGlobalReportQueue();

STATIC
VOID
DrvUnloadFreeThreadList();

STATIC
VOID
DrvUnloadFreeProcessList();

STATIC
NTSTATUS
DrvLoadEnableNotifyRoutines();

STATIC
NTSTATUS
DrvLoadInitialiseObCbConfig();

STATIC
VOID
DrvLoadInitialiseProcessConfig();

STATIC
NTSTATUS
DrvLoadInitialiseDriverConfig(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);

#ifdef ALLOC_PRAGMA
#        pragma alloc_text(INIT, DriverEntry)
#        pragma alloc_text(PAGE, GetProtectedProcessEProcess)
#        pragma alloc_text(PAGE, GetProtectedProcessId)
#        pragma alloc_text(PAGE, GetDriverName)
#        pragma alloc_text(PAGE, GetDriverPath)
#        pragma alloc_text(PAGE, GetDriverRegistryPath)
#        pragma alloc_text(PAGE, GetDriverDeviceName)
#        pragma alloc_text(PAGE, GetDriverSymbolicLink)
#        pragma alloc_text(PAGE, GetDriverConfigSystemInformation)
#        pragma alloc_text(PAGE, RegistryPathQueryCallbackRoutine)
#        pragma alloc_text(PAGE, TerminateProtectedProcessOnViolation)
#        pragma alloc_text(PAGE, DrvUnloadUnregisterObCallbacks)
#        pragma alloc_text(PAGE, DrvUnloadFreeConfigStrings)
#        pragma alloc_text(PAGE, DrvUnloadFreeSymbolicLink)
#        pragma alloc_text(PAGE, DrvUnloadFreeGlobalReportQueue)
#        pragma alloc_text(PAGE, DrvUnloadFreeThreadList)
#        pragma alloc_text(PAGE, DrvLoadEnableNotifyRoutines)
#        pragma alloc_text(PAGE, DrvLoadEnableNotifyRoutines)
#        pragma alloc_text(PAGE, DrvLoadInitialiseObCbConfig)
#        pragma alloc_text(PAGE, DrvLoadInitialiseProcessConfig)
#        pragma alloc_text(PAGE, DrvLoadInitialiseDriverConfig)
#        pragma alloc_text(PAGE, ReadProcessInitialisedConfigFlag)
#endif

typedef struct _DRIVER_CONFIG
{
        UNICODE_STRING         unicode_driver_name;
        ANSI_STRING            ansi_driver_name;
        UNICODE_STRING         device_name;
        UNICODE_STRING         device_symbolic_link;
        UNICODE_STRING         driver_path;
        UNICODE_STRING         registry_path;
        SYSTEM_INFORMATION     system_information;
        PVOID                  apc_contexts[MAXIMUM_APC_CONTEXTS];
        PDRIVER_OBJECT         driver_object;
        PDEVICE_OBJECT         device_object;
        volatile BOOLEAN       unload_in_progress;
        KGUARDED_MUTEX         lock;
        SYS_MODULE_VAL_CONTEXT sys_val_context;
        IRP_QUEUE_HEAD         irp_queue;
        TIMER_OBJECT           timer;
        PROCESS_CONFIG         process_config;
        THREAD_LIST_HEAD       thread_list;
        DRIVER_LIST_HEAD       driver_list;
        PROCESS_LIST_HEAD      process_list;
        REPORT_QUEUE_HEAD      report_queue;

} DRIVER_CONFIG, *PDRIVER_CONFIG;

/*
 * Rather then getting the driver state from the device object passed to our IOCTL handlers, store a
 * pointer to the device extension here and abstract it with getters which can be accessed globally.
 * The reason for this is because there isnt a way for us to pass a context structure to some of
 * notify routines so I think it's better to do it this way.
 *
 * Note that the device extension pointer should be encrypted
 */
PDRIVER_CONFIG g_DriverConfig = NULL;

#define POOL_TAG_CONFIG 'conf'

VOID
AcquireDriverConfigLock()
{
        ImpKeAcquireGuardedMutex(&g_DriverConfig->lock);
}

VOID
ReleaseDriverConfigLock()
{
        ImpKeReleaseGuardedMutex(&g_DriverConfig->lock);
}

PUINT64
GetApcContextArray()
{
        return (PUINT64)g_DriverConfig->apc_contexts;
}

BOOLEAN
IsDriverUnloading()
{
        return InterlockedExchange(&g_DriverConfig->unload_in_progress,
                                   g_DriverConfig->unload_in_progress);
}

PPROCESS_CONFIG
GetProcessConfig()
{
        return &g_DriverConfig->process_config;
}

VOID
GetCallbackConfigStructure(_Out_ POB_CALLBACKS_CONFIG* CallbackConfiguration)
{
        ImpKeAcquireGuardedMutex(&g_DriverConfig->process_config.lock);
        *CallbackConfiguration = &g_DriverConfig->process_config.callback_info;
        ImpKeReleaseGuardedMutex(&g_DriverConfig->process_config.lock);
}

LPCSTR
GetDriverName()
{
        PAGED_CODE();
        return g_DriverConfig->ansi_driver_name.Buffer;
}

PDEVICE_OBJECT
GetDriverDeviceObject()
{
        PAGED_CODE();
        return g_DriverConfig->device_object;
}

PDRIVER_OBJECT
GetDriverObject()
{
        PAGED_CODE();
        return g_DriverConfig->driver_object;
}

PIRP_QUEUE_HEAD
GetIrpQueueHead()
{
        return &g_DriverConfig->irp_queue;
}

PSYS_MODULE_VAL_CONTEXT
GetSystemModuleValidationContext()
{
        PAGED_CODE();
        return &g_DriverConfig->sys_val_context;
}

PUNICODE_STRING
GetDriverPath()
{
        PAGED_CODE();
        return &g_DriverConfig->driver_path;
}

PUNICODE_STRING
GetDriverRegistryPath()
{
        PAGED_CODE();
        return &g_DriverConfig->registry_path;
}

PUNICODE_STRING
GetDriverDeviceName()
{
        PAGED_CODE();
        return &g_DriverConfig->device_name;
}

PUNICODE_STRING
GetDriverSymbolicLink()
{
        PAGED_CODE();
        return &g_DriverConfig->device_symbolic_link;
}

PSYSTEM_INFORMATION
GetDriverConfigSystemInformation()
{
        PAGED_CODE();
        return &g_DriverConfig->system_information;
}

PREPORT_QUEUE_HEAD
GetDriverReportQueue()
{
        PAGED_CODE();
        return &g_DriverConfig->report_queue;
}

PTHREAD_LIST_HEAD
GetThreadList()
{
        PAGED_CODE();
        return &g_DriverConfig->thread_list;
}

PDRIVER_LIST_HEAD
GetDriverList()
{
        PAGED_CODE();
        return &g_DriverConfig->driver_list;
}

PPROCESS_LIST_HEAD
GetProcessList()
{
        PAGED_CODE();
        return &g_DriverConfig->process_list;
}

VOID
ReadProcessInitialisedConfigFlag(_Out_ PBOOLEAN Flag)
{
        PAGED_CODE();
        ImpKeAcquireGuardedMutex(&g_DriverConfig->process_config.lock);
        *Flag = g_DriverConfig->process_config.initialised;
        ImpKeReleaseGuardedMutex(&g_DriverConfig->process_config.lock);
}

VOID
GetProtectedProcessEProcess(_Out_ PEPROCESS* Process)
{
        PAGED_CODE();
        ImpKeAcquireGuardedMutex(&g_DriverConfig->process_config.lock);
        *Process = g_DriverConfig->process_config.process;
        ImpKeReleaseGuardedMutex(&g_DriverConfig->process_config.lock);
}

VOID
GetProtectedProcessId(_Out_ PLONG ProcessId)
{
        PAGED_CODE();
        ImpKeAcquireGuardedMutex(&g_DriverConfig->process_config.lock);
        *ProcessId = g_DriverConfig->process_config.km_handle;
        ImpKeReleaseGuardedMutex(&g_DriverConfig->process_config.lock);
}

VOID
ProcCloseClearProcessConfiguration()
{
        PAGED_CODE();
        DEBUG_INFO("Protected process closed. Clearing process configuration.");

        ImpKeAcquireGuardedMutex(&g_DriverConfig->process_config.lock);
        g_DriverConfig->process_config.km_handle   = NULL;
        g_DriverConfig->process_config.um_handle   = NULL;
        g_DriverConfig->process_config.process     = NULL;
        g_DriverConfig->process_config.initialised = FALSE;
        ImpKeReleaseGuardedMutex(&g_DriverConfig->process_config.lock);
}

NTSTATUS
ProcLoadInitialiseProcessConfig(_In_ PIRP Irp)
{
        PAGED_CODE();

        NTSTATUS                       status      = STATUS_UNSUCCESSFUL;
        PEPROCESS                      process     = NULL;
        PDRIVER_INITIATION_INFORMATION information = NULL;

        status = ValidateIrpInputBuffer(Irp, sizeof(DRIVER_INITIATION_INFORMATION));

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ValidateIrpInputBuffer failed with status %x", status);
                return status;
        }

        information = (PDRIVER_INITIATION_INFORMATION)Irp->AssociatedIrp.SystemBuffer;

        ImpKeAcquireGuardedMutex(&g_DriverConfig->process_config.lock);

        g_DriverConfig->process_config.um_handle = information->protected_process_id;

        /* What if we pass an invalid handle here? not good. */
        status = ImpPsLookupProcessByProcessId(g_DriverConfig->process_config.um_handle, &process);

        if (!NT_SUCCESS(status))
        {
                status = STATUS_INVALID_PARAMETER;
                goto end;
        }

        g_DriverConfig->process_config.km_handle   = ImpPsGetProcessId(process);
        g_DriverConfig->process_config.process     = process;
        g_DriverConfig->process_config.initialised = TRUE;

end:
        ImpKeReleaseGuardedMutex(&g_DriverConfig->process_config.lock);
        return status;
}

/*
 * The question is, What happens if we attempt to register our callbacks after we
 * unregister them but before we free the pool? Hm.. No Good.
 *
 * Okay to solve this well acquire the driver lock aswell, we could also just
 * store the structure in the .data section but i ceebs atm.
 *
 * This definitely doesn't seem optimal, but it works ...
 */
STATIC
VOID
DrvUnloadUnregisterObCallbacks()
{
        PAGED_CODE();
        UnregisterProcessObCallbacks();
}

STATIC
VOID
DrvUnloadFreeConfigStrings()
{
        PAGED_CODE();

        if (g_DriverConfig->unicode_driver_name.Buffer)
                ImpExFreePoolWithTag(g_DriverConfig->unicode_driver_name.Buffer, POOL_TAG_STRINGS);

        if (g_DriverConfig->driver_path.Buffer)
                ImpExFreePoolWithTag(g_DriverConfig->driver_path.Buffer, POOL_TAG_STRINGS);

        if (g_DriverConfig->ansi_driver_name.Buffer)
                ImpRtlFreeAnsiString(&g_DriverConfig->ansi_driver_name);
}

STATIC
VOID
DrvUnloadFreeSymbolicLink()
{
        PAGED_CODE();
        ImpIoDeleteSymbolicLink(&g_DriverConfig->device_symbolic_link);
}

STATIC
VOID
DrvUnloadFreeGlobalReportQueue()
{
        PAGED_CODE();
        FreeGlobalReportQueueObjects();
}

STATIC
VOID
DrvUnloadFreeThreadList()
{
        PAGED_CODE();
        CleanupThreadListOnDriverUnload();
}

STATIC
VOID
DrvUnloadFreeDriverList()
{
        PAGED_CODE();
        CleanupDriverListOnDriverUnload();
}

STATIC
VOID
DrvUnloadFreeTimerObject()
{
        PAGED_CODE();
        CleanupDriverTimerObjects(&g_DriverConfig->timer);
}

STATIC
VOID
DrvUnloadFreeProcessList()
{
        PAGED_CODE();
        CleanupProcessListOnDriverUnload();
}

STATIC
VOID
DrvUnloadFreeModuleValidationContext()
{
        PAGED_CODE();
        CleanupValidationContextOnUnload(&g_DriverConfig->sys_val_context);
}

STATIC
VOID
DrvUnloadFreeImportsStructure()
{
        PAGED_CODE();
        FreeDriverImportsStructure();
}

STATIC
VOID
DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
        DEBUG_VERBOSE("Unloading...");

        InterlockedExchange(&g_DriverConfig->unload_in_progress, TRUE);

        /*
         * This blocks the thread dispatching the unload routine, which I don't think is ideal.
         * This is the issue with using APCs, we have very little safe control over when they
         * complete and thus when we can free them.. For now, thisl do.
         */
        while (DrvUnloadFreeAllApcContextStructures() == FALSE)
                YieldProcessor();

        DrvUnloadFreeTimerObject();
        DrvUnloadFreeModuleValidationContext();
        DrvUnloadUnregisterObCallbacks();

        UnregisterThreadCreateNotifyRoutine();
        UnregisterProcessCreateNotifyRoutine();
        UnregisterImageLoadNotifyRoutine();

        DrvUnloadFreeThreadList();
        DrvUnloadFreeProcessList();
        DrvUnloadFreeDriverList();

        DrvUnloadFreeConfigStrings();
        DrvUnloadFreeGlobalReportQueue();
        DrvUnloadFreeSymbolicLink();

        ImpIoDeleteDevice(DriverObject->DeviceObject);

        DEBUG_INFO("Driver successfully unloaded.");
        DrvUnloadFreeImportsStructure();
}

STATIC
NTSTATUS
DrvLoadEnableNotifyRoutines()
{
        PAGED_CODE();

        NTSTATUS status = STATUS_UNSUCCESSFUL;

        DEBUG_VERBOSE("Enabling driver wide notify routines.");

        status = PsSetLoadImageNotifyRoutine(ImageLoadNotifyRoutineCallback);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("PsSetLoadImageNotifyRoutine failed with status %x", status);
                return status;
        }

        status = ImpPsSetCreateThreadNotifyRoutine(ThreadCreateNotifyRoutine);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("PsSetCreateThreadNotifyRoutine failed with status %x", status);
                PsRemoveLoadImageNotifyRoutine(ImageLoadNotifyRoutineCallback);
                return status;
        }

        status = ImpPsSetCreateProcessNotifyRoutine(ProcessCreateNotifyRoutine, FALSE);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("PsSetCreateProcessNotifyRoutine failed with status %x", status);
                ImpPsRemoveCreateThreadNotifyRoutine(ThreadCreateNotifyRoutine);
                PsRemoveLoadImageNotifyRoutine(ImageLoadNotifyRoutineCallback);
                return status;
        }

        DEBUG_VERBOSE("Successfully enabled driver wide notify routines.");
        return status;
}

STATIC
NTSTATUS
DrvLoadSetupDriverLists()
{
        PAGED_CODE();

        NTSTATUS status = STATUS_UNSUCCESSFUL;

        status = InitialiseDriverList();

        if (!NT_SUCCESS(status))
        {
                UnregisterImageLoadNotifyRoutine();
                DEBUG_ERROR("InitialiseDriverList failed with status %x", status);
                return status;
        }

        status = InitialiseThreadList();

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("InitialiseThreadList failed with status %x", status);
                UnregisterThreadCreateNotifyRoutine();
                UnregisterImageLoadNotifyRoutine();
                return status;
        }

        status = InitialiseProcessList();

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("InitialiseProcessList failed with status %x", status);
                UnregisterProcessCreateNotifyRoutine();
                UnregisterThreadCreateNotifyRoutine();
                UnregisterImageLoadNotifyRoutine();
                return status;
        }

        return status;
}

STATIC
VOID
DrvLoadInitialiseReportQueue()
{
        PAGED_CODE();
        InitialiseGlobalReportQueue(&g_DriverConfig->report_queue);
}

STATIC
VOID
DrvLoadInitialiseProcessConfig()
{
        PAGED_CODE();
        ImpKeInitializeGuardedMutex(&g_DriverConfig->process_config.lock);
}

STATIC
NTSTATUS
DrvLoadInitialiseObCbConfig()
{
        PAGED_CODE();
        InitialiseObCallbacksConfiguration(&g_DriverConfig->process_config);
}

/*
 * Regular routines
 */

VOID
TerminateProtectedProcessOnViolation()
{
        PAGED_CODE();

        NTSTATUS status     = STATUS_UNSUCCESSFUL;
        ULONG    process_id = 0;

        GetProtectedProcessId(&process_id);

        if (!process_id)
        {
                DEBUG_ERROR("Failed to terminate process as process id is null");
                return;
        }

        /* Make sure we pass a km handle to ZwTerminateProcess and NOT a usermode handle. */
        status = ZwTerminateProcess(process_id, STATUS_SYSTEM_INTEGRITY_POLICY_VIOLATION);

        if (!NT_SUCCESS(status))
        {
                /*
                 * We don't want to clear the process config if ZwTerminateProcess fails
                 * so we can try again.
                 */
                DEBUG_ERROR("ZwTerminateProcess failed with status %x", status);
                return;
        }
        /* this wont be needed when procloadstuff is implemented */
        ProcCloseClearProcessConfiguration();
}

STATIC
NTSTATUS
RegistryPathQueryCallbackRoutine(IN PWSTR ValueName,
                                 IN ULONG ValueType,
                                 IN PVOID ValueData,
                                 IN ULONG ValueLength,
                                 IN PVOID Context,
                                 IN PVOID EntryContext)
{
        PAGED_CODE();

        UNICODE_STRING value_name   = {0};
        UNICODE_STRING image_path   = RTL_CONSTANT_STRING(L"ImagePath");
        UNICODE_STRING display_name = RTL_CONSTANT_STRING(L"DisplayName");
        UNICODE_STRING value        = {0};
        PVOID          temp_buffer  = NULL;

        ImpRtlInitUnicodeString(&value_name, ValueName);

        if (ImpRtlCompareUnicodeString(&value_name, &image_path, FALSE) == FALSE)
        {
                temp_buffer = ImpExAllocatePool2(POOL_FLAG_PAGED, ValueLength, POOL_TAG_STRINGS);

                if (!temp_buffer)
                        return STATUS_MEMORY_NOT_ALLOCATED;

                RtlCopyMemory(temp_buffer, ValueData, ValueLength);

                g_DriverConfig->driver_path.Buffer        = (PWCH)temp_buffer;
                g_DriverConfig->driver_path.Length        = ValueLength;
                g_DriverConfig->driver_path.MaximumLength = ValueLength;
        }

        if (ImpRtlCompareUnicodeString(&value_name, &display_name, FALSE) == FALSE)
        {
                temp_buffer =
                    ImpExAllocatePool2(POOL_FLAG_PAGED, ValueLength + 20, POOL_TAG_STRINGS);

                if (!temp_buffer)
                        return STATUS_MEMORY_NOT_ALLOCATED;

                /*
                 * The registry path driver name does not contain the .sys extension which is
                 * required for us since when we enumerate the system modules we are comparing the
                 * entire path including the .sys extension. Hence we add it to the end of the
                 * buffer here.
                 */
                RtlCopyMemory(temp_buffer, ValueData, ValueLength);
                wcscpy((UINT64)temp_buffer + ValueLength - 2, L".sys");

                g_DriverConfig->unicode_driver_name.Buffer        = (PWCH)temp_buffer;
                g_DriverConfig->unicode_driver_name.Length        = ValueLength + 20;
                g_DriverConfig->unicode_driver_name.MaximumLength = ValueLength + 20;
        }

        return STATUS_SUCCESS;
}

/*
 * Values returned from CPUID that are equval to the vendor string
 */
#define CPUID_AUTHENTIC_AMD_EBX 0x68747541
#define CPUID_AUTHENTIC_AMD_EDX 0x69746e65
#define CPUID_AUTHENTIC_AMD_ECX 0x444d4163

#define CPUID_GENUINE_INTEL_EBX 0x756e6547
#define CPUID_GENUINE_INTEL_EDX 0x49656e69
#define CPUID_GENUINE_INTEL_ECX 0x6c65746e

#define EBX_REGISTER 1
#define ECX_REGISTER 2
#define EDX_REGISTER 3

STATIC
NTSTATUS
GetSystemProcessorType()
{
        UINT32 cpuid[4] = {0};

        __cpuid(cpuid, 0);

        DEBUG_VERBOSE("Cpuid: EBX: %lx, ECX: %lx, EDX: %lx", cpuid[1], cpuid[2], cpuid[3]);

        if (cpuid[EBX_REGISTER] == CPUID_AUTHENTIC_AMD_EBX &&
            cpuid[ECX_REGISTER] == CPUID_AUTHENTIC_AMD_ECX &&
            cpuid[EDX_REGISTER] == CPUID_AUTHENTIC_AMD_EDX)
        {
                g_DriverConfig->system_information.processor = GenuineIntel;
                return STATUS_SUCCESS;
        }
        else if (cpuid[EBX_REGISTER] == CPUID_GENUINE_INTEL_EBX &&
                 cpuid[ECX_REGISTER] == CPUID_GENUINE_INTEL_ECX &&
                 cpuid[EDX_REGISTER] == CPUID_GENUINE_INTEL_EDX)
        {
                g_DriverConfig->system_information.processor = AuthenticAmd;
                return STATUS_SUCCESS;
        }
        else
        {
                g_DriverConfig->system_information.processor = Unknown;
                return STATUS_UNSUCCESSFUL;
        }
}

/*
 * Even though we are technically not meant to be operating when running under a virtualized system,
 * it is still useful to test the attainment of system information under a virtualized system for
 * testing purposes.
 */
STATIC
NTSTATUS
ParseSmbiosForGivenSystemEnvironment()
{
        NTSTATUS status = STATUS_UNSUCCESSFUL;

        status = ParseSMBIOSTable(&g_DriverConfig->system_information.vendor,
                                  VENDOR_STRING_MAX_LENGTH,
                                  SmbiosInformation,
                                  SMBIOS_VENDOR_STRING_SUB_INDEX);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ParseSMBIOSTable failed with status %x", status);
                return status;
        }

        if (strstr(&g_DriverConfig->system_information.vendor, "VMware, Inc"))
                g_DriverConfig->system_information.environment = Vmware;
        else if (strstr(&g_DriverConfig->system_information.vendor, "innotek GmbH"))
                g_DriverConfig->system_information.environment = VirtualBox;
        else
                g_DriverConfig->system_information.environment = NativeWindows;

        switch (g_DriverConfig->system_information.environment)
        {
        case NativeWindows:
        {
                /*
                 * TODO: double check that amd indexes are the same should be, but should check just
                 * in case
                 */
                status = ParseSMBIOSTable(&g_DriverConfig->system_information.motherboard_serial,
                                          MOTHERBOARD_SERIAL_CODE_LENGTH,
                                          VendorSpecificInformation,
                                          SMBIOS_NATIVE_SERIAL_NUMBER_SUB_INDEX);

                break;
        }
        case Vmware:
        {
                status = ParseSMBIOSTable(&g_DriverConfig->system_information.motherboard_serial,
                                          MOTHERBOARD_SERIAL_CODE_LENGTH,
                                          SystemInformation,
                                          SMBIOS_VMWARE_SERIAL_NUMBER_SUB_INDEX);

                break;
        }
        case VirtualBox:
        default: DEBUG_WARNING("Environment type not supported."); return STATUS_NOT_SUPPORTED;
        }

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ParseSMBIOSTable 2 failed with status %x", status);
                return status;
        }

        return status;
}

STATIC
NTSTATUS
DrvLoadGatherSystemEnvironmentSettings()
{
        NTSTATUS status = STATUS_UNSUCCESSFUL;

        /*
         * On Vmware, the APERF_MSR is not emulated hence this will return TRUE.
         */
        if (APERFMsrTimingCheck())
                g_DriverConfig->system_information.virtualised_environment = TRUE;

        status = GetOsVersionInformation(&g_DriverConfig->system_information.os_information);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("GetOsVersionInformation failed with status %x", status);
                return status;
        }

        status = GetSystemProcessorType();

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("GetSystemProcessorType failed with status %x", status);
                return status;
        }

        status = ParseSmbiosForGivenSystemEnvironment();

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ParseSmbiosForGivenSystemEnvironment failed with status %x", status);
                DrvUnloadFreeConfigStrings();
                return status;
        }

        status =
            GetHardDiskDriveSerialNumber(&g_DriverConfig->system_information.drive_0_serial,
                                         sizeof(g_DriverConfig->system_information.drive_0_serial));

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("GetHardDiskDriverSerialNumber failed with status %x", status);
                DrvUnloadFreeConfigStrings();
                return status;
        }

        DEBUG_VERBOSE("OS Major Version: %lx, Minor Version: %lx, Build Number: %lx",
                      g_DriverConfig->system_information.os_information.dwMajorVersion,
                      g_DriverConfig->system_information.os_information.dwMinorVersion,
                      g_DriverConfig->system_information.os_information.dwBuildNumber);
        DEBUG_VERBOSE("Environment type: %lx", g_DriverConfig->system_information.environment);
        DEBUG_VERBOSE("Processor type: %lx", g_DriverConfig->system_information.processor);
        DEBUG_VERBOSE("Motherboard serial: %s",
                      g_DriverConfig->system_information.motherboard_serial);
        DEBUG_VERBOSE("Drive 0 serial: %s", g_DriverConfig->system_information.drive_0_serial);

        return status;
}

STATIC
NTSTATUS
DrvLoadRetrieveDriverNameFromRegistry(_In_ PUNICODE_STRING RegistryPath)
{
        NTSTATUS                 status         = STATUS_UNSUCCESSFUL;
        RTL_QUERY_REGISTRY_TABLE query_table[3] = {0};

        query_table[0].Flags         = RTL_QUERY_REGISTRY_NOEXPAND;
        query_table[0].Name          = L"ImagePath";
        query_table[0].DefaultType   = REG_MULTI_SZ;
        query_table[0].DefaultLength = 0;
        query_table[0].DefaultData   = NULL;
        query_table[0].EntryContext  = NULL;
        query_table[0].QueryRoutine  = RegistryPathQueryCallbackRoutine;

        query_table[1].Flags         = RTL_QUERY_REGISTRY_NOEXPAND;
        query_table[1].Name          = L"DisplayName";
        query_table[1].DefaultType   = REG_SZ;
        query_table[1].DefaultLength = 0;
        query_table[1].DefaultData   = NULL;
        query_table[1].EntryContext  = NULL;
        query_table[1].QueryRoutine  = RegistryPathQueryCallbackRoutine;

        status = RtlxQueryRegistryValues(
            RTL_REGISTRY_ABSOLUTE, RegistryPath->Buffer, &query_table, NULL, NULL);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("RtlxQueryRegistryValues failed with status %x", status);
                return status;
        }

        /*
         * The registry path contains the name of the driver i.e Driver, but does not contain the
         * .sys extension. Lets add it to our stored driver name since we need the .sys extension
         * when querying the system modules for our driver.
         */

        status = ImpRtlUnicodeStringToAnsiString(
            &g_DriverConfig->ansi_driver_name, &g_DriverConfig->unicode_driver_name, TRUE);

        if (!NT_SUCCESS(status))
                DEBUG_ERROR("RtlUnicodeStringToAnsiString failed with status %x", status);

        return status;
}

STATIC
NTSTATUS
DrvLoadInitialiseDriverConfig(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
        PAGED_CODE();
        DEBUG_VERBOSE("Initialising driver configuration");

        NTSTATUS status = STATUS_UNSUCCESSFUL;

        ImpKeInitializeGuardedMutex(&g_DriverConfig->lock);
        IrpQueueInitialise();

        g_DriverConfig->unload_in_progress                         = FALSE;
        g_DriverConfig->system_information.virtualised_environment = FALSE;
        g_DriverConfig->sys_val_context.active                     = FALSE;

        status = DrvLoadRetrieveDriverNameFromRegistry(RegistryPath);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("DrvLoadRetrieveDriverNameFromRegistry failed with status %x", status);
                DrvUnloadFreeConfigStrings();
                return status;
        }

        status = DrvLoadGatherSystemEnvironmentSettings();

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("GatherSystemEnvironmentSettings failed with status %x", status);
                DrvUnloadFreeConfigStrings();
                return status;
        }

        status = DrvLoadInitialiseObCbConfig();

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("AllocateCallbackStructure failed with status %x", status);
                DrvUnloadFreeConfigStrings();
                return status;
        }

        status = InitialiseTimerObject(&g_DriverConfig->timer);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("InitialiseTimerObject failed with status %x", status);
                DrvUnloadFreeConfigStrings();
                return status;
        }

        DEBUG_VERBOSE("driver name: %s", g_DriverConfig->ansi_driver_name.Buffer);
        return status;
}

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
        BOOLEAN        flag          = FALSE;
        NTSTATUS       status        = STATUS_UNSUCCESSFUL;
        UNICODE_STRING device_name   = RTL_CONSTANT_STRING(L"\\Device\\DonnaAC");
        UNICODE_STRING symbolic_link = RTL_CONSTANT_STRING(L"\\??\\DonnaAC");

        DriverObject->MajorFunction[IRP_MJ_CREATE]         = DeviceCreate;
        DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DeviceClose;
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
        DriverObject->DriverUnload                         = DriverUnload;

        DEBUG_VERBOSE("Beginning driver entry routine...");

        status = IoCreateDevice(DriverObject,
                                sizeof(DRIVER_CONFIG),
                                &device_name,
                                FILE_DEVICE_UNKNOWN,
                                FILE_DEVICE_SECURE_OPEN,
                                FALSE,
                                &DriverObject->DeviceObject);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("IoCreateDevice failed with status %x", status);
                return status;
        }

        g_DriverConfig                = DriverObject->DeviceObject->DeviceExtension;
        g_DriverConfig->driver_object = DriverObject;
        g_DriverConfig->device_object = DriverObject->DeviceObject;

        RtlCopyUnicodeString(&g_DriverConfig->device_name, &device_name);
        RtlCopyUnicodeString(&g_DriverConfig->device_symbolic_link, &symbolic_link);

        /* this needs to be restructured since we leak device object */
        status = ResolveDynamicImports(DriverObject);

        if (!NT_SUCCESS(status))
                return status;

        status = DrvLoadInitialiseDriverConfig(DriverObject, RegistryPath);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("InitialiseDriverConfigOnDriverEntry failed with status %x", status);
                ImpIoDeleteDevice(DriverObject->DeviceObject);
                return status;
        }

        DrvLoadInitialiseReportQueue();
        DrvLoadInitialiseProcessConfig();

        status = IoCreateSymbolicLink(&symbolic_link, &device_name);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("IoCreateSymbolicLink failed with status %x", status);
                DrvUnloadFreeConfigStrings();
                ImpIoDeleteDevice(DriverObject->DeviceObject);
                DrvUnloadFreeTimerObject();
                return STATUS_FAILED_DRIVER_ENTRY;
        }

        status = DrvLoadEnableNotifyRoutines();

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("EnablenotifyRoutines failed with status %x", status);
                DrvUnloadFreeConfigStrings();
                DrvUnloadFreeTimerObject();
                ImpIoDeleteSymbolicLink(&g_DriverConfig->device_symbolic_link);
                ImpIoDeleteDevice(DriverObject->DeviceObject);
                DrvUnloadFreeImportsStructure();
                return STATUS_FAILED_DRIVER_ENTRY;
        }

        status = DrvLoadSetupDriverLists();

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("DrvLoadSetupDriverLists failed with status %x", status);
                DrvUnloadFreeConfigStrings();
                DrvUnloadFreeTimerObject();
                ImpIoDeleteSymbolicLink(&g_DriverConfig->device_symbolic_link);
                ImpIoDeleteDevice(DriverObject->DeviceObject);
                DrvUnloadFreeImportsStructure();
        }

        DEBUG_VERBOSE("Driver Entry Complete.");
        return STATUS_SUCCESS;
}
