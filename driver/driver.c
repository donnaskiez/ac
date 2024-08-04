#include "driver.h"

#include "apc.h"
#include "callbacks.h"
#include "common.h"
#include "crypt.h"
#include "hv.h"
#include "hw.h"
#include "imports.h"
#include "integrity.h"
#include "io.h"
#include "modules.h"
#include "pool.h"
#include "session.h"
#include "thread.h"

#include "lib/stdlib.h"

#include <immintrin.h>

STATIC
VOID
DriverUnload(_In_ PDRIVER_OBJECT DriverObject);

_Function_class_(DRIVER_INITIALIZE) _IRQL_requires_same_
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);

STATIC
NTSTATUS
RegistryPathQueryCallbackRoutine(
    IN PWSTR ValueName,
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
DrvUnloadFreeThreadList();

STATIC
VOID
DrvUnloadFreeProcessList();

STATIC
NTSTATUS
DrvLoadEnableNotifyRoutines();

STATIC
NTSTATUS
DrvLoadInitialiseDriverConfig(
    _In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);

#ifdef ALLOC_PRAGMA
#    pragma alloc_text(INIT, DriverEntry)
#    pragma alloc_text(PAGE, GetDriverName)
#    pragma alloc_text(PAGE, GetDriverPath)
#    pragma alloc_text(PAGE, GetDriverRegistryPath)
#    pragma alloc_text(PAGE, GetDriverDeviceName)
#    pragma alloc_text(PAGE, GetDriverSymbolicLink)
#    pragma alloc_text(PAGE, GetDriverConfigSystemInformation)
#    pragma alloc_text(PAGE, RegistryPathQueryCallbackRoutine)
#    pragma alloc_text(PAGE, DrvUnloadUnregisterObCallbacks)
#    pragma alloc_text(PAGE, DrvUnloadFreeConfigStrings)
#    pragma alloc_text(PAGE, DrvUnloadFreeThreadList)
#    pragma alloc_text(PAGE, DrvLoadEnableNotifyRoutines)
#    pragma alloc_text(PAGE, DrvLoadEnableNotifyRoutines)
#    pragma alloc_text(PAGE, DrvLoadInitialiseDriverConfig)
#endif

typedef struct _DRIVER_CONFIG {
    volatile UINT32 nmi_status;
    UNICODE_STRING unicode_driver_name;
    ANSI_STRING ansi_driver_name;
    PUNICODE_STRING device_name;
    PUNICODE_STRING device_symbolic_link;
    UNICODE_STRING driver_path;
    UNICODE_STRING registry_path;
    SYSTEM_INFORMATION system_information;
    PVOID apc_contexts[MAXIMUM_APC_CONTEXTS];
    PDRIVER_OBJECT driver_object;
    PDEVICE_OBJECT device_object;
    volatile BOOLEAN unload_in_progress;
    KGUARDED_MUTEX lock;
    SYS_MODULE_VAL_CONTEXT sys_val_context;
    IRP_QUEUE_HEAD irp_queue;
    TIMER_OBJECT integrity_check_timer;
    ACTIVE_SESSION session_information;
    RB_TREE thread_tree;
    DRIVER_LIST_HEAD driver_list;
    RTL_HASHMAP process_hashmap;
    SHARED_MAPPING mapping;
    BOOLEAN has_driver_loaded;
    BCRYPT_ALG_HANDLE aes_hash;
    BCRYPT_ALG_HANDLE sha256_hash;
} DRIVER_CONFIG, *PDRIVER_CONFIG;

UNICODE_STRING g_DeviceName = RTL_CONSTANT_STRING(L"\\Device\\DonnaAC");
UNICODE_STRING g_DeviceSymbolicLink = RTL_CONSTANT_STRING(L"\\??\\DonnaAC");

/* xor key generated on driver entry used to encrypt the imports array. Kept in
 * here since imports array is encrypted before the device extension is
 * allocated.*/
__m256i g_ImportsKey;

/* xor key generated that encrypts the DeviceObject->DeviceExtension aswell as
 * our g_DriverConfig pointer. Probably best not to even use the device
 * extension but whatevs */
UINT64 g_DeviceExtensionKey;

/*
 * Rather then getting the driver state from the device object passed to our
 * IOCTL handlers, store a pointer to the device extension here and abstract it
 * with getters which can be accessed globally. The reason for this is because
 * there isnt a way for us to pass a context structure to some of notify
 * routines so I think it's better to do it this way.
 *
 * Note that the device extension pointer should be encrypted
 */
PDRIVER_CONFIG g_DriverConfig = NULL;

/* Its not ideal that this isnt inlined, but it causes errors with the
 * decryption process and subsequently causes deadlocks / invalid pointer errors
 * etc. Will need to look into it.*/
DECLSPEC_NOINLINE
PDRIVER_CONFIG
GetDecryptedDriverConfig()
{
    return (PDRIVER_CONFIG)CryptDecryptPointerOutOfPlace64(
        (PUINT64)&g_DriverConfig,
        g_DeviceExtensionKey);
}

#define POOL_TAG_CONFIG 'conf'

STATIC
VOID
EncryptDeviceExtensionPointers(_In_ PDEVICE_OBJECT DeviceObject)
{
    CryptEncryptPointer64(&g_DriverConfig, g_DeviceExtensionKey);
    CryptEncryptPointer64(&DeviceObject->DeviceExtension, g_DeviceExtensionKey);
}

STATIC
VOID
DecryptDeviceExtensionPointers(_In_ PDEVICE_OBJECT DeviceObject)
{
    CryptDecryptPointer64(&g_DriverConfig, g_DeviceExtensionKey);
    CryptDecryptPointer64(&DeviceObject->DeviceExtension, g_DeviceExtensionKey);
}

PUINT64
GetDriverDeviceExtensionKey()
{
    return &g_DeviceExtensionKey;
}

__m256i*
GetDriverImportsKey()
{
    return &g_ImportsKey;
}

STATIC
VOID
SetDriverLoadedFlag()
{
    PAGED_CODE();
    GetDecryptedDriverConfig()->has_driver_loaded = TRUE;
}

BCRYPT_ALG_HANDLE*
GetCryptHandle_Sha256()
{
    PAGED_CODE();
    return &GetDecryptedDriverConfig()->sha256_hash;
}

PRTL_HASHMAP
GetProcessHashmap()
{
    PAGED_CODE();
    return &GetDecryptedDriverConfig()->process_hashmap;
}

BCRYPT_ALG_HANDLE*
GetCryptHandle_AES()
{
    PAGED_CODE();
    return &GetDecryptedDriverConfig()->aes_hash;
}

BOOLEAN
HasDriverLoaded()
{
    PAGED_CODE();
    return GetDecryptedDriverConfig()->has_driver_loaded;
}

VOID
UnsetNmiInProgressFlag()
{
    PAGED_CODE();
    InterlockedDecrement(&GetDecryptedDriverConfig()->nmi_status);
}

BOOLEAN
IsNmiInProgress()
{
    PAGED_CODE();
    return InterlockedCompareExchange(
               &GetDecryptedDriverConfig()->nmi_status,
               TRUE,
               FALSE) != 0;
}

PSHARED_MAPPING
GetSharedMappingConfig()
{
    PAGED_CODE();
    return &GetDecryptedDriverConfig()->mapping;
}

VOID
AcquireDriverConfigLock()
{
    PAGED_CODE();
    ImpKeAcquireGuardedMutex(&GetDecryptedDriverConfig()->lock);
}

VOID
ReleaseDriverConfigLock()
{
    PAGED_CODE();
    ImpKeReleaseGuardedMutex(&GetDecryptedDriverConfig()->lock);
}

PUINT64
GetApcContextArray()
{
    PAGED_CODE();
    return (PUINT64)GetDecryptedDriverConfig()->apc_contexts;
}

BOOLEAN
IsDriverUnloading()
{
    PAGED_CODE();
    return InterlockedExchange(
        &GetDecryptedDriverConfig()->unload_in_progress,
        GetDecryptedDriverConfig()->unload_in_progress);
}

PACTIVE_SESSION
GetActiveSession()
{
    PAGED_CODE();
    return &GetDecryptedDriverConfig()->session_information;
}

LPCSTR
GetDriverName()
{
    PAGED_CODE();
    return GetDecryptedDriverConfig()->ansi_driver_name.Buffer;
}

PDEVICE_OBJECT
GetDriverDeviceObject()
{
    PAGED_CODE();
    return GetDecryptedDriverConfig()->device_object;
}

PDRIVER_OBJECT
GetDriverObject()
{
    PAGED_CODE();
    return GetDecryptedDriverConfig()->driver_object;
}

PIRP_QUEUE_HEAD
GetIrpQueueHead()
{
    PAGED_CODE();
    return &GetDecryptedDriverConfig()->irp_queue;
}

PSYS_MODULE_VAL_CONTEXT
GetSystemModuleValidationContext()
{
    PAGED_CODE();
    return &GetDecryptedDriverConfig()->sys_val_context;
}

PUNICODE_STRING
GetDriverPath()
{
    PAGED_CODE();
    return &GetDecryptedDriverConfig()->driver_path;
}

PUNICODE_STRING
GetDriverRegistryPath()
{
    PAGED_CODE();
    return &GetDecryptedDriverConfig()->registry_path;
}

PUNICODE_STRING
GetDriverDeviceName()
{
    PAGED_CODE();
    return &GetDecryptedDriverConfig()->device_name;
}

PUNICODE_STRING
GetDriverSymbolicLink()
{
    PAGED_CODE();
    return &GetDecryptedDriverConfig()->device_symbolic_link;
}

PSYSTEM_INFORMATION
GetDriverConfigSystemInformation()
{
    PAGED_CODE();
    return &GetDecryptedDriverConfig()->system_information;
}

PRB_TREE
GetThreadTree()
{
    PAGED_CODE();
    return &GetDecryptedDriverConfig()->thread_tree;
}

PDRIVER_LIST_HEAD
GetDriverList()
{
    PAGED_CODE();
    return &GetDecryptedDriverConfig()->driver_list;
}

/*
 * The question is, What happens if we attempt to register our callbacks after
 * we unregister them but before we free the pool? Hm.. No Good.
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

    PDRIVER_CONFIG cfg = GetDecryptedDriverConfig();

    if (cfg->unicode_driver_name.Buffer)
        ImpExFreePoolWithTag(cfg->unicode_driver_name.Buffer, POOL_TAG_STRINGS);

    if (cfg->driver_path.Buffer)
        ImpExFreePoolWithTag(cfg->driver_path.Buffer, POOL_TAG_STRINGS);

    if (cfg->ansi_driver_name.Buffer)
        ImpRtlFreeAnsiString(&cfg->ansi_driver_name);
}

STATIC
VOID
DrvUnloadDeleteSymbolicLink()
{
    if (GetDecryptedDriverConfig()->device_symbolic_link)
        ImpIoDeleteSymbolicLink(
            GetDecryptedDriverConfig()->device_symbolic_link);
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
    CleanupDriverTimerObjects(
        &GetDecryptedDriverConfig()->integrity_check_timer);
}

STATIC
VOID
DrvUnloadFreeProcessList()
{
    PAGED_CODE();
    CleanupProcessHashmap();
}

STATIC
VOID
DrvUnloadFreeModuleValidationContext()
{
    PAGED_CODE();
    CleanupValidationContextOnUnload(
        &GetDecryptedDriverConfig()->sys_val_context);
}

STATIC
VOID
CloseHashingAlgorithmProvider()
{
    BCRYPT_ALG_HANDLE* handle = GetCryptHandle_Sha256();
    BCryptCloseAlgorithmProvider(*handle, 0);
}

STATIC
VOID
DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    DEBUG_VERBOSE("Unloading...");

    InterlockedExchange(&GetDecryptedDriverConfig()->unload_in_progress, TRUE);

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

    CryptCloseProvider();
    CloseHashingAlgorithmProvider();

    DrvUnloadFreeConfigStrings();
    DrvUnloadDeleteSymbolicLink();

    DecryptDeviceExtensionPointers(DriverObject->DeviceObject);
    ImpIoDeleteDevice(DriverObject->DeviceObject);

    DEBUG_INFO("Driver successfully unloaded.");
}

STATIC
NTSTATUS
DrvLoadEnableNotifyRoutines()
{
    PAGED_CODE();

    NTSTATUS status = STATUS_UNSUCCESSFUL;

    DEBUG_VERBOSE("Enabling driver wide notify routines.");

    status = PsSetLoadImageNotifyRoutine(ImageLoadNotifyRoutineCallback);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR(
            "PsSetLoadImageNotifyRoutine failed with status %x",
            status);
        return status;
    }

    status = ImpPsSetCreateThreadNotifyRoutine(ThreadCreateNotifyRoutine);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR(
            "PsSetCreateThreadNotifyRoutine failed with status %x",
            status);
        PsRemoveLoadImageNotifyRoutine(ImageLoadNotifyRoutineCallback);
        return status;
    }

    status =
        ImpPsSetCreateProcessNotifyRoutine(ProcessCreateNotifyRoutine, FALSE);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR(
            "PsSetCreateProcessNotifyRoutine failed with status %x",
            status);
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

    if (!NT_SUCCESS(status)) {
        UnregisterProcessCreateNotifyRoutine();
        UnregisterThreadCreateNotifyRoutine();
        UnregisterImageLoadNotifyRoutine();
        DEBUG_ERROR("InitialiseDriverList failed with status %x", status);
        return status;
    }

    status = InitialiseThreadList();

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("InitialiseThreadList failed with status %x", status);
        UnregisterProcessCreateNotifyRoutine();
        UnregisterThreadCreateNotifyRoutine();
        UnregisterImageLoadNotifyRoutine();
        CleanupDriverListOnDriverUnload();
        return status;
    }

    status = InitialiseProcessHashmap();

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("InitialiseProcessList failed with status %x", status);
        UnregisterProcessCreateNotifyRoutine();
        UnregisterThreadCreateNotifyRoutine();
        UnregisterImageLoadNotifyRoutine();
        CleanupDriverListOnDriverUnload();
        CleanupThreadListOnDriverUnload();
        return status;
    }

    return status;
}

/*
 * Regular routines
 */

STATIC
NTSTATUS
RegistryPathQueryCallbackRoutine(
    IN PWSTR ValueName,
    IN ULONG ValueType,
    IN PVOID ValueData,
    IN ULONG ValueLength,
    IN PVOID Context,
    IN PVOID EntryContext)
{
    PAGED_CODE();

    UNICODE_STRING value_name = {0};
    UNICODE_STRING image_path = RTL_CONSTANT_STRING(L"ImagePath");
    UNICODE_STRING display_name = RTL_CONSTANT_STRING(L"DisplayName");
    UNICODE_STRING value = {0};
    PVOID temp_buffer = NULL;

    ImpRtlInitUnicodeString(&value_name, ValueName);

    PDRIVER_CONFIG cfg = GetDecryptedDriverConfig();

    if (ImpRtlCompareUnicodeString(&value_name, &image_path, FALSE) == FALSE) {
        temp_buffer =
            ImpExAllocatePool2(POOL_FLAG_PAGED, ValueLength, POOL_TAG_STRINGS);

        if (!temp_buffer)
            return STATUS_MEMORY_NOT_ALLOCATED;

        IntCopyMemory(temp_buffer, ValueData, ValueLength);

        cfg->driver_path.Buffer = (PWCH)temp_buffer;
        cfg->driver_path.Length = ValueLength;
        cfg->driver_path.MaximumLength = ValueLength;
    }

    if (ImpRtlCompareUnicodeString(&value_name, &display_name, FALSE) ==
        FALSE) {
        temp_buffer = ImpExAllocatePool2(
            POOL_FLAG_PAGED,
            ValueLength + 20,
            POOL_TAG_STRINGS);

        if (!temp_buffer)
            return STATUS_MEMORY_NOT_ALLOCATED;

        IntCopyMemory(temp_buffer, ValueData, ValueLength);
        IntWideStringCopy(
            (PWCH)((UINT64)temp_buffer + ValueLength - 2),
            L".sys");

        cfg->unicode_driver_name.Buffer = (PWCH)temp_buffer;
        cfg->unicode_driver_name.Length = ValueLength + 20;
        cfg->unicode_driver_name.MaximumLength = ValueLength + 20;
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
    PDRIVER_CONFIG cfg = GetDecryptedDriverConfig();

    __cpuid(cpuid, 0);

    DEBUG_VERBOSE(
        "Cpuid: EBX: %lx, ECX: %lx, EDX: %lx",
        cpuid[1],
        cpuid[2],
        cpuid[3]);

    if (cpuid[EBX_REGISTER] == CPUID_AUTHENTIC_AMD_EBX &&
        cpuid[ECX_REGISTER] == CPUID_AUTHENTIC_AMD_ECX &&
        cpuid[EDX_REGISTER] == CPUID_AUTHENTIC_AMD_EDX) {
        cfg->system_information.processor = AuthenticAmd;
        return STATUS_SUCCESS;
    }
    else if (
        cpuid[EBX_REGISTER] == CPUID_GENUINE_INTEL_EBX &&
        cpuid[ECX_REGISTER] == CPUID_GENUINE_INTEL_ECX &&
        cpuid[EDX_REGISTER] == CPUID_GENUINE_INTEL_EDX) {
        cfg->system_information.processor = GenuineIntel;
        return STATUS_SUCCESS;
    }
    else {
        cfg->system_information.processor = Unknown;
        return STATUS_UNSUCCESSFUL;
    }
}

/*
 * Even though we are technically not meant to be operating when running under a
 * virtualized system, it is still useful to test the attainment of system
 * information under a virtualized system for testing purposes.
 */
STATIC
NTSTATUS
ParseSmbiosForGivenSystemEnvironment()
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PDRIVER_CONFIG cfg = GetDecryptedDriverConfig();

    status = ParseSMBIOSTable(
        &cfg->system_information.vendor,
        VENDOR_STRING_MAX_LENGTH,
        SmbiosInformation,
        SMBIOS_VENDOR_STRING_SUB_INDEX);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ParseSMBIOSTable failed with status %x", status);
        return status;
    }

    if (IntFindSubstring(&cfg->system_information.vendor, "VMware, Inc"))
        cfg->system_information.environment = Vmware;
    else if (IntFindSubstring(&cfg->system_information.vendor, "innotek GmbH"))
        cfg->system_information.environment = VirtualBox;
    else
        cfg->system_information.environment = NativeWindows;

    switch (cfg->system_information.environment) {
    case NativeWindows: {
        status = ParseSMBIOSTable(
            &cfg->system_information.motherboard_serial,
            MOTHERBOARD_SERIAL_CODE_LENGTH,
            VendorSpecificInformation,
            SMBIOS_NATIVE_SERIAL_NUMBER_SUB_INDEX);
        break;
    }
    case Vmware: {
        status = ParseSMBIOSTable(
            &cfg->system_information.motherboard_serial,
            MOTHERBOARD_SERIAL_CODE_LENGTH,
            SystemInformation,
            SMBIOS_VMWARE_SERIAL_NUMBER_SUB_INDEX);
        break;
    }
    case VirtualBox:
    default:
        DEBUG_WARNING("Environment type not supported.");
        return STATUS_NOT_SUPPORTED;
    }

    if (!NT_SUCCESS(status)) {
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
    PDRIVER_CONFIG cfg = GetDecryptedDriverConfig();

    if (APERFMsrTimingCheck())
        cfg->system_information.virtualised_environment = TRUE;

    status = GetOsVersionInformation(&cfg->system_information.os_information);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("GetOsVersionInformation failed with status %x", status);
        return status;
    }

    status = GetSystemProcessorType();

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("GetSystemProcessorType failed with status %x", status);
        return status;
    }

    status = ParseSmbiosForGivenSystemEnvironment();

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR(
            "ParseSmbiosForGivenSystemEnvironment failed with status %x",
            status);
        return status;
    }

    status = GetHardDiskDriveSerialNumber(
        &cfg->system_information.drive_0_serial,
        sizeof(cfg->system_information.drive_0_serial));

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR(
            "GetHardDiskDriverSerialNumber failed with status %x",
            status);
        return status;
    }

    DEBUG_VERBOSE(
        "OS Major Version: %lx, Minor Version: %lx, Build Number: %lx",
        cfg->system_information.os_information.dwMajorVersion,
        cfg->system_information.os_information.dwMinorVersion,
        cfg->system_information.os_information.dwBuildNumber);
    DEBUG_VERBOSE("Environment type: %lx", cfg->system_information.environment);
    DEBUG_VERBOSE("Processor type: %lx", cfg->system_information.processor);
    DEBUG_VERBOSE(
        "Motherboard serial: %s",
        cfg->system_information.motherboard_serial);
    DEBUG_VERBOSE("Drive 0 serial: %s", cfg->system_information.drive_0_serial);

    return status;
}

STATIC
NTSTATUS
DrvLoadRetrieveDriverNameFromRegistry(_In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PDRIVER_CONFIG cfg = GetDecryptedDriverConfig();
    RTL_QUERY_REGISTRY_TABLE query[3] = {0};

    query[0].Flags = RTL_QUERY_REGISTRY_NOEXPAND;
    query[0].Name = L"ImagePath";
    query[0].DefaultType = REG_MULTI_SZ;
    query[0].DefaultLength = 0;
    query[0].DefaultData = NULL;
    query[0].EntryContext = NULL;
    query[0].QueryRoutine = RegistryPathQueryCallbackRoutine;

    query[1].Flags = RTL_QUERY_REGISTRY_NOEXPAND;
    query[1].Name = L"DisplayName";
    query[1].DefaultType = REG_SZ;
    query[1].DefaultLength = 0;
    query[1].DefaultData = NULL;
    query[1].EntryContext = NULL;
    query[1].QueryRoutine = RegistryPathQueryCallbackRoutine;

    status = RtlxQueryRegistryValues(
        RTL_REGISTRY_ABSOLUTE,
        RegistryPath->Buffer,
        &query,
        NULL,
        NULL);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("RtlxQueryRegistryValues failed with status %x", status);
        return status;
    }

    /*
     * The registry path contains the name of the driver i.e Driver, but
     * does not contain the .sys extension. Lets add it to our stored driver
     * name since we need the .sys extension when querying the system
     * modules for our driver.
     */
    status = ImpRtlUnicodeStringToAnsiString(
        &cfg->ansi_driver_name,
        &cfg->unicode_driver_name,
        TRUE);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR(
            "RtlUnicodeStringToAnsiString failed with status %x",
            status);
    }

    return status;
}

STATIC
NTSTATUS
DrvLoadInitialiseDriverConfig(
    _In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    PAGED_CODE();
    DEBUG_VERBOSE("Initialising driver configuration");

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PDRIVER_CONFIG cfg = GetDecryptedDriverConfig();

    ImpKeInitializeGuardedMutex(&cfg->lock);

    IrpQueueInitialise();
    SessionInitialiseCallbackConfiguration();

    cfg->unload_in_progress = FALSE;
    cfg->system_information.virtualised_environment = FALSE;
    cfg->sys_val_context.active = FALSE;

    status = DrvLoadRetrieveDriverNameFromRegistry(RegistryPath);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR(
            "DrvLoadRetrieveDriverNameFromRegistry failed with status %x",
            status);
        return status;
    }

    /* when this function failed, we bugcheck in freeconfigstrings todo: fix */
    status = DrvLoadGatherSystemEnvironmentSettings();

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR(
            "GatherSystemEnvironmentSettings failed with status %x",
            status);
        return status;
    }

    status = InitialiseTimerObject(&cfg->integrity_check_timer);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("InitialiseTimerObject failed with status %x", status);
        return status;
    }

    status = IrpQueueInitialise();

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("IrpQueueInitialise failed with status %x", status);
        return status;
    }

    DEBUG_VERBOSE("driver name: %s", cfg->ansi_driver_name.Buffer);
    return status;
}

STATIC
NTSTATUS
InitialiseHashingAlgorithmProvider()
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BCRYPT_ALG_HANDLE* handle = GetCryptHandle_Sha256();

    status = BCryptOpenAlgorithmProvider(
        handle,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        BCRYPT_PROV_DISPATCH);

    if (!NT_SUCCESS(status))
        DEBUG_ERROR("BCryptOpenAlgorithmProvider: %x", status);

    return status;
}

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    BOOLEAN flag = FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    g_DeviceExtensionKey = CryptXorKeyGenerate_uint64();

    status = ImpResolveDynamicImports(DriverObject);

    if (!NT_SUCCESS(status))
        return STATUS_FAILED_DRIVER_ENTRY;

    DEBUG_VERBOSE("Beginning driver entry routine...");

    status = ImpIoCreateDevice(
        DriverObject,
        sizeof(DRIVER_CONFIG),
        &g_DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &DriverObject->DeviceObject);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("IoCreateDevice failed with status %x", status);
        return status;
    }

    g_DriverConfig = DriverObject->DeviceObject->DeviceExtension;
    g_DriverConfig->device_object = DriverObject->DeviceObject;
    g_DriverConfig->driver_object = DriverObject;
    g_DriverConfig->device_name = &g_DeviceName;
    g_DriverConfig->device_symbolic_link = &g_DeviceSymbolicLink;

    EncryptDeviceExtensionPointers(DriverObject->DeviceObject);

    status = DrvLoadInitialiseDriverConfig(DriverObject, RegistryPath);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR(
            "InitialiseDriverConfigOnDriverEntry failed with status %x",
            status);
        DrvUnloadFreeConfigStrings();
        ImpIoDeleteDevice(GetDecryptedDriverConfig()->device_object);
        return status;
    }

    status = SessionInitialiseStructure();

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("SessionInitialiseStructure failed with status %x", status);
        DrvUnloadFreeConfigStrings();
        DrvUnloadFreeTimerObject();
        ImpIoDeleteDevice(GetDecryptedDriverConfig()->device_object);
        return status;
    }

    status = IoCreateSymbolicLink(
        GetDecryptedDriverConfig()->device_symbolic_link,
        GetDecryptedDriverConfig()->device_name);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("IoCreateSymbolicLink failed with status %x", status);
        DrvUnloadFreeConfigStrings();
        DrvUnloadFreeTimerObject();
        ImpIoDeleteDevice(GetDecryptedDriverConfig()->device_object);
        return status;
    }

    status = DrvLoadEnableNotifyRoutines();

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("EnablenotifyRoutines failed with status %x", status);
        DrvUnloadFreeConfigStrings();
        DrvUnloadFreeTimerObject();
        DrvUnloadDeleteSymbolicLink();
        ImpIoDeleteDevice(GetDecryptedDriverConfig()->device_object);
        return status;
    }

    status = InitialiseHashingAlgorithmProvider();

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR(
            "InitialiseHashingAlgorithmProvider failed with status %x",
            status);
        DrvUnloadFreeConfigStrings();
        DrvUnloadFreeTimerObject();
        DrvUnloadDeleteSymbolicLink();
        ImpIoDeleteDevice(GetDecryptedDriverConfig()->device_object);
        return status;
    }

    status = DrvLoadSetupDriverLists();

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("DrvLoadSetupDriverLists failed with status %x", status);
        CloseHashingAlgorithmProvider();
        DrvUnloadFreeConfigStrings();
        DrvUnloadFreeTimerObject();
        DrvUnloadDeleteSymbolicLink();
        ImpIoDeleteDevice(GetDecryptedDriverConfig()->device_object);
        return status;
    }

    SetDriverLoadedFlag();
    TpmExtractEndorsementKey();
    //PoolScanForManualMappedDrivers();

    DEBUG_INFO("Driver Entry Complete.");
    return STATUS_SUCCESS;
}
