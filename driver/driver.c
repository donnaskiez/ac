#include "driver.h"

#include "common.h"
#include "ioctl.h"
#include "callbacks.h"

#include "hv.h"
#include "pool.h"
#include "thread.h"
#include "modules.h"
#include "integrity.h"

STATIC 
NTSTATUS 
AllocateCallbackStructure();

STATIC 
VOID 
CleanupDriverCallbacksOnDriverUnload();

STATIC 
VOID 
FreeDriverConfigurationStringBuffers();

STATIC 
BOOLEAN 
FreeAllApcContextStructures();

STATIC 
VOID 
InitialiseProcessConfigOnDriverEntry();

STATIC 
VOID 
CleanupDriverConfigOnUnload();

STATIC 
VOID 
DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject);

STATIC 
NTSTATUS 
InitialiseDriverConfigOnDriverEntry(
	_In_ PUNICODE_STRING RegistryPath);

NTSTATUS 
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject, 
	_In_ PUNICODE_STRING RegistryPath);

STATIC 
NTSTATUS RegistryPathQueryCallbackRoutine(
	IN PWSTR ValueName,
	IN ULONG ValueType,
	IN PVOID ValueData,
	IN ULONG ValueLength,
	IN PVOID Context,
	IN PVOID EntryContext);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, EnableCallbackRoutinesOnProcessRun)
#pragma alloc_text(PAGE, AllocateCallbackStructure)
#pragma alloc_text(PAGE, UnregisterCallbacksOnProcessTermination)
#pragma alloc_text(PAGE, CleanupDriverCallbacksOnDriverUnload)
#pragma alloc_text(PAGE, GetCallbackConfigStructure)
#pragma alloc_text(PAGE, InsertApcContext)
#pragma alloc_text(PAGE, GetApcContext)
#pragma alloc_text(PAGE, GetApcContextByIndex)
#pragma alloc_text(PAGE, ReadProcessInitialisedConfigFlag)
#pragma alloc_text(PAGE, GetProtectedProcessEProcess)
#pragma alloc_text(PAGE, GetProtectedProcessId)
#pragma alloc_text(PAGE, ClearProcessConfigOnProcessTermination)
#pragma alloc_text(PAGE, GetDriverName)
#pragma alloc_text(PAGE, GetDriverPath)
#pragma alloc_text(PAGE, GetDriverRegistryPath)
#pragma alloc_text(PAGE, GetDriverDeviceName)
#pragma alloc_text(PAGE, GetDriverSymbolicLink)
#pragma alloc_text(PAGE, GetDriverConfigSystemInformation)
#pragma alloc_text(PAGE, RegistryPathQueryCallbackRoutine)
#pragma alloc_text(PAGE, FreeDriverConfigurationStringBuffers)
#pragma alloc_text(PAGE, InitialiseDriverConfigOnDriverEntry)
#pragma alloc_text(PAGE, InitialiseProcessConfigOnProcessLaunch)
#pragma alloc_text(PAGE, InitialiseProcessConfigOnDriverEntry)
#pragma alloc_text(PAGE, CleanupDriverConfigOnUnload)
#pragma alloc_text(PAGE, DriverUnload)
#pragma alloc_text(PAGE, TerminateProtectedProcessOnViolation)
#endif

#define MAXIMUM_APC_CONTEXTS 10

typedef struct _DRIVER_CONFIG
{
	UNICODE_STRING unicode_driver_name;
	ANSI_STRING ansi_driver_name;
	UNICODE_STRING device_name;
	UNICODE_STRING device_symbolic_link;
	UNICODE_STRING driver_path;
	UNICODE_STRING registry_path;
	SYSTEM_INFORMATION system_information;
	PVOID apc_contexts[MAXIMUM_APC_CONTEXTS];
	CALLBACK_CONFIGURATION callback_config;
	KGUARDED_MUTEX lock;

}DRIVER_CONFIG, * PDRIVER_CONFIG;

/*
* This structure can change at anytime based on whether
* the target process to protect is open / closed / changes etc.
*/
typedef struct _PROCESS_CONFIG
{
	BOOLEAN initialised;
	LONG um_handle;
	LONG km_handle;
	PEPROCESS protected_process_eprocess;
	KGUARDED_MUTEX lock;

}PROCESS_CONFIG, * PPROCESS_CONFIG;

DRIVER_CONFIG driver_config = { 0 };
PROCESS_CONFIG process_config = { 0 };

#define POOL_TAG_CONFIG 'conf'

/*
* The CALLBACKS_CONFIGURATION structure was being paged out, aswell as enabling a race condition
* to occur by being encapsulated in the callbacks.c file, so to solve both these problems I have moved
* them here. This way, we can make use of both locks (which is very ugly and I am pretty sure means
* I have made a mistake implementation wise but alas) ensuring we get rid of any race conditions
* aswell as the sturcture being paged out as we allocate in a non-paged pool meaning theres no
* chance our mutex will cause an IRQL bug check due to being paged out during acquisition.
*/
NTSTATUS
EnableCallbackRoutinesOnProcessRun()
{
	NTSTATUS status;

	KeAcquireGuardedMutex(&driver_config.lock);

	OB_CALLBACK_REGISTRATION callback_registration = { 0 };
	OB_OPERATION_REGISTRATION operation_registration = { 0 };
	PCREATE_PROCESS_NOTIFY_ROUTINE_EX notify_routine = { 0 };

	operation_registration.ObjectType = PsProcessType;
	operation_registration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	operation_registration.PreOperation = ObPreOpCallbackRoutine;
	operation_registration.PostOperation = ObPostOpCallbackRoutine;

	callback_registration.Version = OB_FLT_REGISTRATION_VERSION;
	callback_registration.OperationRegistration = &operation_registration;
	callback_registration.OperationRegistrationCount = 1;
	callback_registration.RegistrationContext = NULL;

	status = ObRegisterCallbacks(
		&callback_registration,
		&driver_config.callback_config.registration_handle
	);

	if (!NT_SUCCESS(status))
	{
		DEBUG_ERROR("failed to launch obregisters with status %x", status);
		goto end;
	}

	//status = PsSetCreateProcessNotifyRoutine(
	//	ProcessCreateNotifyRoutine,
	//	FALSE
	//);

	//if ( !NT_SUCCESS( status ) )
	//	DEBUG_ERROR( "Failed to launch ps create notif routines with status %x", status );

end:
	KeReleaseGuardedMutex(&driver_config.lock);
	return status;
}

STATIC
NTSTATUS
EnableCallbackRoutinesOnDriverEntry()
{
	NTSTATUS status;

	status = InitialiseThreadList();

	if (!NT_SUCCESS(status))
	{
		DEBUG_ERROR("InitialiseThreadList failed with status %x", status);
		return status;
	}

	status = PsSetCreateThreadNotifyRoutine(ThreadCreateNotifyRoutine);

	if (!NT_SUCCESS(status))
		DEBUG_ERROR("PsSetCreateProcessNotifyRoutine failed with status %x", status);

	return status;
}

STATIC
NTSTATUS
AllocateCallbackStructure()
{
	/*
	* This mutex ensures we don't unregister our ObRegisterCallbacks while
	* the callback function is running since this might cause some funny stuff
	* to happen. Better to be safe then sorry :)
	*/
	KeInitializeGuardedMutex(&driver_config.callback_config.lock);
}

VOID
UnregisterCallbacksOnProcessTermination()
{
	KeAcquireGuardedMutex(&driver_config.callback_config.lock);

	if (driver_config.callback_config.registration_handle)
	{
		ObUnRegisterCallbacks(driver_config.callback_config.registration_handle);
		driver_config.callback_config.registration_handle = NULL;
	}

	KeReleaseGuardedMutex(&driver_config.callback_config.lock);
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
CleanupDriverCallbacksOnDriverUnload()
{
	UnregisterCallbacksOnProcessTermination();
}

/*
* Can return a null value if we attempt to read the value is underway whilst we are 
* freeing the structure, hence the use of the 2 locks.
*/
VOID
GetCallbackConfigStructure(
	_Out_ PCALLBACK_CONFIGURATION* CallbackConfiguration
)
{
	if (!CallbackConfiguration)
		return;

	*CallbackConfiguration = NULL;
	KeAcquireGuardedMutex(&driver_config.lock);
	*CallbackConfiguration = &driver_config.callback_config;
	KeReleaseGuardedMutex(&driver_config.lock);
}

/*
* The driver config structure holds an array of pointers to APC context structures. These
* APC context structures are unique to each APC operation that this driver will perform. For
* example, a single context will manage all APCs that are used to stackwalk, whilst another
* context will be used to manage all APCs used to query a threads memory for example.
*
* Due to the nature of APCs, its important to keep a total or count of the number of APCs we
* have allocated and queued to threads. This information is stored in the APC_CONTEXT_HEADER which
* all APC context structures will contain as the first entry in their structure. It holds the ContextId
* which is a unique identifier for the type of APC operation it is managing aswell as the number of
* currently queued APCs.
*
* When an APC is allocated a queued, we increment this count. When an APC is completed and freed, we
* decrement this counter and free the APC itself. If all APCs have been freed and the counter is 0,the
* following objects will be freed:
*
* 1. Any additional allocations used by the APC stored in the context structure
* 2. The APC context structure for the given APC operation
* 3. The APC context entry in driver_config->apc_contexts will be zero'd.
*
* It's important to remember that the driver can unload when pending APC's have not been freed due to the
* limitations windows places on APCs, however I am in the process of finding a solution for this.
*/

STATIC
BOOLEAN
FreeAllApcContextStructures()
{
	BOOLEAN flag = TRUE;

	KeAcquireGuardedMutex(&driver_config.lock);

	for (INT index = 0; index < MAXIMUM_APC_CONTEXTS; index++)
	{
		PUINT64 entry = driver_config.apc_contexts;

		if (entry[index] != NULL)
		{
			PAPC_CONTEXT_HEADER context = entry[index];

			if (context->count > 0)
			{
				flag = FALSE;
				goto unlock;
			}

			ExFreePoolWithTag(entry, POOL_TAG_APC);
		}
	}

unlock:
	KeReleaseGuardedMutex(&driver_config.lock);
	return flag;
}

/*
* No need to hold the lock here as the thread freeing the APCs will
* already hold the configuration lock. We also dont want to release and
* reclaim the lock before calling this function since we need to ensure
* we hold the lock during the entire decrement and free process.
*/
STATIC
BOOLEAN
FreeApcContextStructure(
	_Inout_ PAPC_CONTEXT_HEADER Context
)
{
	BOOLEAN result = FALSE;

	DEBUG_LOG("All APCs executed, freeing context structure");

	for (INT index = 0; index < MAXIMUM_APC_CONTEXTS; index++)
	{
		PUINT64 entry = driver_config.apc_contexts;

		if (entry[index] == Context)
		{
			if (Context->count != 0)
				goto unlock;

			ExFreePoolWithTag(Context, POOL_TAG_APC);
			entry[index] = NULL;
			result = TRUE;
			goto unlock;
		}
	}

unlock:
	return result;
}

VOID
IncrementApcCount(
	_In_ LONG ContextId
)
{
	PAPC_CONTEXT_HEADER header = NULL;
	GetApcContext(&header, ContextId);

	if (!header)
		return;

	KeAcquireGuardedMutex(&driver_config.lock);
	header->count += 1;
	KeReleaseGuardedMutex(&driver_config.lock);
}

VOID
FreeApcAndDecrementApcCount(
	_Inout_ PRKAPC Apc,
	_In_ LONG ContextId
)
{
	PAPC_CONTEXT_HEADER context = NULL;
	ExFreePoolWithTag(Apc, POOL_TAG_APC);
	GetApcContext(&context, ContextId);

	if (!context)
		goto end;

	KeAcquireGuardedMutex(&driver_config.lock);
	context->count -= 1;
end:
	KeReleaseGuardedMutex(&driver_config.lock);
}

/*
* The reason we use a query model rather then checking the count of queued APCs
* after each APC free and decrement is that the lock will be recursively acquired by
* freeing threads (i.e executing APCs) rather then APC allocation threads. The reason for this
* being that freeing threads are executing at a higher IRQL then the APC allocation
* thread, hence they are granted higher priority by the scheduler when determining
* which thread will accquire the lock next:
*
* [+] Freeing thread -> ApcKernelRoutine IRQL: 1 (APC_LEVEL)
* [+] Allocation thread -> ValidateThreadViaKernelApcCallback IRQL: 0 (PASSIVE_LEVEL)
*
* As a result, once an APC is executed and reaches the freeing stage, it will acquire the
* lock and decrement it. Then, if atleast 1 APC execution thread is waiting on the lock,
* it will be prioritised due to its higher IRQL and the cycle will continue. Eventually,
* the count will reach 0 due to recursive acquisition by the executing APC threads and then
* the function will free the APC context structure. This will then cause a bug check the next
* time a thread accesses the context structure and hence not good :c.
*
* So to combat this, we add in a flag specifying whether or not an allocation of APCs is
* in progress, and even if the count is 0 we will not free the context structure until
* the count is 0 and allocation_in_progress is 0. We can then call this function alongside
* other query callbacks via IOCTL to constantly monitor the status of open APC contexts.
*/
NTSTATUS
QueryActiveApcContextsForCompletion()
{
	for (INT index = 0; index < MAXIMUM_APC_CONTEXTS; index++)
	{
		PAPC_CONTEXT_HEADER entry = NULL;
		GetApcContextByIndex(&entry, index);

		/* acquire mutex after we get the context to prevent thread deadlock */
		KeAcquireGuardedMutex(&driver_config.lock);

		if (entry == NULL)
		{
			KeReleaseGuardedMutex(&driver_config.lock);
			continue;
		}

		DEBUG_LOG("APC Context Id: %lx", entry->context_id);
		DEBUG_LOG("Active APC Count: %i", entry->count);

		if (entry->count > 0 || entry->allocation_in_progress == TRUE)
		{
			KeReleaseGuardedMutex(&driver_config.lock);
			continue;
		}

		switch (entry->context_id)
		{
		case APC_CONTEXT_ID_STACKWALK:
			FreeApcStackwalkApcContextInformation(entry);
			FreeApcContextStructure(entry);
			break;
		}

		KeReleaseGuardedMutex(&driver_config.lock);

	}
	return STATUS_SUCCESS;
}

VOID
InsertApcContext(
	_In_ PVOID Context
)
{
	KeAcquireGuardedMutex(&driver_config.lock);

	PAPC_CONTEXT_HEADER header = Context;

	for (INT index = 0; index < MAXIMUM_APC_CONTEXTS; index++)
	{
		PUINT64 entry = driver_config.apc_contexts;

		if (entry[index] == NULL)
		{
			entry[index] = Context;
			goto end;
		}
	}
end:
	KeReleaseGuardedMutex(&driver_config.lock);
}

VOID
GetApcContext(
	_Inout_ PVOID* Context,
	_In_ LONG ContextIdentifier
)
{
	KeAcquireGuardedMutex(&driver_config.lock);

	for (INT index = 0; index < MAXIMUM_APC_CONTEXTS; index++)
	{
		PAPC_CONTEXT_HEADER header = driver_config.apc_contexts[index];

		if (header == NULL)
			continue;

		if (header->context_id == ContextIdentifier)
		{
			*Context = header;
			goto unlock;
		}
	}

unlock:
	KeReleaseGuardedMutex(&driver_config.lock);
}

VOID
GetApcContextByIndex(
	_Inout_ PVOID* Context,
	_In_ INT Index
)
{
	if (!Context)
		return;

	*Context = NULL;
	KeAcquireGuardedMutex(&driver_config.lock);
	*Context = driver_config.apc_contexts[Index];
	KeReleaseGuardedMutex(&driver_config.lock);
}

VOID
ReadProcessInitialisedConfigFlag(
	_Out_ PBOOLEAN Flag
)
{
	if (Flag == NULL)
		return;

	KeAcquireGuardedMutex(&process_config.lock);
	*Flag = process_config.initialised;
	KeReleaseGuardedMutex(&process_config.lock);
}

VOID
GetProtectedProcessEProcess(
	_Out_ PEPROCESS* Process
)
{
	if (Process == NULL)
		return;

	*Process = NULL;
	KeAcquireGuardedMutex(&process_config.lock);
	*Process = process_config.protected_process_eprocess;
	KeReleaseGuardedMutex(&process_config.lock);
}

VOID
GetProtectedProcessId(
	_Out_ PLONG ProcessId
)
{
	KeAcquireGuardedMutex(&process_config.lock);
	RtlZeroMemory(ProcessId, sizeof(LONG));
	*ProcessId = process_config.km_handle;
	KeReleaseGuardedMutex(&process_config.lock);
}

VOID
ClearProcessConfigOnProcessTermination()
{
	DEBUG_LOG("Process closed, clearing driver process_configuration");
	KeAcquireGuardedMutex(&process_config.lock);
	process_config.km_handle = NULL;
	process_config.um_handle = NULL;
	process_config.protected_process_eprocess = NULL;
	process_config.initialised = FALSE;
	KeReleaseGuardedMutex(&process_config.lock);
}

VOID
GetDriverName(
	_Out_ LPCSTR* DriverName
)
{
	if (DriverName == NULL)
		return;

	*DriverName = NULL;
	KeAcquireGuardedMutex(&driver_config.lock);
	*DriverName = driver_config.ansi_driver_name.Buffer;
	KeReleaseGuardedMutex(&driver_config.lock);
}

VOID
GetDriverPath(
	_Out_ PUNICODE_STRING DriverPath
)
{
	KeAcquireGuardedMutex(&driver_config.lock);
	RtlZeroMemory(DriverPath, sizeof(UNICODE_STRING));
	RtlInitUnicodeString(DriverPath, driver_config.driver_path.Buffer);
	KeReleaseGuardedMutex(&driver_config.lock);
}

VOID
GetDriverRegistryPath(
	_Out_ PUNICODE_STRING RegistryPath
)
{
	KeAcquireGuardedMutex(&driver_config.lock);
	RtlZeroMemory(RegistryPath, sizeof(UNICODE_STRING));
	RtlCopyUnicodeString(RegistryPath, &driver_config.registry_path);
	KeReleaseGuardedMutex(&driver_config.lock);
}

VOID
GetDriverDeviceName(
	_Out_ PUNICODE_STRING DeviceName
)
{
	KeAcquireGuardedMutex(&driver_config.lock);
	RtlZeroMemory(DeviceName, sizeof(UNICODE_STRING));
	RtlCopyUnicodeString(DeviceName, &driver_config.device_name);
	KeReleaseGuardedMutex(&driver_config.lock);
}

VOID
GetDriverSymbolicLink(
	_Out_ PUNICODE_STRING DeviceSymbolicLink
)
{
	KeAcquireGuardedMutex(&driver_config.lock);
	RtlZeroMemory(DeviceSymbolicLink, sizeof(UNICODE_STRING));
	RtlCopyUnicodeString(DeviceSymbolicLink, &driver_config.device_symbolic_link);
	KeReleaseGuardedMutex(&driver_config.lock);
}

VOID
GetDriverConfigSystemInformation(
	_Out_ PSYSTEM_INFORMATION* SystemInformation
)
{
	if (SystemInformation == NULL)
		return;

	*SystemInformation = NULL;
	KeAcquireGuardedMutex(&driver_config.lock);
	*SystemInformation = &driver_config.system_information;
	KeReleaseGuardedMutex(&driver_config.lock);
}

STATIC
NTSTATUS
RegistryPathQueryCallbackRoutine(
	IN PWSTR ValueName,
	IN ULONG ValueType,
	IN PVOID ValueData,
	IN ULONG ValueLength,
	IN PVOID Context,
	IN PVOID EntryContext
)
{
	UNICODE_STRING value_name;
	UNICODE_STRING image_path = RTL_CONSTANT_STRING(L"ImagePath");
	UNICODE_STRING display_name = RTL_CONSTANT_STRING(L"DisplayName");
	UNICODE_STRING value;
	PVOID temp_buffer;

	RtlInitUnicodeString(&value_name, ValueName);

	if (RtlCompareUnicodeString(&value_name, &image_path, FALSE) == FALSE)
	{
		temp_buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, ValueLength, POOL_TAG_STRINGS);

		if (!temp_buffer)
			return STATUS_MEMORY_NOT_ALLOCATED;

		RtlCopyMemory(
			temp_buffer,
			ValueData,
			ValueLength
		);

		driver_config.driver_path.Buffer = (PWCH)temp_buffer;
		driver_config.driver_path.Length = ValueLength;
		driver_config.driver_path.MaximumLength = ValueLength + 1;
	}

	if (RtlCompareUnicodeString(&value_name, &display_name, FALSE) == FALSE)
	{
		temp_buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, ValueLength, POOL_TAG_STRINGS);

		if (!temp_buffer)
			return STATUS_MEMORY_NOT_ALLOCATED;

		RtlCopyMemory(
			temp_buffer,
			ValueData,
			ValueLength
		);

		driver_config.unicode_driver_name.Buffer = (PWCH)temp_buffer;
		driver_config.unicode_driver_name.Length = ValueLength;
		driver_config.unicode_driver_name.MaximumLength = ValueLength + 1;
	}

	return STATUS_SUCCESS;
}

STATIC
VOID
FreeDriverConfigurationStringBuffers()
{
	if (driver_config.unicode_driver_name.Buffer)
		ExFreePoolWithTag(driver_config.unicode_driver_name.Buffer, POOL_TAG_STRINGS);

	if (driver_config.driver_path.Buffer)
		ExFreePoolWithTag(driver_config.driver_path.Buffer, POOL_TAG_STRINGS);

	if (driver_config.ansi_driver_name.Buffer)
		RtlFreeAnsiString(&driver_config.ansi_driver_name);
}

STATIC
NTSTATUS
InitialiseDriverConfigOnDriverEntry(
	_In_ PUNICODE_STRING RegistryPath
)
{
	NTSTATUS status;

	/* 3rd page acts as a null terminator for the callback routine */
	RTL_QUERY_REGISTRY_TABLE query_table[3] = { 0 };

	KeInitializeGuardedMutex(&driver_config.lock);

	RtlInitUnicodeString(&driver_config.device_name, L"\\Device\\DonnaAC");
	RtlInitUnicodeString(&driver_config.device_symbolic_link, L"\\??\\DonnaAC");
	RtlCopyUnicodeString(&driver_config.registry_path, RegistryPath);

	query_table[0].Flags = RTL_QUERY_REGISTRY_NOEXPAND;
	query_table[0].Name = L"ImagePath";
	query_table[0].DefaultType = REG_MULTI_SZ;
	query_table[0].DefaultLength = 0;
	query_table[0].DefaultData = NULL;
	query_table[0].EntryContext = NULL;
	query_table[0].QueryRoutine = RegistryPathQueryCallbackRoutine;

	query_table[1].Flags = RTL_QUERY_REGISTRY_NOEXPAND;
	query_table[1].Name = L"DisplayName";
	query_table[1].DefaultType = REG_SZ;
	query_table[1].DefaultLength = 0;
	query_table[1].DefaultData = NULL;
	query_table[1].EntryContext = NULL;
	query_table[1].QueryRoutine = RegistryPathQueryCallbackRoutine;

	status = RtlxQueryRegistryValues(
		RTL_REGISTRY_ABSOLUTE,
		RegistryPath->Buffer,
		&query_table,
		NULL,
		NULL
	);

	if (!NT_SUCCESS(status))
	{
		DEBUG_ERROR("RtlxQueryRegistryValues failed with status %x", status);
		FreeDriverConfigurationStringBuffers();
		return status;
	}

	status = RtlUnicodeStringToAnsiString(
		&driver_config.ansi_driver_name,
		&driver_config.unicode_driver_name,
		TRUE
	);

	if (!NT_SUCCESS(status))
	{
		DEBUG_ERROR("Failed to convert unicode string to ansi string");
		FreeDriverConfigurationStringBuffers();
		return status;
	}

	status = ParseSMBIOSTable(
		&driver_config.system_information.motherboard_serial,
		sizeof(driver_config.system_information.motherboard_serial)
	);

	if (!NT_SUCCESS(status))
	{
		DEBUG_ERROR("ParseSMBIOSTable failed with status %x", status);
		FreeDriverConfigurationStringBuffers();
		return status;
	}

	status = GetHardDiskDriveSerialNumber(
		&driver_config.system_information.drive_0_serial,
		sizeof(driver_config.system_information.drive_0_serial)
	);

	if (!NT_SUCCESS(status))
	{
		DEBUG_ERROR("GetHardDiskDriverSerialNumber failed with status %x", status);
		FreeDriverConfigurationStringBuffers();
		return status;
	}

	status = AllocateCallbackStructure();

	if (!NT_SUCCESS(status))
	{
		DEBUG_ERROR("AllocateCallbackStructure failed with status %x", status);
		FreeDriverConfigurationStringBuffers();
		return status;
	}

	DEBUG_LOG("Motherboard serial: %s", driver_config.system_information.motherboard_serial);
	DEBUG_LOG("Drive 0 serial: %s", driver_config.system_information.drive_0_serial);

	return status;
}

NTSTATUS
InitialiseProcessConfigOnProcessLaunch(
	_In_ PIRP Irp
)
{
	NTSTATUS status;
	PEPROCESS eprocess;
	PDRIVER_INITIATION_INFORMATION information;

	information = (PDRIVER_INITIATION_INFORMATION)Irp->AssociatedIrp.SystemBuffer;

	status = PsLookupProcessByProcessId(information->protected_process_id, &eprocess);

	if (!NT_SUCCESS(status))
		return status;

	KeAcquireGuardedMutex(&process_config.lock);

	process_config.protected_process_eprocess = eprocess;
	process_config.um_handle = information->protected_process_id;
	process_config.km_handle = PsGetProcessId(eprocess);
	process_config.initialised = TRUE;

	KeReleaseGuardedMutex(&process_config.lock);

	return status;
}

STATIC
VOID
InitialiseProcessConfigOnDriverEntry()
{
	KeInitializeGuardedMutex(&process_config.lock);
}

STATIC
VOID
CleanupDriverConfigOnUnload()
{
	FreeDriverConfigurationStringBuffers();
	FreeGlobalReportQueueObjects();
	IoDeleteSymbolicLink(&driver_config.device_symbolic_link);
}

STATIC
VOID
DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	DEBUG_LOG("Unloading driver...");
	//PsSetCreateProcessNotifyRoutine( ProcessCreateNotifyRoutine, TRUE );
	//QueryActiveApcContextsForCompletion();

	/* dont unload while we have active APC operations */
	while (FreeAllApcContextStructures() == FALSE)
		YieldProcessor();

	/* This is safe to call even if the callbacks have already been disabled */
	CleanupDriverCallbacksOnDriverUnload();
	CleanupThreadListOnDriverUnload();

	CleanupDriverConfigOnUnload();
	IoDeleteDevice(DriverObject->DeviceObject);

	DEBUG_LOG("Driver unloaded");
}

VOID
TerminateProtectedProcessOnViolation()
{
	NTSTATUS status;
	ULONG process_id;

	GetProtectedProcessId(&process_id);

	if (!process_id)
	{
		DEBUG_ERROR("Failed to terminate process as process id is null");
		return;
	}

	/*
	* Make sure we pass a km handle to ZwTerminateProcess and NOT a usermode handle.
	*/
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

	ClearProcessConfigOnProcessTermination();
}

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	BOOLEAN flag = FALSE;
	NTSTATUS status;

	status = InitialiseDriverConfigOnDriverEntry(RegistryPath);

	if (!NT_SUCCESS(status))
	{
		DEBUG_ERROR("InitialiseDriverConfigOnDriverEntry failed with status %x", status);
		return status;
	}

	InitialiseProcessConfigOnDriverEntry();

	status = IoCreateDevice(
		DriverObject,
		NULL,
		&driver_config.device_name,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&DriverObject->DeviceObject
	);

	if (!NT_SUCCESS(status))
	{
		DEBUG_ERROR("IoCreateDevice failed with status %x", status);
		FreeDriverConfigurationStringBuffers();
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	status = IoCreateSymbolicLink(
		&driver_config.device_symbolic_link,
		&driver_config.device_name
	);

	if (!NT_SUCCESS(status))
	{
		DEBUG_ERROR("failed to create symbolic link");
		FreeDriverConfigurationStringBuffers();
		IoDeleteDevice(DriverObject->DeviceObject);
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
	DriverObject->DriverUnload = DriverUnload;

	InitialiseGlobalReportQueue(&flag);

	if (!flag)
	{
		DEBUG_ERROR("failed to init report queue");
		FreeDriverConfigurationStringBuffers();
		IoDeleteSymbolicLink(&driver_config.device_symbolic_link);
		IoDeleteDevice(DriverObject->DeviceObject);
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	status = EnableCallbackRoutinesOnDriverEntry();

	if (!NT_SUCCESS(status))
	{
		DEBUG_ERROR("failed to init callback routines on driver entry");
		FreeGlobalReportQueueObjects();
		FreeDriverConfigurationStringBuffers();
		IoDeleteSymbolicLink(&driver_config.device_symbolic_link);
		IoDeleteDevice(DriverObject->DeviceObject);
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	DEBUG_LOG("DonnaAC Driver Entry Complete");

	return STATUS_SUCCESS;
}

