#include "modules.h"

#include "callbacks.h"
#include "driver.h"

#define WHITELISTED_MODULE_TAG 'whte'

#define NMI_DELAY 200 * 10000

#define WHITELISTED_MODULE_COUNT 11
#define MODULE_MAX_STRING_SIZE 256

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
CHAR WHITELISTED_MODULES[WHITELISTED_MODULE_COUNT][MODULE_MAX_STRING_SIZE] =
{
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
	"LXCORE.SYS"
};

#define MODULE_REPORT_DRIVER_NAME_BUFFER_SIZE 128

#define REASON_NO_BACKING_MODULE 1
#define REASON_INVALID_IOCTL_DISPATCH 2

#define SYSTEM_IDLE_PROCESS_ID 0
#define SYSTEM_PROCESS_ID 4
#define SVCHOST_PROCESS_ID 8

typedef struct _WHITELISTED_REGIONS
{
	UINT64 base;
	UINT64 end;

}WHITELISTED_REGIONS, * PWHITELISTED_REGIONS;

typedef struct _NMI_POOLS
{
	PVOID thread_data_pool;
	PVOID stack_frames;
	PVOID nmi_context;

}NMI_POOLS, * PNMI_POOLS;

typedef struct _NMI_CORE_CONTEXT
{
	INT nmi_callbacks_run;

}NMI_CORE_CONTEXT, * PNMI_CORE_CONTEXT;

typedef struct _MODULE_VALIDATION_FAILURE_HEADER
{
	INT module_count;

}MODULE_VALIDATION_FAILURE_HEADER, * PMODULE_VALIDATION_FAILURE_HEADER;

typedef struct _NMI_CONTEXT
{
	PVOID thread_data_pool;
	PVOID stack_frames;
	PVOID nmi_core_context;
	INT core_count;

}NMI_CONTEXT, * PNMI_CONTEXT;

typedef struct _NMI_CALLBACK_DATA
{
	UINT64		kthread_address;
	UINT64		kprocess_address;
	UINT64		start_address;
	UINT64		stack_limit;
	UINT64		stack_base;
	uintptr_t	stack_frames_offset;
	INT		num_frames_captured;
	UINT64		cr3;

}NMI_CALLBACK_DATA, * PNMI_CALLBACK_DATA;

typedef struct _INVALID_DRIVER
{
	struct _INVALID_DRIVER* next;
	INT reason;
	PDRIVER_OBJECT driver;

}INVALID_DRIVER, * PINVALID_DRIVER;

typedef struct _INVALID_DRIVERS_HEAD
{
	PINVALID_DRIVER first_entry;
	INT count;

}INVALID_DRIVERS_HEAD, * PINVALID_DRIVERS_HEAD;

STATIC 
NTSTATUS 
PopulateWhitelistedModuleBuffer(
	_Inout_ PVOID Buffer, 
	_In_ PSYSTEM_MODULES SystemModules);

STATIC 
NTSTATUS 
ValidateDriverIOCTLDispatchRegion(
	_In_ PDRIVER_OBJECT Driver, 
	_In_ PSYSTEM_MODULES Modules,
	_In_ PWHITELISTED_REGIONS WhitelistedRegions, 
	_Out_ PBOOLEAN Flag);

STATIC 
VOID 
InitDriverList(
	_Inout_ PINVALID_DRIVERS_HEAD ListHead);

STATIC 
VOID 
AddDriverToList(
	_Inout_ PINVALID_DRIVERS_HEAD InvalidDriversHead, 
	_In_ PDRIVER_OBJECT Driver,
	_In_ INT Reason);

STATIC 
VOID 
RemoveInvalidDriverFromList(
	_Inout_ PINVALID_DRIVERS_HEAD InvalidDriversHead);

STATIC 
VOID 
EnumerateInvalidDrivers(
	_In_ PINVALID_DRIVERS_HEAD InvalidDriversHead);

STATIC 
NTSTATUS 
ValidateDriverObjectHasBackingModule(
	_In_ PSYSTEM_MODULES ModuleInformation,
	_In_ PDRIVER_OBJECT DriverObject, 
	_Out_ PBOOLEAN Result);

STATIC 
NTSTATUS 
ValidateDriverObjects(
	_In_ PSYSTEM_MODULES SystemModules,
	_Inout_ PINVALID_DRIVERS_HEAD InvalidDriverListHead);

STATIC 
NTSTATUS 
AnalyseNmiData(
	_In_ PNMI_CONTEXT NmiContext, 
	_In_ PSYSTEM_MODULES SystemModules,
	_Inout_ PIRP Irp);

STATIC 
NTSTATUS 
LaunchNonMaskableInterrupt(
	_Inout_ PNMI_CONTEXT NmiContext);

STATIC 
VOID 
ApcRundownRoutine(
	_In_ PRKAPC Apc);

STATIC 
VOID 
ApcKernelRoutine(
	_In_ PRKAPC Apc, 
	_Inout_ _Deref_pre_maybenull_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ _Deref_pre_maybenull_ PVOID* NormalContext, 
	_Inout_ _Deref_pre_maybenull_ PVOID* SystemArgument1,
	_Inout_ _Deref_pre_maybenull_ PVOID* SystemArgument2);

STATIC 
VOID 
ApcNormalRoutine(
	_In_opt_ PVOID NormalContext, 
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2);

STATIC
VOID
ValidateThreadViaKernelApcCallback(
	_In_ PTHREAD_LIST_ENTRY ThreadListEntry,
	_Inout_opt_ PVOID Context);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, FindSystemModuleByName)
#pragma alloc_text(PAGE, PopulateWhitelistedModuleBuffer)
#pragma alloc_text(PAGE, ValidateDriverIOCTLDispatchRegion)
#pragma alloc_text(PAGE, InitDriverList)
#pragma alloc_text(PAGE, AddDriverToList)
#pragma alloc_text(PAGE, RemoveInvalidDriverFromList)
#pragma alloc_text(PAGE, EnumerateInvalidDrivers)
#pragma alloc_text(PAGE, ValidateDriverObjectHasBackingModule)
#pragma alloc_text(PAGE, GetSystemModuleInformation)
#pragma alloc_text(PAGE, ValidateDriverObjects)
#pragma alloc_text(PAGE, HandleValidateDriversIOCTL)
#pragma alloc_text(PAGE, IsInstructionPointerInInvalidRegion)
#pragma alloc_text(PAGE, AnalyseNmiData)
#pragma alloc_text(PAGE, LaunchNonMaskableInterrupt)
#pragma alloc_text(PAGE, HandleNmiIOCTL)
#pragma alloc_text(PAGE, ApcRundownRoutine)
#pragma alloc_text(PAGE, ApcKernelRoutine)
#pragma alloc_text(PAGE, ApcNormalRoutine)
#pragma alloc_text(PAGE, FlipKThreadMiscFlagsFlag)
#pragma alloc_text(PAGE, ValidateThreadsViaKernelApc)
#endif

/*
* TODO: this needs to be refactored to just return the entry not the whole fukin thing
*/
PRTL_MODULE_EXTENDED_INFO
FindSystemModuleByName(
	_In_ LPCSTR ModuleName,
	_In_ PSYSTEM_MODULES SystemModules
)
{
	if (!ModuleName || !SystemModules)
		return STATUS_INVALID_PARAMETER;

	for (INT index = 0; index < SystemModules->module_count; index++)
	{
		PRTL_MODULE_EXTENDED_INFO system_module = (PRTL_MODULE_EXTENDED_INFO)(
			(uintptr_t)SystemModules->address + index * sizeof(RTL_MODULE_EXTENDED_INFO));

		if (strstr(system_module->FullPathName, ModuleName))
		{
			return system_module;
		}
	}
}

STATIC
NTSTATUS
PopulateWhitelistedModuleBuffer(
	_Inout_ PVOID Buffer,
	_In_ PSYSTEM_MODULES SystemModules
)
{
	if (!Buffer || !SystemModules)
		return STATUS_INVALID_PARAMETER;

	for (INT index = 0; index < WHITELISTED_MODULE_COUNT; index++)
	{
		LPCSTR name = WHITELISTED_MODULES[index];

		PRTL_MODULE_EXTENDED_INFO module = FindSystemModuleByName(name, SystemModules);

		/* not everyone will contain all whitelisted modules */
		if (!module)
			continue;

		WHITELISTED_REGIONS region;
		region.base = (UINT64)module->ImageBase;
		region.end = region.base + module->ImageSize;

		RtlCopyMemory(
			(UINT64)Buffer + index * sizeof(WHITELISTED_REGIONS),
			&region,
			sizeof(WHITELISTED_REGIONS)
		);
	}

	return STATUS_SUCCESS;
}

STATIC
NTSTATUS
ValidateDriverIOCTLDispatchRegion(
	_In_ PDRIVER_OBJECT Driver,
	_In_ PSYSTEM_MODULES Modules,
	_In_ PWHITELISTED_REGIONS WhitelistedRegions,
	_Out_ PBOOLEAN Flag
)
{
	if (!Modules || !Driver || !Flag || !WhitelistedRegions)
		return STATUS_INVALID_PARAMETER;

	UINT64 dispatch_function;
	UINT64 module_base;
	UINT64 module_end;

	*Flag = TRUE;

	dispatch_function = Driver->MajorFunction[IRP_MJ_DEVICE_CONTROL];

	if (dispatch_function == NULL)
		return STATUS_SUCCESS;

	for (INT index = 0; index < Modules->module_count; index++)
	{
		PRTL_MODULE_EXTENDED_INFO system_module = (PRTL_MODULE_EXTENDED_INFO)(
			(uintptr_t)Modules->address + index * sizeof(RTL_MODULE_EXTENDED_INFO));

		if (system_module->ImageBase != Driver->DriverStart)
			continue;

		/* make sure our driver has a device object which is required for IOCTL */
		if (Driver->DeviceObject == NULL)
			return STATUS_SUCCESS;

		module_base = (UINT64)system_module->ImageBase;
		module_end = module_base + system_module->ImageSize;

		/* firstly, check if its inside its own module */
		if (dispatch_function >= module_base && dispatch_function <= module_end)
			return STATUS_SUCCESS;

		/*
		* The WDF framework and other low level drivers often hook the dispatch routines
		* when initiating the respective config of their framework or system. With a bit of
		* digging you can view the drivers reponsible for the hooks. What this means is that
		* there will be legit drivers with dispatch routines that point outside of ntoskrnl
		* and their own memory region. So, I have formed a list which contains the drivers
		* that perform these hooks and we iteratively check if the dispatch routine is contained
		* within one of these whitelisted regions. A note on how to imrpove this is the fact
		* that a code cave can be used inside a whitelisted region which then jumps to an invalid
		* region such as a manually mapped driver. So in the future we should implement a function
		* which checks for standard hook implementations like mov rax jmp rax etc.
		*/
		for (INT index = 0; index < WHITELISTED_MODULE_COUNT; index++)
		{
			if (dispatch_function >= WhitelistedRegions[index].base &&
				dispatch_function <= WhitelistedRegions[index].end)
				return STATUS_SUCCESS;
		}

		DEBUG_LOG("name: %s, base: %p, size: %lx, dispatch: %llx, type: %lx",
			system_module->FullPathName,
			system_module->ImageBase,
			system_module->ImageSize,
			dispatch_function,
			Driver->DeviceObject->DeviceType);

		*Flag = FALSE;
		return STATUS_SUCCESS;
	}

	return STATUS_SUCCESS;
}

STATIC
VOID
InitDriverList(
	_Inout_ PINVALID_DRIVERS_HEAD ListHead
)
{
	ListHead->count = 0;
	ListHead->first_entry = NULL;
}

STATIC
VOID
AddDriverToList(
	_Inout_ PINVALID_DRIVERS_HEAD InvalidDriversHead,
	_In_ PDRIVER_OBJECT Driver,
	_In_ INT Reason
)
{
	PINVALID_DRIVER new_entry = ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		sizeof(INVALID_DRIVER),
		INVALID_DRIVER_LIST_ENTRY_POOL
	);

	if (!new_entry)
		return;

	new_entry->driver = Driver;
	new_entry->reason = Reason;
	new_entry->next = InvalidDriversHead->first_entry;
	InvalidDriversHead->first_entry = new_entry;
}

STATIC
VOID
RemoveInvalidDriverFromList(
	_Inout_ PINVALID_DRIVERS_HEAD InvalidDriversHead
)
{
	if (InvalidDriversHead->first_entry)
	{
		PINVALID_DRIVER entry = InvalidDriversHead->first_entry;
		InvalidDriversHead->first_entry = InvalidDriversHead->first_entry->next;
		ExFreePoolWithTag(entry, INVALID_DRIVER_LIST_ENTRY_POOL);
	}
}

STATIC
VOID
EnumerateInvalidDrivers(
	_In_ PINVALID_DRIVERS_HEAD InvalidDriversHead
)
{
	PINVALID_DRIVER entry = InvalidDriversHead->first_entry;

	while (entry != NULL)
	{
		DEBUG_LOG("Invalid Driver: %wZ", entry->driver->DriverName);
		entry = entry->next;
	}
}

STATIC
NTSTATUS
ValidateDriverObjectHasBackingModule(
	_In_ PSYSTEM_MODULES ModuleInformation,
	_In_ PDRIVER_OBJECT DriverObject,
	_Out_ PBOOLEAN Result
)
{
	if (!ModuleInformation || !DriverObject || !Result)
		return STATUS_INVALID_PARAMETER;

	for (INT i = 0; i < ModuleInformation->module_count; i++)
	{
		PRTL_MODULE_EXTENDED_INFO system_module = (PRTL_MODULE_EXTENDED_INFO)(
			(uintptr_t)ModuleInformation->address + i * sizeof(RTL_MODULE_EXTENDED_INFO));

		if (system_module->ImageBase == DriverObject->DriverStart)
		{
			*Result = TRUE;
			return STATUS_SUCCESS;
		}
	}

	DEBUG_LOG("invalid driver found");
	*Result = FALSE;

	return STATUS_SUCCESS;
}

//https://imphash.medium.com/windows-process-internals-a-few-concepts-to-know-before-jumping-on-memory-forensics-part-3-4a0e195d947b
NTSTATUS
GetSystemModuleInformation(
	_Inout_ PSYSTEM_MODULES ModuleInformation
)
{
	if (!ModuleInformation)
		return STATUS_INVALID_PARAMETER;

	ULONG size = 0;

	/*
	* query system module information without an output buffer to get
	* number of bytes required to store all module info structures
	*/
	if (!NT_SUCCESS(RtlQueryModuleInformation(
		&size,
		sizeof(RTL_MODULE_EXTENDED_INFO),
		NULL
	)))
	{
		DEBUG_ERROR("Failed to query module information");
		return STATUS_ABANDONED;
	}

	/* Allocate a pool equal to the output size of RtlQueryModuleInformation */
	PRTL_MODULE_EXTENDED_INFO driver_information = ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		size,
		SYSTEM_MODULES_POOL
	);

	if (!driver_information)
	{
		DEBUG_ERROR("Failed to allocate pool LOL");
		return STATUS_ABANDONED;
	}

	/* Query the modules again this time passing a pointer to the allocated buffer */
	if (!NT_SUCCESS(RtlQueryModuleInformation(
		&size,
		sizeof(RTL_MODULE_EXTENDED_INFO),
		driver_information
	)))
	{
		DEBUG_ERROR("Failed lolz");
		ExFreePoolWithTag(driver_information, SYSTEM_MODULES_POOL);
		return STATUS_ABANDONED;
	}

	ModuleInformation->address = driver_information;
	ModuleInformation->module_count = size / sizeof(RTL_MODULE_EXTENDED_INFO);

	return STATUS_SUCCESS;
}

STATIC
NTSTATUS
ValidateDriverObjects(
	_In_ PSYSTEM_MODULES SystemModules,
	_Inout_ PINVALID_DRIVERS_HEAD InvalidDriverListHead
)
{
	if (!SystemModules || !InvalidDriverListHead)
		return STATUS_INVALID_PARAMETER;

	HANDLE handle;
	OBJECT_ATTRIBUTES attributes = { 0 };
	PVOID directory = { 0 };
	UNICODE_STRING directory_name;
	NTSTATUS status;

	RtlInitUnicodeString(&directory_name, L"\\Driver");

	InitializeObjectAttributes(
		&attributes,
		&directory_name,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL
	);

	if (!NT_SUCCESS(ZwOpenDirectoryObject(
		&handle,
		DIRECTORY_ALL_ACCESS,
		&attributes
	)))
	{
		DEBUG_ERROR("Failed to query directory object");
		return STATUS_ABANDONED;
	}

	if (!NT_SUCCESS(ObReferenceObjectByHandle(
		handle,
		DIRECTORY_ALL_ACCESS,
		NULL,
		KernelMode,
		&directory,
		NULL
	)))
	{
		DEBUG_ERROR("Failed to reference directory by handle");
		ZwClose(handle);
		return STATUS_ABANDONED;
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

	POBJECT_DIRECTORY directory_object = (POBJECT_DIRECTORY)directory;

	ExAcquirePushLockExclusiveEx(&directory_object->Lock, NULL);

	PVOID whitelisted_regions_buffer = ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		WHITELISTED_MODULE_COUNT * MODULE_MAX_STRING_SIZE,
		WHITELISTED_MODULE_TAG
	);

	if (!whitelisted_regions_buffer)
		goto end;

	status = PopulateWhitelistedModuleBuffer(
		whitelisted_regions_buffer,
		SystemModules
	);

	if (!NT_SUCCESS(status))
	{
		DEBUG_ERROR("PopulateWhiteListedBuffer failed with status %x", status);
		goto end;
	}

	for (INT i = 0; i < NUMBER_HASH_BUCKETS; i++)
	{
		POBJECT_DIRECTORY_ENTRY entry = directory_object->HashBuckets[i];

		if (!entry)
			continue;

		POBJECT_DIRECTORY_ENTRY sub_entry = entry;

		while (sub_entry)
		{
			PDRIVER_OBJECT current_driver = sub_entry->Object;
			BOOLEAN flag;

			/* validate driver has backing module */

			if (!NT_SUCCESS(ValidateDriverObjectHasBackingModule(
				SystemModules,
				current_driver,
				&flag
			)))
			{
				DEBUG_LOG("Error validating driver object");
				ExReleasePushLockExclusiveEx(&directory_object->Lock, 0);
				ObDereferenceObject(directory);
				ZwClose(handle);
				return STATUS_ABANDONED;
			}

			if (!flag)
			{
				InvalidDriverListHead->count += 1;
				AddDriverToList(InvalidDriverListHead, current_driver, REASON_NO_BACKING_MODULE);
			}

			/* validate drivers IOCTL dispatch routines */

			if (!NT_SUCCESS(ValidateDriverIOCTLDispatchRegion(
				current_driver,
				SystemModules,
				(PWHITELISTED_REGIONS)whitelisted_regions_buffer,
				&flag
			)))
			{
				DEBUG_LOG("Error validating drivers IOCTL routines");
				ExReleasePushLockExclusiveEx(&directory_object->Lock, 0);
				ObDereferenceObject(directory);
				ZwClose(handle);
				return STATUS_ABANDONED;
			}

			if (!flag)
			{
				InvalidDriverListHead->count += 1;
				AddDriverToList(InvalidDriverListHead, current_driver, REASON_INVALID_IOCTL_DISPATCH);
			}

			sub_entry = sub_entry->ChainLink;
		}
	}

end:
	if (whitelisted_regions_buffer)
		ExFreePoolWithTag(whitelisted_regions_buffer, WHITELISTED_MODULE_TAG);

	ExReleasePushLockExclusiveEx(&directory_object->Lock, 0);
	ObDereferenceObject(directory);
	ZwClose(handle);

	return STATUS_SUCCESS;
}

NTSTATUS
HandleValidateDriversIOCTL(
	_Inout_ PIRP Irp
)
{
	NTSTATUS status;
	SYSTEM_MODULES system_modules = { 0 };

	/* Fix annoying visual studio linting error */
	RtlZeroMemory(&system_modules, sizeof(SYSTEM_MODULES));

	status = GetSystemModuleInformation(&system_modules);

	if (!NT_SUCCESS(status))
	{
		DEBUG_ERROR("Error retriving system module information");
		return status;
	}

	PINVALID_DRIVERS_HEAD head =
		ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(INVALID_DRIVERS_HEAD), INVALID_DRIVER_LIST_HEAD_POOL);

	if (!head)
	{
		ExFreePoolWithTag(system_modules.address, SYSTEM_MODULES_POOL);
		return STATUS_ABANDONED;
	}

	/*
	* Use a linked list here so that so we have easy access to the invalid drivers
	* which we can then use to copy the drivers logic for further analysis in
	* identifying drivers specifically used for the purpose of cheating
	*/

	InitDriverList(head);

	if (!NT_SUCCESS(ValidateDriverObjects(&system_modules, head)))
	{
		DEBUG_ERROR("Failed to validate driver objects");
		ExFreePoolWithTag(system_modules.address, SYSTEM_MODULES_POOL);
		return STATUS_ABANDONED;
	}

	MODULE_VALIDATION_FAILURE_HEADER header;

	header.module_count = head->count >= MODULE_VALIDATION_FAILURE_MAX_REPORT_COUNT
		? MODULE_VALIDATION_FAILURE_MAX_REPORT_COUNT
		: head->count;

	if (head->count > 0)
	{
		DEBUG_LOG("found INVALID drivers with count: %i", head->count);

		PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(MODULE_VALIDATION_FAILURE_HEADER) +
			MODULE_VALIDATION_FAILURE_MAX_REPORT_COUNT * sizeof(MODULE_VALIDATION_FAILURE), MODULES_REPORT_POOL_TAG);

		if (!buffer)
		{
			ExFreePoolWithTag(head, INVALID_DRIVER_LIST_HEAD_POOL);
			ExFreePoolWithTag(system_modules.address, SYSTEM_MODULES_POOL);
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		Irp->IoStatus.Information = sizeof(MODULE_VALIDATION_FAILURE_HEADER) +
			MODULE_VALIDATION_FAILURE_MAX_REPORT_COUNT * sizeof(MODULE_VALIDATION_FAILURE);

		RtlCopyMemory(
			buffer,
			&header,
			sizeof(MODULE_VALIDATION_FAILURE_HEADER)
		);

		for (INT i = 0; i < head->count; i++)
		{
			/* make sure we free any non reported modules */
			if (i >= MODULE_VALIDATION_FAILURE_MAX_REPORT_COUNT)
			{
				RemoveInvalidDriverFromList(head);
				continue;
			}

			MODULE_VALIDATION_FAILURE report;
			report.report_code = REPORT_MODULE_VALIDATION_FAILURE;
			report.report_type = head->first_entry->reason;
			report.driver_base_address = head->first_entry->driver->DriverStart;
			report.driver_size = head->first_entry->driver->DriverSize;

			ANSI_STRING string;
			string.Length = 0;
			string.MaximumLength = MODULE_REPORT_DRIVER_NAME_BUFFER_SIZE;
			string.Buffer = &report.driver_name;

			status = RtlUnicodeStringToAnsiString(
				&string,
				&head->first_entry->driver->DriverName,
				FALSE
			);

			/* still continue if we fail to get the driver name */
			if (!NT_SUCCESS(status))
				DEBUG_ERROR("RtlUnicodeStringToAnsiString failed with statsu %x", status);

			RtlCopyMemory(
				(UINT64)buffer + sizeof(MODULE_VALIDATION_FAILURE_HEADER) + i * sizeof(MODULE_VALIDATION_FAILURE),
				&report,
				sizeof(MODULE_VALIDATION_FAILURE));

			RemoveInvalidDriverFromList(head);
		}

		RtlCopyMemory(
			Irp->AssociatedIrp.SystemBuffer,
			buffer,
			sizeof(MODULE_VALIDATION_FAILURE_HEADER) + MODULE_VALIDATION_FAILURE_MAX_REPORT_COUNT * sizeof(MODULE_VALIDATION_FAILURE)
		);

		ExFreePoolWithTag(buffer, MODULES_REPORT_POOL_TAG);
	}
	else
	{
		DEBUG_LOG("No INVALID drivers found :)");
	}

	ExFreePoolWithTag(head, INVALID_DRIVER_LIST_HEAD_POOL);
	ExFreePoolWithTag(system_modules.address, SYSTEM_MODULES_POOL);

	return status;
}

NTSTATUS
IsInstructionPointerInInvalidRegion(
	_In_ UINT64 RIP,
	_In_ PSYSTEM_MODULES SystemModules,
	_Out_ PBOOLEAN Result
)
{
	if (!RIP || !SystemModules || !Result)
		return STATUS_INVALID_PARAMETER;

	/* Note that this does not check for HAL or PatchGuard Execution */
	for (INT i = 0; i < SystemModules->module_count; i++)
	{
		PRTL_MODULE_EXTENDED_INFO system_module = (PRTL_MODULE_EXTENDED_INFO)(
			(uintptr_t)SystemModules->address + i * sizeof(RTL_MODULE_EXTENDED_INFO));

		UINT64 base = (UINT64)system_module->ImageBase;
		UINT64 end = base + system_module->ImageSize;

		if (RIP >= base && RIP <= end)
		{
			*Result = TRUE;
			return STATUS_SUCCESS;;
		}
	}

	*Result = FALSE;
	return STATUS_SUCCESS;
}

STATIC
NTSTATUS
AnalyseNmiData(
	_In_ PNMI_CONTEXT NmiContext,
	_In_ PSYSTEM_MODULES SystemModules,
	_Inout_ PIRP Irp
)
{
	if (!NmiContext || !SystemModules)
		return STATUS_INVALID_PARAMETER;

	for (INT core = 0; core < NmiContext->core_count; core++)
	{
		PNMI_CORE_CONTEXT context = (PNMI_CORE_CONTEXT)((uintptr_t)NmiContext->nmi_core_context + core * sizeof(NMI_CORE_CONTEXT));

		/* Make sure our NMIs were run  */
		if (!context->nmi_callbacks_run)
		{
			NMI_CALLBACK_FAILURE report;
			report.report_code = REPORT_NMI_CALLBACK_FAILURE;
			report.kthread_address = NULL;
			report.invalid_rip = NULL;
			report.were_nmis_disabled = TRUE;

			Irp->IoStatus.Information = sizeof(NMI_CALLBACK_FAILURE);

			RtlCopyMemory(
				Irp->AssociatedIrp.SystemBuffer,
				&report,
				sizeof(NMI_CALLBACK_FAILURE)
			);

			return STATUS_SUCCESS;
		}

		PNMI_CALLBACK_DATA thread_data = (PNMI_CALLBACK_DATA)(
			(uintptr_t)NmiContext->thread_data_pool + core * sizeof(NMI_CALLBACK_DATA));

		DEBUG_LOG("cpu number: %i callback count: %i", core, context->nmi_callbacks_run);

		/* Walk the stack */
		for (INT frame = 0; frame < thread_data->num_frames_captured; frame++)
		{
			BOOLEAN flag;
			DWORD64 stack_frame = *(DWORD64*)(
				((uintptr_t)NmiContext->stack_frames + thread_data->stack_frames_offset + frame * sizeof(PVOID)));

			if (!NT_SUCCESS(IsInstructionPointerInInvalidRegion(stack_frame, SystemModules, &flag)))
			{
				DEBUG_ERROR("errro checking RIP for current stack address");
				continue;
			}

			if (flag == FALSE)
			{
				/*
				* Note: for now, we only handle 1 report at a time so we stop the
				* analysis once we receive a report since we only send a buffer
				* large enough for 1 report. In the future this should be changed
				* to a buffer that can hold atleast 4 reports (since the chance we
				* get 4 reports with a single NMI would be impossible) so we can
				* continue parsing the rest of the stack frames after receiving a
				* single report.
				*/

				NMI_CALLBACK_FAILURE report;
				report.report_code = REPORT_NMI_CALLBACK_FAILURE;
				report.kthread_address = thread_data->kthread_address;
				report.invalid_rip = stack_frame;
				report.were_nmis_disabled = FALSE;

				Irp->IoStatus.Information = sizeof(NMI_CALLBACK_FAILURE);

				RtlCopyMemory(
					Irp->AssociatedIrp.SystemBuffer,
					&report,
					sizeof(NMI_CALLBACK_FAILURE)
				);

				return STATUS_SUCCESS;
			}
		}
	}

	return STATUS_SUCCESS;
}

STATIC
BOOLEAN
NmiCallback(
	_Inout_opt_ PVOID Context,
	_In_ BOOLEAN Handled
)
{
	UNREFERENCED_PARAMETER(Handled);

	PVOID current_thread = KeGetCurrentThread();
	NMI_CALLBACK_DATA thread_data = { 0 };
	PNMI_CONTEXT nmi_context = (PNMI_CONTEXT)Context;
	ULONG proc_num = KeGetCurrentProcessorNumber();

	if (!nmi_context)
		return TRUE;

	/*
	* Cannot allocate pool in this function as it runs at IRQL >= dispatch level
	* so ive just allocated a global pool with size equal to 0x200 * num_procs
	*/
	INT num_frames_captured = RtlCaptureStackBackTrace(
		NULL,
		STACK_FRAME_POOL_SIZE / sizeof(UINT64),
		(uintptr_t)nmi_context->stack_frames + proc_num * STACK_FRAME_POOL_SIZE,
		NULL
	);

	/*
	* This function is run in the context of the interrupted thread hence we can
	* gather any and all information regarding the thread that may be useful for analysis
	*/
	thread_data.kthread_address = (UINT64)current_thread;
	thread_data.kprocess_address = (UINT64)PsGetCurrentProcess();
	thread_data.stack_base = *((UINT64*)((uintptr_t)current_thread + KTHREAD_STACK_BASE_OFFSET));
	thread_data.stack_limit = *((UINT64*)((uintptr_t)current_thread + KTHREAD_STACK_LIMIT_OFFSET));
	thread_data.start_address = *((UINT64*)((uintptr_t)current_thread + KTHREAD_START_ADDRESS_OFFSET));
	thread_data.cr3 = __readcr3();
	thread_data.stack_frames_offset = proc_num * STACK_FRAME_POOL_SIZE;
	thread_data.num_frames_captured = num_frames_captured;

	RtlCopyMemory(
		((uintptr_t)nmi_context->thread_data_pool) + proc_num * sizeof(thread_data),
		&thread_data,
		sizeof(thread_data)
	);

	PNMI_CORE_CONTEXT core_context =
		(PNMI_CORE_CONTEXT)((uintptr_t)nmi_context->nmi_core_context + proc_num * sizeof(NMI_CORE_CONTEXT));

	core_context->nmi_callbacks_run += 1;

	return TRUE;
}

STATIC
NTSTATUS
LaunchNonMaskableInterrupt(
	_Inout_ PNMI_CONTEXT NmiContext
)
{
	if (!NmiContext)
		return STATUS_INVALID_PARAMETER;

	PKAFFINITY_EX ProcAffinityPool =
		ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAFFINITY_EX), PROC_AFFINITY_POOL);

	if (!ProcAffinityPool)
		return STATUS_MEMORY_NOT_ALLOCATED;

	NmiContext->stack_frames =
		ExAllocatePool2(POOL_FLAG_NON_PAGED, NmiContext->core_count * STACK_FRAME_POOL_SIZE, STACK_FRAMES_POOL);

	if (!NmiContext->stack_frames)
	{
		ExFreePoolWithTag(ProcAffinityPool, PROC_AFFINITY_POOL);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	NmiContext->thread_data_pool =
		ExAllocatePool2(POOL_FLAG_NON_PAGED, NmiContext->core_count * sizeof(NMI_CALLBACK_DATA), THREAD_DATA_POOL);

	if (!NmiContext->thread_data_pool)
	{
		ExFreePoolWithTag(NmiContext->stack_frames, STACK_FRAMES_POOL);
		ExFreePoolWithTag(ProcAffinityPool, PROC_AFFINITY_POOL);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	LARGE_INTEGER delay = { 0 };
	delay.QuadPart -= 100 * 10000;

	for (ULONG core = 0; core < NmiContext->core_count; core++)
	{
		KeInitializeAffinityEx(ProcAffinityPool);
		KeAddProcessorAffinityEx(ProcAffinityPool, core);

		HalSendNMI(ProcAffinityPool);

		/*
		* Only a single NMI can be active at any given time, so arbitrarily
		* delay execution  to allow time for the NMI to be processed
		*/
		KeDelayExecutionThread(KernelMode, FALSE, &delay);
	}

	ExFreePoolWithTag(ProcAffinityPool, PROC_AFFINITY_POOL);

	return STATUS_SUCCESS;
}

NTSTATUS
HandleNmiIOCTL(
	_Inout_ PIRP Irp
)
{
	NTSTATUS status;
	SYSTEM_MODULES system_modules = { 0 };
	NMI_CONTEXT nmi_context = { 0 };
	PVOID callback_handle;

	nmi_context.core_count = KeQueryActiveProcessorCountEx(0);
	nmi_context.nmi_core_context =
		ExAllocatePool2(POOL_FLAG_NON_PAGED, nmi_context.core_count * sizeof(NMI_CORE_CONTEXT), NMI_CONTEXT_POOL);

	if (!nmi_context.nmi_core_context)
		return STATUS_MEMORY_NOT_ALLOCATED;

	/*
	* We want to register and unregister our callback each time so it becomes harder
	* for people to hook our callback and get up to some funny business
	*/
	callback_handle = KeRegisterNmiCallback(NmiCallback, &nmi_context);

	if (!callback_handle)
	{
		DEBUG_ERROR("KeRegisterNmiCallback failed");
		ExFreePoolWithTag(nmi_context.nmi_core_context, NMI_CONTEXT_POOL);
		return STATUS_ABANDONED;
	}

	/*
	* We query the system modules each time since they can potentially
	* change at any time
	*/
	status = GetSystemModuleInformation(&system_modules);

	if (!NT_SUCCESS(status))
	{
		DEBUG_ERROR("Error retriving system module information");
		return status;
	}
	status = LaunchNonMaskableInterrupt(&nmi_context);

	if (!NT_SUCCESS(status))
	{
		DEBUG_ERROR("Error running NMI callbacks");

		if (system_modules.address)
			ExFreePoolWithTag(system_modules.address, SYSTEM_MODULES_POOL);

		return status;
	}
	status = AnalyseNmiData(&nmi_context, &system_modules, Irp);

	if (!NT_SUCCESS(status))
		DEBUG_ERROR("Error analysing nmi data");

	if (system_modules.address)
		ExFreePoolWithTag(system_modules.address, SYSTEM_MODULES_POOL);

	if (nmi_context.nmi_core_context)
		ExFreePoolWithTag(nmi_context.nmi_core_context, NMI_CONTEXT_POOL);

	if (nmi_context.stack_frames)
		ExFreePoolWithTag(nmi_context.stack_frames, STACK_FRAMES_POOL);

	if (nmi_context.thread_data_pool)
		ExFreePoolWithTag(nmi_context.thread_data_pool, THREAD_DATA_POOL);

	KeDeregisterNmiCallback(callback_handle);

	return status;
}

/*
* The RundownRoutine is executed if the thread terminates before the APC was delivered to
* user mode.
*/
STATIC
VOID
ApcRundownRoutine(
	_In_ PRKAPC Apc
)
{
	FreeApcAndDecrementApcCount(Apc, APC_CONTEXT_ID_STACKWALK);
}

/*
* The KernelRoutine is executed in kernel mode at APC_LEVEL before the APC is delivered. This
* is also where we want to free our APC object.
*/
STATIC
VOID
ApcKernelRoutine(
	_In_ PRKAPC Apc,
	_Inout_ _Deref_pre_maybenull_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ _Deref_pre_maybenull_ PVOID* NormalContext,
	_Inout_ _Deref_pre_maybenull_ PVOID* SystemArgument1,
	_Inout_ _Deref_pre_maybenull_ PVOID* SystemArgument2
)
{
	PVOID buffer = NULL;
	INT frames_captured = 0;
	UINT64 stack_frame = 0;
	NTSTATUS status;
	BOOLEAN flag = FALSE;
	PAPC_STACKWALK_CONTEXT context;
	PTHREAD_LIST_ENTRY thread_list_entry = NULL;

	context = (PAPC_STACKWALK_CONTEXT)Apc->NormalContext;

	FindThreadListEntryByThreadAddress(KeGetCurrentThread(), &thread_list_entry);

	if (!thread_list_entry)
		return;

	buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, STACK_FRAME_POOL_SIZE, POOL_TAG_APC);

	if (!buffer)
		goto free;

	frames_captured = RtlCaptureStackBackTrace(
		NULL,
		STACK_FRAME_POOL_SIZE / sizeof(UINT64),
		buffer,
		NULL
	);

	if (frames_captured == NULL)
		goto free;

	for (INT index = 0; index < frames_captured; index++)
	{
		stack_frame = *(UINT64*)((UINT64)buffer + index * sizeof(UINT64));

		/*
		* Apc->NormalContext holds the address of our context data structure that we passed into
		* KeInitializeApc as the last argument.
		*/
		status = IsInstructionPointerInInvalidRegion(
			stack_frame,
			context->modules,
			&flag
		);

		if (!NT_SUCCESS(status))
		{
			DEBUG_ERROR("IsInstructionPointerInInvalidRegion failed with status %x", status);
			goto free;
		}

		if (flag == FALSE)
		{
			PAPC_STACKWALK_REPORT report = 
				ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(APC_STACKWALK_REPORT), POOL_TAG_APC);

			if (!report)
				goto free;

			report->report_code = REPORT_APC_STACKWALK;
			report->kthread_address = (UINT64)KeGetCurrentThread();
			report->invalid_rip = stack_frame;

			RtlCopyMemory(
				&report->driver,
				(UINT64)stack_frame - 0x500,
				APC_STACKWALK_BUFFER_SIZE
			);

			InsertReportToQueue(report);
		}
	}

free:

	if (buffer)
		ExFreePoolWithTag(buffer, POOL_TAG_APC);

	FreeApcAndDecrementApcCount(Apc, APC_CONTEXT_ID_STACKWALK);

	thread_list_entry->apc = NULL;
	thread_list_entry->apc_queued = FALSE;
}

/*
* The NormalRoutine is executed in user mode when the APC is delivered.
*/
STATIC
VOID
ApcNormalRoutine(
	_In_opt_ PVOID NormalContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
)
{

}

VOID
FlipKThreadMiscFlagsFlag(
	_In_ PKTHREAD Thread,
	_In_ LONG FlagIndex,
	_In_ BOOLEAN NewValue
)
{
	PLONG misc_flags = (PLONG)((UINT64)Thread + KTHREAD_MISC_FLAGS_OFFSET);
	LONG mask = 1U << FlagIndex;

	if (NewValue)
		*misc_flags |= mask;
	else
		*misc_flags &= ~mask;
}

#define THREAD_STATE_TERMINATED 4
#define THREAD_STATE_WAIT 5
#define THREAD_STATE_INIT 0

STATIC
VOID
ValidateThreadViaKernelApcCallback(
	_In_ PTHREAD_LIST_ENTRY ThreadListEntry,
	_Inout_opt_ PVOID Context
)
{
	PKAPC apc = NULL;
	BOOLEAN apc_status = FALSE;
	PLONG misc_flags = NULL;
	PCHAR previous_mode = NULL;
	PUCHAR state = NULL;
	BOOLEAN apc_queueable = FALSE;
	PAPC_STACKWALK_CONTEXT context = (PAPC_STACKWALK_CONTEXT)Context;
	LPCSTR process_name = PsGetProcessImageFileName(ThreadListEntry->owning_process);

	/* we dont want to schedule an apc to threads owned by the kernel */
	if (ThreadListEntry->owning_process == PsInitialSystemProcess || !Context)
		return;

	/* We are not interested in these processess.. for now lol */
	if (!strcmp(process_name, "svchost.exe") ||
		!strcmp(process_name, "Registry") ||
		!strcmp(process_name, "smss.exe") ||
		!strcmp(process_name, "csrss.exe") ||
		!strcmp(process_name, "explorer.exe") ||
		!strcmp(process_name, "svchost.exe") ||
		!strcmp(process_name, "lsass.exe") ||
		!strcmp(process_name, "MemCompression"))
		return;

	DEBUG_LOG("Process: %s", process_name);

	if (ThreadListEntry->thread == KeGetCurrentThread() || !ThreadListEntry->thread)
		return;
	/*
	* Its possible to set the KThread->ApcQueueable flag to false ensuring that no APCs can be
	* queued to the thread, as KeInsertQueueApc will check this flag before queueing an APC so
	* lets make sure we flip this before before queueing ours. Since we filter out any system
	* threads this should be fine... c:
	*/
	misc_flags = (PLONG)((UINT64)ThreadListEntry->thread + KTHREAD_MISC_FLAGS_OFFSET);
	previous_mode = (PCHAR)((UINT64)ThreadListEntry->thread + KTHREAD_PREVIOUS_MODE_OFFSET);
	state = (PUCHAR)((UINT64)ThreadListEntry->thread + KTHREAD_STATE_OFFSET);

	/* we dont care about user mode threads */
	//if (*previous_mode == UserMode)
	//	return;

	/* todo: We should also flag all threads that have the flag set to false */
	if (*misc_flags >> KTHREAD_MISC_FLAGS_APC_QUEUEABLE == FALSE)
		FlipKThreadMiscFlagsFlag(ThreadListEntry->thread, KTHREAD_MISC_FLAGS_APC_QUEUEABLE, TRUE);

	/* 
	* force thread into an alertable state, noting that this does not guarantee that our APC will be 
	* run.
	*/
	if (*misc_flags >> KTHREAD_MISC_FLAGS_ALERTABLE == FALSE)
		FlipKThreadMiscFlagsFlag(ThreadListEntry->thread, KTHREAD_MISC_FLAGS_ALERTABLE, TRUE);

	apc = (PKAPC)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), POOL_TAG_APC);

	if (!apc)
		return;

	/*
	* KTHREAD->State values:
	*
	*  0 is INITIALIZED;
	*  1 is READY;
	*  2 is RUNNING;
	*  3 is STANDBY;
	*  4 is TERMINATED;
	*  5 is WAIT;
	*  6 is TRANSITION.
	*
	* Since we are unsafely enumerating the threads linked list, it's best just
	* to make sure we don't queue an APC to a terminated thread. We also check after
	* we've allocated memory for the apc to ensure the window between queuing our APC
	* and checking the thread state is as small as possible.
	*/

	//if (*state == THREAD_STATE_TERMINATED || THREAD_STATE_INIT)
	//{
	//	ExFreePoolWithTag(apc, POOL_TAG_APC);
	//	return;
	//}

	DEBUG_LOG("Apc: %llx", (UINT64)apc);

	KeInitializeApc(
		apc,
		ThreadListEntry->thread,
		OriginalApcEnvironment,
		ApcKernelRoutine,
		ApcRundownRoutine,
		ApcNormalRoutine,
		KernelMode,
		Context
	);

	apc_status = KeInsertQueueApc(
		apc,
		NULL,
		NULL,
		IO_NO_INCREMENT
	);

	if (!apc_status)
	{
		DEBUG_ERROR("KeInsertQueueApc failed");
		ExFreePoolWithTag(apc, POOL_TAG_APC);
		return;
	}

	ThreadListEntry->apc = apc;
	ThreadListEntry->apc_queued = TRUE;

	IncrementApcCount(APC_CONTEXT_ID_STACKWALK);
}

/*
* Since NMIs are only executed on the thread that is running on each logical core, it makes
* sense to make use of APCs that, while can be masked off, provide us to easily issue a callback
* routine to threads we want a stack trace of. Hence by utilising both APCs and NMIs we get
* excellent coverage of the entire system.
*/
NTSTATUS
ValidateThreadsViaKernelApc()
{
	NTSTATUS status;
	PAPC_STACKWALK_CONTEXT context = NULL;

	/* First, ensure we dont already have an ongoing operation */
	GetApcContext(&context, APC_CONTEXT_ID_STACKWALK);

	if (context)
	{
		DEBUG_LOG("Existing APC_STACKWALK operation already in progress.");
		return STATUS_ALREADY_INITIALIZED;
	}

	context = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(APC_STACKWALK_CONTEXT), POOL_TAG_APC);

	if (!context)
		return STATUS_MEMORY_NOT_ALLOCATED;

	context->header.context_id = APC_CONTEXT_ID_STACKWALK;
	context->modules = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(SYSTEM_MODULES), POOL_TAG_APC);

	if (!context->modules)
	{
		ExFreePoolWithTag(context, POOL_TAG_APC);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	status = GetSystemModuleInformation(context->modules);

	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(context->modules, POOL_TAG_APC);
		ExFreePoolWithTag(context, POOL_TAG_APC);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	status = InsertApcContext(context);

	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(context->modules, POOL_TAG_APC);
		ExFreePoolWithTag(context, POOL_TAG_APC);
		return status;
	}

	context->header.allocation_in_progress = TRUE;

	EnumerateThreadListWithCallbackRoutine(
		ValidateThreadViaKernelApcCallback,
		context
	);

	context->header.allocation_in_progress = FALSE;

	return status;
}

VOID
FreeApcStackwalkApcContextInformation(
	_Inout_ PAPC_STACKWALK_CONTEXT Context
)
{
	if (Context->modules->address)
		ExFreePoolWithTag(Context->modules->address, SYSTEM_MODULES_POOL);

	if (Context->modules)
		ExFreePoolWithTag(Context->modules, POOL_TAG_APC);
}

