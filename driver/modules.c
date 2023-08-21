#include "modules.h"

#include "nmi.h"
#include "common.h"

#define WHITELISTED_MODULE_TAG 'whte'

#define WHITELISTED_MODULE_COUNT 3
#define MODULE_MAX_STRING_SIZE 256

#define NTOSKRNL 1
#define CLASSPNP 2
#define WDF01000 3

CHAR WHITELISTED_MODULES[ WHITELISTED_MODULE_COUNT ][ MODULE_MAX_STRING_SIZE ] =
{
	"ntoskrnl.exe",
	"CLASSPNP.SYS",
	"Wdf01000.sys",
};

typedef struct _WHITELISTED_REGIONS
{
	UINT64 base;
	UINT64 end;

}WHITELISTED_REGIONS, *PWHITELISTED_REGIONS;

PRTL_MODULE_EXTENDED_INFO FindSystemModuleByName(
	_In_ LPCSTR ModuleName,
	_In_ PSYSTEM_MODULES SystemModules,
	_In_ PVOID Buffer
)
{
	if ( !ModuleName || !SystemModules || !Buffer )
		return STATUS_INVALID_PARAMETER;

	for ( INT index = 0; index < SystemModules->module_count; index++ )
	{
		PRTL_MODULE_EXTENDED_INFO system_module = ( PRTL_MODULE_EXTENDED_INFO )(
			( uintptr_t )SystemModules->address + index * sizeof( RTL_MODULE_EXTENDED_INFO ) );

		if ( strstr( system_module->FullPathName, ModuleName ) )
		{
			return system_module;
		}
	}
}

NTSTATUS PopulateWhitelistedModuleBuffer(
	_In_ PVOID Buffer,
	_In_ PSYSTEM_MODULES SystemModules
)
{
	if ( !Buffer || !SystemModules)
		return STATUS_INVALID_PARAMETER;

	for ( INT index = 0; index < WHITELISTED_MODULE_COUNT; index++ )
	{
		LPCSTR name = WHITELISTED_MODULES[ index ];

		PRTL_MODULE_EXTENDED_INFO module = FindSystemModuleByName( name, SystemModules, Buffer );

		WHITELISTED_REGIONS region;
		region.base = (UINT64)module->ImageBase;
		region.end = region.base + module->ImageSize;

		RtlCopyMemory(
			( UINT64 )Buffer + index * sizeof( WHITELISTED_REGIONS ),
			&region,
			sizeof( WHITELISTED_REGIONS )
		);
	}

	return STATUS_SUCCESS;
}

NTSTATUS ValidateDriverIOCTLDispatchRegion(
	_In_ PDRIVER_OBJECT Driver,
	_In_ PSYSTEM_MODULES Modules,
	_In_ PWHITELISTED_REGIONS WhitelistedRegions,
	_In_ PBOOLEAN Flag
)
{
	if ( !Modules || !Driver || !Flag || !WhitelistedRegions )
		return STATUS_INVALID_PARAMETER;

	UINT64 dispatch_function;
	UINT64 module_base;
	UINT64 module_end;

	*Flag = TRUE;

	dispatch_function = Driver->MajorFunction[ IRP_MJ_DEVICE_CONTROL ];

	if ( dispatch_function == NULL )
		return STATUS_SUCCESS;

	for ( INT index = 0; index < Modules->module_count; index++ )
	{
		PRTL_MODULE_EXTENDED_INFO system_module = ( PRTL_MODULE_EXTENDED_INFO )(
			( uintptr_t )Modules->address + index * sizeof( RTL_MODULE_EXTENDED_INFO ) );

		if ( system_module->ImageBase != Driver->DriverStart )
			continue;

		/* make sure our driver has a device object which is required for IOCTL */
		if ( Driver->DeviceObject == NULL )
			return STATUS_SUCCESS;

		module_base = ( UINT64 )system_module->ImageBase;
		module_end = module_base + system_module->ImageSize;

		/* firstly, check if its inside its own module */
		if ( dispatch_function >= module_base && dispatch_function <= module_end )
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
		for ( INT index = 0; index < WHITELISTED_MODULE_COUNT; index++ )
		{
			if ( dispatch_function >= WhitelistedRegions[ index ].base &&
				dispatch_function <= WhitelistedRegions[ index ].end )
				return STATUS_SUCCESS;
		}

		DEBUG_LOG( "name: %s, base: %p, size: %lx, dispatch: %llx, type: %lx",
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

VOID InitDriverList(
	_In_ PINVALID_DRIVERS_HEAD ListHead
)
{
	ListHead->count = 0;
	ListHead->first_entry = NULL;
}

VOID AddDriverToList(
	_In_ PINVALID_DRIVERS_HEAD InvalidDriversHead,
	_In_ PDRIVER_OBJECT Driver,
	_In_ INT Reason
)
{
	PINVALID_DRIVER new_entry = ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		sizeof( INVALID_DRIVER ),
		INVALID_DRIVER_LIST_ENTRY_POOL
	);

	if ( !new_entry )
		return;

	new_entry->driver = Driver;
	new_entry->reason = Reason;
	new_entry->next = InvalidDriversHead->first_entry;
	InvalidDriversHead->first_entry = new_entry;
}

VOID RemoveInvalidDriverFromList(
	_In_ PINVALID_DRIVERS_HEAD InvalidDriversHead
)
{
	if ( InvalidDriversHead->first_entry )
	{
		PINVALID_DRIVER entry = InvalidDriversHead->first_entry;
		InvalidDriversHead->first_entry = InvalidDriversHead->first_entry->next;
		ExFreePoolWithTag( entry, INVALID_DRIVER_LIST_ENTRY_POOL );
	}
}

VOID EnumerateInvalidDrivers(
	_In_ PINVALID_DRIVERS_HEAD InvalidDriversHead
)
{
	PINVALID_DRIVER entry = InvalidDriversHead->first_entry;

	while ( entry != NULL )
	{
		DEBUG_LOG( "Invalid Driver: %wZ", entry->driver->DriverName );
		entry = entry->next;
	}
}

NTSTATUS ValidateDriverObjectHasBackingModule(
	_In_ PSYSTEM_MODULES ModuleInformation,
	_In_ PDRIVER_OBJECT DriverObject,
	_Out_ PBOOLEAN Result
)
{
	if ( !ModuleInformation || !DriverObject || !Result )
		return STATUS_INVALID_PARAMETER;

	for ( INT i = 0; i < ModuleInformation->module_count; i++ )
	{
		PRTL_MODULE_EXTENDED_INFO system_module = ( PRTL_MODULE_EXTENDED_INFO )(
			( uintptr_t )ModuleInformation->address + i * sizeof( RTL_MODULE_EXTENDED_INFO ) );

		if ( system_module->ImageBase == DriverObject->DriverStart )
		{
			*Result = TRUE;
			return STATUS_SUCCESS;
		}
	}

	DEBUG_LOG( "invalid driver found" );
	*Result = FALSE;

	return STATUS_SUCCESS;
}

//https://imphash.medium.com/windows-process-internals-a-few-concepts-to-know-before-jumping-on-memory-forensics-part-3-4a0e195d947b
NTSTATUS GetSystemModuleInformation(
	_Out_ PSYSTEM_MODULES ModuleInformation
)
{
	if ( !ModuleInformation )
		return STATUS_INVALID_PARAMETER;

	ULONG size = 0;

	/*
	* query system module information without an output buffer to get
	* number of bytes required to store all module info structures
	*/
	if ( !NT_SUCCESS( RtlQueryModuleInformation(
		&size,
		sizeof( RTL_MODULE_EXTENDED_INFO ),
		NULL
	) ) )
	{
		DEBUG_ERROR( "Failed to query module information" );
		return STATUS_ABANDONED;
	}

	/* Allocate a pool equal to the output size of RtlQueryModuleInformation */
	PRTL_MODULE_EXTENDED_INFO driver_information = ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		size,
		SYSTEM_MODULES_POOL
	);

	if ( !driver_information )
	{
		DEBUG_ERROR( "Failed to allocate pool LOL" );
		return STATUS_ABANDONED;
	}

	/* Query the modules again this time passing a pointer to the allocated buffer */
	if ( !NT_SUCCESS( RtlQueryModuleInformation(
		&size,
		sizeof( RTL_MODULE_EXTENDED_INFO ),
		driver_information
	) ) )
	{
		DEBUG_ERROR( "Failed lolz" );
		ExFreePoolWithTag( driver_information, SYSTEM_MODULES_POOL );
		return STATUS_ABANDONED;
	}

	ModuleInformation->address = driver_information;
	ModuleInformation->module_count = size / sizeof( RTL_MODULE_EXTENDED_INFO );

	return STATUS_SUCCESS;
}

NTSTATUS ValidateDriverObjects(
	_In_ PSYSTEM_MODULES SystemModules,
	_In_ PINVALID_DRIVERS_HEAD InvalidDriverListHead
)
{
	if ( !SystemModules || !InvalidDriverListHead )
		return STATUS_INVALID_PARAMETER;

	HANDLE handle;
	OBJECT_ATTRIBUTES attributes = { 0 };
	PVOID directory = { 0 };
	UNICODE_STRING directory_name;
	NTSTATUS status;

	RtlInitUnicodeString( &directory_name, L"\\Driver" );

	InitializeObjectAttributes(
		&attributes,
		&directory_name,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL
	);

	if ( !NT_SUCCESS( ZwOpenDirectoryObject(
		&handle,
		DIRECTORY_ALL_ACCESS,
		&attributes
	) ) )
	{
		DEBUG_ERROR( "Failed to query directory object" );
		return STATUS_ABANDONED;
	}

	if ( !NT_SUCCESS( ObReferenceObjectByHandle(
		handle,
		DIRECTORY_ALL_ACCESS,
		NULL,
		KernelMode,
		&directory,
		NULL
	) ) )
	{
		DEBUG_ERROR( "Failed to reference directory by handle" );
		ZwClose( handle );
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

	POBJECT_DIRECTORY directory_object = ( POBJECT_DIRECTORY )directory;

	ExAcquirePushLockExclusiveEx( &directory_object->Lock, NULL );

	PVOID whitelisted_regions_buffer = ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		WHITELISTED_MODULE_COUNT * MODULE_MAX_STRING_SIZE,
		WHITELISTED_MODULE_TAG );

	if ( !whitelisted_regions_buffer )
		goto end;

	status = PopulateWhitelistedModuleBuffer(
		whitelisted_regions_buffer,
		SystemModules
	);

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "PopulateWhiteListedBuffer failed with status %x", status );
		goto end;
	}

	for ( INT i = 0; i < NUMBER_HASH_BUCKETS; i++ )
	{
		POBJECT_DIRECTORY_ENTRY entry = directory_object->HashBuckets[ i ];

		if ( !entry )
			continue;

		POBJECT_DIRECTORY_ENTRY sub_entry = entry;

		while ( sub_entry )
		{
			PDRIVER_OBJECT current_driver = sub_entry->Object;
			BOOLEAN flag;

			/* validate driver has backing module */

			if ( !NT_SUCCESS( ValidateDriverObjectHasBackingModule(
				SystemModules,
				current_driver,
				&flag
			) ) )
			{
				DEBUG_LOG( "Error validating driver object" );
				ExReleasePushLockExclusiveEx( &directory_object->Lock, 0 );
				ObDereferenceObject( directory );
				ZwClose( handle );
				return STATUS_ABANDONED;
			}

			if ( !flag )
			{
				InvalidDriverListHead->count += 1;
				AddDriverToList( InvalidDriverListHead, current_driver, REASON_NO_BACKING_MODULE );
			}

			/* validate drivers IOCTL dispatch routines */

			if ( !NT_SUCCESS( ValidateDriverIOCTLDispatchRegion(
				current_driver,
				SystemModules,
				(PWHITELISTED_REGIONS)whitelisted_regions_buffer,
				&flag
			) ) )
			{
				DEBUG_LOG( "Error validating drivers IOCTL routines" );
				ExReleasePushLockExclusiveEx( &directory_object->Lock, 0 );
				ObDereferenceObject( directory );
				ZwClose( handle );
				return STATUS_ABANDONED;
			}

			if ( !flag )
			{
				InvalidDriverListHead->count += 1;
				AddDriverToList( InvalidDriverListHead, current_driver, REASON_INVALID_IOCTL_DISPATCH );
			}

			sub_entry = sub_entry->ChainLink;
		}
	}

end:
	if ( whitelisted_regions_buffer) 
		ExFreePoolWithTag( whitelisted_regions_buffer, WHITELISTED_MODULE_TAG );

	ExReleasePushLockExclusiveEx( &directory_object->Lock, 0 );
	ObDereferenceObject( directory );
	ZwClose( handle );

	return STATUS_SUCCESS;
}

NTSTATUS HandleValidateDriversIOCTL(
	_In_ PIRP Irp
)
{
	NTSTATUS status = STATUS_SUCCESS;
	SYSTEM_MODULES system_modules = { 0 };

	/* Fix annoying visual studio linting error */
	RtlZeroMemory( &system_modules, sizeof( SYSTEM_MODULES ) );

	status = GetSystemModuleInformation( &system_modules );

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "Error retriving system module information" );
		return status;
	}

	PINVALID_DRIVERS_HEAD head =
		ExAllocatePool2( POOL_FLAG_NON_PAGED, sizeof( INVALID_DRIVERS_HEAD ), INVALID_DRIVER_LIST_HEAD_POOL );

	if ( !head )
	{
		ExFreePoolWithTag( system_modules.address, SYSTEM_MODULES_POOL );
		return STATUS_ABANDONED;
	}

	/*
	* Use a linked list here so that so we have easy access to the invalid drivers
	* which we can then use to copy the drivers logic for further analysis in
	* identifying drivers specifically used for the purpose of cheating
	*/

	InitDriverList( head );

	if ( !NT_SUCCESS( ValidateDriverObjects( &system_modules, head ) ) )
	{
		DEBUG_ERROR( "Failed to validate driver objects" );
		ExFreePoolWithTag( system_modules.address, SYSTEM_MODULES_POOL );
		return STATUS_ABANDONED;
	}

	MODULE_VALIDATION_FAILURE_HEADER header;

	header.module_count = head->count >= MODULE_VALIDATION_FAILURE_MAX_REPORT_COUNT
		? MODULE_VALIDATION_FAILURE_MAX_REPORT_COUNT
		: head->count;

	if ( head->count > 0 )
	{
		DEBUG_LOG( "found INVALID drivers with count: %i", head->count );

		Irp->IoStatus.Information = sizeof( MODULE_VALIDATION_FAILURE_HEADER ) +
			MODULE_VALIDATION_FAILURE_MAX_REPORT_COUNT * sizeof( MODULE_VALIDATION_FAILURE );

		RtlCopyMemory(
			Irp->AssociatedIrp.SystemBuffer,
			&header,
			sizeof( MODULE_VALIDATION_FAILURE_HEADER )
		);

		for ( INT i = 0; i < head->count; i++ )
		{
			/* make sure we free any non reported modules */
			if ( i >= MODULE_VALIDATION_FAILURE_MAX_REPORT_COUNT )
			{
				RemoveInvalidDriverFromList( head );
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
			if ( !NT_SUCCESS( status ) )
				DEBUG_ERROR( "RtlUnicodeStringToAnsiString failed with statsu %x", status );

			RtlCopyMemory(
				( UINT64 )Irp->AssociatedIrp.SystemBuffer + sizeof( MODULE_VALIDATION_FAILURE_HEADER ) + i * sizeof( MODULE_VALIDATION_FAILURE ),
				&report,
				sizeof( MODULE_VALIDATION_FAILURE ) );

			RemoveInvalidDriverFromList( head );
		}
	}
	else
	{
		DEBUG_LOG( "No INVALID drivers found :)" );
	}

	ExFreePoolWithTag( head, INVALID_DRIVER_LIST_HEAD_POOL );
	ExFreePoolWithTag( system_modules.address, SYSTEM_MODULES_POOL );

	return status;
}