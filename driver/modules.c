#include "modules.h"

#include "nmi.h"
#include "common.h"

NTSTATUS ValidateDriverIOCTLDispatchRegion(
	_In_ PDRIVER_OBJECT Driver,
	_In_ PSYSTEM_MODULES Modules,
	_In_ PBOOLEAN Flag
)
{
	NTSTATUS status;
	UINT64 current_function;

	UINT64 base = ( UINT64 )Driver->DriverStart;
	UINT64 end = base + Driver->DriverSize;

	*Flag = TRUE;

	/*
	* If the dispatch routine points to a location that is not in the confines of
	* the module, report it. Basic check but every effective for catching driver
	* dispatch hooking.
	*/

	for ( INT index = 0; index < IRP_MJ_MAXIMUM_FUNCTION + 1; index++ )
	{
		current_function = *(UINT64*)
			( ( UINT64 )Driver->MajorFunction + index * sizeof( PVOID ) );

		DEBUG_LOG( "Current function: %llx", current_function );

		if ( current_function == NULL )
			continue;

		if ( current_function >= base && current_function <= end )
		{
			DEBUG_LOG( "THIS ADDRESS IS INSIDE ITS REGIUON :)" );
			continue;
		}

		DEBUG_ERROR( "Driver with invalid IOCTL dispatch routine found" );
		*Flag = FALSE;
	}
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
			else
			{
				DEBUG_LOG( "All drivers have valid dispatch routines :)" );
			}

			sub_entry = sub_entry->ChainLink;
		}
	}

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
	header.module_count = head->count;

	if ( head->count > 0 )
	{
		DEBUG_LOG( "found INVALID drivers with count: %i", head->count );

		Irp->IoStatus.Information = sizeof( MODULE_VALIDATION_FAILURE_HEADER ) +
			MODULE_VALIDATION_FAILURE_MAX_REPORT_COUNT * sizeof( MODULE_VALIDATION_FAILURE );

		RtlCopyMemory(
			Irp->AssociatedIrp.SystemBuffer,
			&header,
			sizeof( MODULE_VALIDATION_FAILURE_HEADER ) );

		for ( INT i = 0; i < head->count; i++ )
		{
			/* make sure we free any non reported modules */
			if ( i >= MODULE_VALIDATION_FAILURE_MAX_REPORT_COUNT )
				RemoveInvalidDriverFromList( head );

			MODULE_VALIDATION_FAILURE report;
			report.report_code = REPORT_MODULE_VALIDATION_FAILURE;
			report.report_type = head->first_entry->reason;
			report.driver_base_address = head->first_entry->driver->DriverStart;
			report.driver_size = head->first_entry->driver->Size;

			RtlCopyMemory(
				&report.driver_name,
				head->first_entry->driver->DriverName.Buffer,
				MODULE_REPORT_DRIVER_NAME_BUFFER_SIZE );

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

	/*
	* Complete the IRP here so we don't have to implement a waiting mechanism
	* to prevent an early completion of the IRP.
	*/
	//IoCompleteRequest( Irp, IO_NO_INCREMENT );
	//Irp->IoStatus.Status = status;

	return status;
}