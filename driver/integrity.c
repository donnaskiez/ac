#include "integrity.h"

#include "common.h"
#include "modules.h"

typedef struct _INTEGRITY_CHECK_HEADER
{
	INT executable_section_count;
	LONG total_packet_size;

}INTEGRITY_CHECK_HEADER, *PINTEGRITY_CHECK_HEADER;

/*
* note: this can be put into its own function wihtout an IRP as argument then it can be used 
* in both the get driver image ioctl handler and the CopyDriverExecvutableRegions func
*/
NTSTATUS GetDriverImageSize(
	_In_ PIRP Irp
)
{
	NTSTATUS status;
	SYSTEM_MODULES modules = { 0 };
	PRTL_MODULE_EXTENDED_INFO driver_info;

	status = GetSystemModuleInformation( &modules );

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "GetSystemModuleInformation failed with status %x", status );
		return status;
	}

	driver_info = FindSystemModuleByName(
		"driver.sys",
		&modules
	);

	Irp->IoStatus.Information = sizeof( ULONG );
	RtlCopyMemory( Irp->AssociatedIrp.SystemBuffer, &driver_info->ImageSize, sizeof( ULONG ) );
	
	if (modules.address )
		ExFreePoolWithTag( modules.address, SYSTEM_MODULES_POOL );

	return status;
}

NTSTATUS CopyDriverExecutableRegions(
	_In_ PIRP Irp
)
{
	NTSTATUS status;
	SYSTEM_MODULES modules = { 0 };
	PRTL_MODULE_EXTENDED_INFO driver_info;
	PVOID mapped_address;
	PHYSICAL_ADDRESS physical_address;
	PIMAGE_DOS_HEADER dos_header;
	PLOCAL_NT_HEADER nt_header;
	PIMAGE_SECTION_HEADER section;
	ULONG total_packet_size = 0;
	ULONG previous_section_size = 0;
	PVOID buffer = NULL;
	ULONG num_sections = 0;
	ULONG num_executable_sections = 0;
	UINT64 buffer_base;
	ULONG bytes_returned;
	MM_COPY_ADDRESS address;

	status = GetSystemModuleInformation( &modules );

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "GetSystemModuleInformation failed with status %x", status );
		goto end;
	}

	driver_info = FindSystemModuleByName(
		"driver.sys",
		&modules
	);

	/*
	* The reason we allocate a buffer to temporarily hold the section data is that
	* we don't know the total size until after we iterate over the sections meaning
	* we cant set Irp->IoStatus.Information to the size of our reponse until we 
	* enumerate and count all executable sections for the file.
	*/
	buffer = ExAllocatePool2( POOL_FLAG_NON_PAGED, driver_info->ImageSize + sizeof( INTEGRITY_CHECK_HEADER ), POOL_TAG_INTEGRITY);

	if ( !buffer )
		goto end;

	/*
	* Note: Verifier doesn't like it when we map the module :c
	*/

	dos_header = ( PIMAGE_DOS_HEADER )driver_info->ImageBase;

	/*
	* The IMAGE_DOS_HEADER.e_lfanew stores the offset of the IMAGE_NT_HEADER from the base
	* of the image.
	*/
	nt_header = ( struct _IMAGE_NT_HEADERS64* )( ( UINT64 )driver_info->ImageBase + dos_header->e_lfanew );

	num_sections = nt_header->FileHeader.NumberOfSections;

	/*
	* The IMAGE_FIRST_SECTION macro takes in an IMAGE_NT_HEADER and returns the address of
	* the first section of the PE file.
	*/
	section = IMAGE_FIRST_SECTION( nt_header );

	buffer_base = ( UINT64 )buffer + sizeof( INTEGRITY_CHECK_HEADER );

	for ( ULONG index = 0; index < num_sections; index++ )
	{
		if ( section->Characteristics & IMAGE_SCN_MEM_EXECUTE )
		{
			DEBUG_LOG( "Found executable section with name: %s", section->Name );

			/*
			* Note: MmCopyMemory will fail on discardable sections.
			*/

			address.VirtualAddress = section;

			status = MmCopyMemory(
				( UINT64 )buffer_base + total_packet_size,
				address,
				sizeof( IMAGE_SECTION_HEADER ),
				MM_COPY_MEMORY_VIRTUAL,
				&bytes_returned
			);

			if ( !NT_SUCCESS( status ) )
			{
				DEBUG_ERROR( "MmCopyMemory failed with status %x", status );
				goto end;
			}

			address.VirtualAddress = ( UINT64 )driver_info->ImageBase + section->PointerToRawData;

			status = MmCopyMemory(
				( UINT64 )buffer_base + total_packet_size + sizeof( IMAGE_SECTION_HEADER ),
				address,
				section->SizeOfRawData,
				MM_COPY_MEMORY_VIRTUAL,
				&bytes_returned
			);

			if ( !NT_SUCCESS( status ) )
			{
				DEBUG_ERROR( "MmCopyMemory failed with status %x", status );
				goto end;
			}

			total_packet_size += section->SizeOfRawData + sizeof( IMAGE_SECTION_HEADER );
			num_executable_sections += 1;
		}

		section++;
	}

	INTEGRITY_CHECK_HEADER header = { 0 };
	header.executable_section_count = num_executable_sections;
	header.total_packet_size = total_packet_size + sizeof( INTEGRITY_CHECK_HEADER );

	RtlCopyMemory( 
		buffer, 
		&header, 
		sizeof( INTEGRITY_CHECK_HEADER ) 
	);

	//Irp->IoStatus.Information = total_packet_size;

	//RtlCopyMemory(
	//	Irp->AssociatedIrp.SystemBuffer,
	//	buffer,
	//	total_packet_size
	//);

end:

	//Irp->IoStatus.Status = status;

	if ( modules.address )
		ExFreePoolWithTag( modules.address, SYSTEM_MODULES_POOL );

	if ( buffer )
		ExFreePoolWithTag( buffer, POOL_TAG_INTEGRITY );

	return status;
}

/*
* 1. map driver to memory 
* 2. store executable sections in buffer
* 3. do the same with the in-memory module
* 4. hash both buffers with the current time or something 
* 5. compare 
*/
NTSTATUS MapDiskImageIntoVirtualAddressSpace()
{
	NTSTATUS status;
	HANDLE section_handle;
	HANDLE file_handle;
	OBJECT_ATTRIBUTES object_attributes;
	PIO_STATUS_BLOCK pio_block;
	PVOID section = NULL;
	SIZE_T size = 0;
	UNICODE_STRING path;

	/* TODO add this to global config */
	RtlInitUnicodeString( &path, L"\\SystemRoot\\System32\\Drivers\\driver.sys" );

	InitializeObjectAttributes(
		&object_attributes,
		&path,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		NULL
	);

	status = ZwOpenFile(
		&file_handle,
		FILE_GENERIC_READ | SYNCHRONIZE,
		&object_attributes,
		&pio_block,
		FILE_SHARE_READ,
		FILE_SYNCHRONOUS_IO_NONALERT
	);

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "ZwOpenFile failed with statsu %x", status );
		return status;
	}

	object_attributes.ObjectName = NULL;

	/*
	* Its important that we set the SEC_IMAGE_NO_EXECUTE flag with the PAGE_READONLY
	* flag as we are mapping an executable image.
	*/
	status = ZwCreateSection(
		&section_handle,
		SECTION_ALL_ACCESS,
		&object_attributes,
		NULL,
		PAGE_READONLY,
		SEC_IMAGE,
		file_handle
	);

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "ZwCreateSection failed with status %x", status );
		ZwClose( file_handle );
		return status;
	}

	status = ZwMapViewOfSection(
		section_handle,
		NtCurrentProcess(),
		&section,
		NULL,
		NULL,
		NULL,
		&size,
		ViewUnmap,
		MEM_TOP_DOWN,
		PAGE_READONLY
	);

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "ZwMapViewOfSection failed with status %x", status );
		ZwClose( file_handle );
		ZwClose( section_handle );
		return status;
	}

	DEBUG_LOG( "mapped LOL!" );



	ZwUnmapViewOfSection( NtCurrentProcess(), section );
	ZwClose( file_handle );
	ZwClose( section_handle );
}