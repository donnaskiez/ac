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

NTSTATUS GetModuleInformationByName(
	_In_ PRTL_MODULE_EXTENDED_INFO ModuleInfo,
	_In_ LPCSTR ModuleName
)
{
	NTSTATUS status = STATUS_SUCCESS;
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

	ModuleInfo->FileNameOffset = driver_info->FileNameOffset;
	ModuleInfo->ImageBase = driver_info->ImageBase;
	ModuleInfo->ImageSize = driver_info->ImageSize;

	RtlCopyMemory(
		ModuleInfo->FullPathName,
		driver_info->FullPathName,
		sizeof( ModuleInfo->FullPathName )
	);

	if ( modules.address )
		ExFreePoolWithTag( modules.address, SYSTEM_MODULES_POOL );

	return status;
}

NTSTATUS StoreModuleExecutableRegionsInBuffer(
	_In_ PVOID* Buffer,
	_In_ PVOID ModuleBase,
	_In_ SIZE_T ModuleSize,
	_In_ PSIZE_T BytesWritten
)
{
	NTSTATUS status = STATUS_SUCCESS;
	PIMAGE_DOS_HEADER dos_header;
	PLOCAL_NT_HEADER nt_header;
	PIMAGE_SECTION_HEADER section;
	ULONG total_packet_size = 0;
	ULONG num_sections = 0;
	ULONG num_executable_sections = 0;
	UINT64 buffer_base;
	ULONG bytes_returned;
	MM_COPY_ADDRESS address;

	if ( !ModuleBase || !ModuleSize )
		return STATUS_INVALID_PARAMETER;

	DEBUG_LOG( "Module base: %llx, size: %llx", (UINT64)ModuleBase, ModuleSize );

	/*
	* The reason we allocate a buffer to temporarily hold the section data is that
	* we don't know the total size until after we iterate over the sections meaning
	* we cant set Irp->IoStatus.Information to the size of our reponse until we
	* enumerate and count all executable sections for the file.
	*/
	*Buffer = ExAllocatePool2( POOL_FLAG_NON_PAGED, ModuleSize + sizeof( INTEGRITY_CHECK_HEADER ), POOL_TAG_INTEGRITY );

	if ( !*Buffer )
		return STATUS_ABANDONED;

	/*
	* Note: Verifier doesn't like it when we map the module :c
	*/

	dos_header = ( PIMAGE_DOS_HEADER )ModuleBase;

	/*
	* The IMAGE_DOS_HEADER.e_lfanew stores the offset of the IMAGE_NT_HEADER from the base
	* of the image.
	*/
	nt_header = ( struct _IMAGE_NT_HEADERS64* )( ( UINT64 )ModuleBase + dos_header->e_lfanew );

	num_sections = nt_header->FileHeader.NumberOfSections;

	/*
	* The IMAGE_FIRST_SECTION macro takes in an IMAGE_NT_HEADER and returns the address of
	* the first section of the PE file.
	*/
	section = IMAGE_FIRST_SECTION( nt_header );

	buffer_base = ( UINT64 )*Buffer + sizeof( INTEGRITY_CHECK_HEADER );

	for ( ULONG index = 0; index < num_sections; index++ )
	{
		DEBUG_LOG( "section name: %s, size: %lx", section->Name, section->SizeOfRawData );

		if ( section->Characteristics & IMAGE_SCN_MEM_EXECUTE )
		{
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
				ExFreePoolWithTag( *Buffer, POOL_TAG_INTEGRITY );
				return status;
			}

			address.VirtualAddress = ( UINT64 )ModuleBase + section->PointerToRawData;

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
				ExFreePoolWithTag( *Buffer, POOL_TAG_INTEGRITY );
				return status;
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
		*Buffer,
		&header,
		sizeof( INTEGRITY_CHECK_HEADER )
	);

	*BytesWritten = total_packet_size + sizeof( INTEGRITY_CHECK_HEADER );

	return status;
}

NTSTATUS MapDiskImageIntoVirtualAddressSpace(
	_In_ PHANDLE SectionHandle,
	_In_ PVOID* Section,
	_In_ PUNICODE_STRING Path,
	_In_ PSIZE_T Size
)
{
	NTSTATUS status;
	HANDLE file_handle;
	OBJECT_ATTRIBUTES object_attributes;
	PIO_STATUS_BLOCK pio_block;
	UNICODE_STRING path;

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
		FILE_GENERIC_EXECUTE | SYNCHRONIZE,
		&object_attributes,
		&pio_block,
		FILE_GENERIC_EXECUTE,
		NULL
	);

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "ZwOpenFile failed with statsu %x", status );
		return status;
	}

	object_attributes.ObjectName = NULL;
	
	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "NTSetInformationProcess failed with status %x", status );
		ZwClose( file_handle );
		return status;
	}

	/*
	* Its important that we set the SEC_IMAGE flag with the PAGE_READONLY
	* flag as we are mapping an executable image.
	*/
	status = ZwCreateSection(
		SectionHandle,
		SECTION_ALL_ACCESS,
		&object_attributes,
		NULL,
		PAGE_EXECUTE_READWRITE,
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
		*SectionHandle,
		ZwCurrentProcess(),
		Section,
		NULL,
		NULL,
		NULL,
		Size,
		ViewUnmap,
		MEM_TOP_DOWN,
		PAGE_READWRITE
	);

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "ZwMapViewOfSection failed with status %x", status );
		ZwClose( file_handle );
		ZwClose( *SectionHandle );
		return status;
	}

	DEBUG_LOG( "mapped LOL!" );
	ZwClose( file_handle );

	return status;
}

/*
* 1. map driver to memory
* 2. store executable sections in buffer
* 3. do the same with the in-memory module
* 4. hash both buffers with the current time or something
* 5. compare
*/
NTSTATUS VerifyInMemoryImageVsDiskImage(
	//_In_ PIRP Irp
)
{
	NTSTATUS status;
	UNICODE_STRING path;
	HANDLE section_handle = NULL;
	PVOID section = NULL;
	SIZE_T section_size = NULL;
	SIZE_T bytes_written = NULL;
	PVOID disk_buffer = NULL;
	PVOID in_memory_buffer = NULL;
	RTL_MODULE_EXTENDED_INFO module_info = { 0 };


	/*
	* Map the disk image into memory and parse it. Note that we still need to parse the PE
	* file since the on-disk version is different to the in memory module before we
	* compare the executable sections.
	*/

	RtlInitUnicodeString( &path, L"\\SystemRoot\\System32\\Drivers\\driver.sys" );

	status = MapDiskImageIntoVirtualAddressSpace(
		&section_handle,
		&section,
		&path,
		&section_size
	);

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "MapDiskImageIntoVirtualAddressSpace failed with status %x", status );
		return status;
	}

	status = StoreModuleExecutableRegionsInBuffer(
		&disk_buffer,
		section,
		section_size,
		&bytes_written
	);

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "StoreModuleExecutableRegionsInBuffer failed with status %x", status );
		goto end;
	}

	/*
	* Parse the in-memory module
	*/

	status = GetModuleInformationByName(
		&module_info,
		"driver.sys"
	);

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "GetModuleInformationByName failed with status %x", status );
		goto end;
	}

	status = StoreModuleExecutableRegionsInBuffer(
		&in_memory_buffer,
		module_info.ImageBase,
		module_info.ImageSize,
		&bytes_written
	);

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "StoreModuleExecutableRegionsInBuffe failed with status %x", status );
		goto end;
	}

	/*
	* The in memory text section seems to be around 1k bytes larger then on disk section
	*/
	UINT64 disk_base = ( UINT64 )( ( UINT64 )disk_buffer + sizeof( INTEGRITY_CHECK_HEADER ) + sizeof( IMAGE_SECTION_HEADER ) );
	UINT64 memory_base = ( UINT64 )( ( UINT64 )in_memory_buffer + sizeof( INTEGRITY_CHECK_HEADER ) + sizeof( IMAGE_SECTION_HEADER ) );

	PIMAGE_SECTION_HEADER disk_text_header = ( PIMAGE_SECTION_HEADER )( ( UINT64 )disk_buffer + sizeof( INTEGRITY_CHECK_HEADER ) );

	if ( !disk_base || !memory_base || !disk_buffer || !in_memory_buffer )
	{
		DEBUG_ERROR( "buffers are null lmao" );
		goto end;
	}

	DEBUG_LOG( "Disk base: %llx, memory base: %llx, disk_text header: %llx", disk_base, memory_base, ( UINT64 )disk_text_header );

	DEBUG_LOG( "Disk text header size of data: %lx", disk_text_header->SizeOfRawData );

	int result = RtlCompareMemory( (PVOID)disk_base, (PVOID)memory_base, disk_text_header->SizeOfRawData - 8000 );

	DEBUG_LOG( "Result: %lx", result );

	__debugbreak();

end:

	ZwUnmapViewOfSection( NtCurrentProcess(), section );

	if ( section_handle != NULL )
		ZwClose( section_handle );

	if ( disk_buffer )
		ExFreePoolWithTag( disk_buffer, POOL_TAG_INTEGRITY );

	if ( in_memory_buffer )
		ExFreePoolWithTag( in_memory_buffer, POOL_TAG_INTEGRITY );
}

NTSTATUS RetrieveInMemoryModuleExecutableSections(
	_In_ PIRP Irp
)
{
	NTSTATUS status;
	SIZE_T bytes_written = NULL;
	PVOID buffer = NULL;
	RTL_MODULE_EXTENDED_INFO module_info = { 0 };

	status = GetModuleInformationByName(
		&module_info,
		"driver.sys"
	);

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "GetModuleInformationByName failed with status %x", status );
		return status;
	}

	status = StoreModuleExecutableRegionsInBuffer(
		&buffer,
		module_info.ImageBase,
		module_info.ImageSize,
		&bytes_written
	);

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "StoreModuleExecutableRegionsInBuffe failed with status %x", status );
		return status;
	}

	Irp->IoStatus.Information = bytes_written;

	RtlCopyMemory(
		Irp->AssociatedIrp.SystemBuffer,
		buffer,
		bytes_written
	);

	if ( buffer )
		ExFreePoolWithTag( buffer, POOL_TAG_INTEGRITY );

	return status;
}