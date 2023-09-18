#include "pool.h"

#include "common.h"

#include "callbacks.h"
#include "queue.h"

#include <intrin.h>

#define POOL_TAG_LENGTH 4
#define EXECUTIVE_OBJECT_COUNT 8

#define INDEX_PROCESS_POOL_TAG 0
#define INDEX_THREAD_POOL_TAG 1
#define INDEX_DESKTOP_POOL_TAG 2
#define INDEX_WINDOW_STATIONS_POOL_TAG 3
#define INDEX_MUTANTS_POOL_TAG 4
#define INDEX_FILE_OBJECTS_POOL_TAG 5
#define INDEX_DRIVERS_POOL_TAG 6
#define INDEX_SYMBOLIC_LINKS_POOL_TAG 7

CHAR EXECUTIVE_OBJECT_POOL_TAGS[ EXECUTIVE_OBJECT_COUNT ][ POOL_TAG_LENGTH ] =
{
	"\x50\x72\x6f\x63",		/* Process */
	"\x54\x68\x72\x64",		/* Thread */
	"\x44\x65\x73\x6B",		/* Desktop */
	"\x57\x69\x6E\x64",		/* Windows Station */
	"\x4D\x75\x74\x65",		/* Mutants i.e mutex etc. */
	"\x46\x69\x6C\x65",		/* File objects */
	"\x44\x72\x69\x76",		/* Drivers */
	"\x4C\x69\x6E\x6B"		/* Symbolic links */
};

PVOID process_buffer = NULL;
ULONG process_count = NULL;

PKDDEBUGGER_DATA64 GetGlobalDebuggerData()
{
	CONTEXT context = { 0 };
	PDUMP_HEADER dump_header = { 0 };
	UINT64 thread_state;
	PKDDEBUGGER_DATA64 debugger_data = NULL;

	context.ContextFlags = CONTEXT_FULL;

	RtlCaptureContext( &context );

	dump_header = ExAllocatePool2( POOL_FLAG_NON_PAGED, DUMP_BLOCK_SIZE, POOL_DUMP_BLOCK_TAG );

	if ( !dump_header )
		goto end;

	KeCapturePersistentThreadState(
		&context,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		dump_header
	);

	debugger_data = ( PKDDEBUGGER_DATA64 )ExAllocatePool2( POOL_FLAG_NON_PAGED, sizeof( KDDEBUGGER_DATA64 ), POOL_DEBUGGER_DATA_TAG );

	if ( !debugger_data )
		goto end;

	RtlCopyMemory( debugger_data, dump_header->KdDebuggerDataBlock, sizeof( KDDEBUGGER_DATA64 ) );

end:

	if ( dump_header )
		ExFreePoolWithTag( dump_header, POOL_DUMP_BLOCK_TAG );

	return debugger_data;
}

VOID GetPsActiveProcessHead(
	_In_ PUINT64 Address
)
{
	PKDDEBUGGER_DATA64 debugger_data = GetGlobalDebuggerData();

	*Address = *( UINT64* )( debugger_data->PsActiveProcessHead );

	ExFreePoolWithTag( debugger_data, POOL_DEBUGGER_DATA_TAG );
}

/*
* Here we define a signature that can be used to find EPROCESS structures consistently across
* major windows versions. The fields we test have proven to be consistent in the following study:
* 
* https://www.cise.ufl.edu/~traynor/papers/ccs09b.pdf
* 
* Aswell as some of my own additional research and testing. The following signature is used:
* 
* PeakVirtualSize must be greater then 0 for any valid process:
*	-> EPROCESS->PeakVirtualSize > 0
* 
* The DirectoryTableBase must be 0x20 aligned:
*	-> EPROCESS->DirectoryTableBase % 20 == 0
* 
* The pool allocation size must be greater then the size of an EPROCESS allocation and 
* less then the size of a page. Allocation size can be found with the following formula:
*	-> AllocationSize = POOL_HEADER->BlockSize * CHUNK_SIZE - sizeof(POOL_HEADER)
*	-> AllocationSize > sizeof(EPROCESS) 
*	-> AllocationSize < PAGE_SIZE (4096)
* 
* Pool type must be non-null:
*	-> POOL_HEADER->PoolType != NULL
* 
* The process PEB must be a usermode address and 0x1000 aligned:
*	-> EPROCESS->Peb & 0x7ffd0000 == 0x7ffd0000 && EPROCESS->Peb % 0x1000 == 0
* 
* The object table must have the following properties and be 0x8 aligned:
*	-> EPROCESS->ObjectTable & 0xe0000000 == 0xe0000000 && EPROCESS->ObjectTable % 0x8 == 0
* 
* The allocation size, when AND'd with 0xfff0 must not equal 0xfff0:
*	-> AllocationSize & 0xfff0 != 0xfff0
* 
* This signature will allow us to consistently and accurately determine if a given pool allocation is
* indeed an executive process allocation across major versions of Windows.
*/
BOOLEAN ValidateIfAddressIsProcessStructure(
	_In_ PVOID Address,
	_In_ PPOOL_HEADER PoolHeader
)
{
	UINT64 peak_virtual_size = NULL;
	UINT64 dir_table_base = NULL;
	UINT64 allocation_size = NULL;
	UINT64 peb = NULL;
	UINT64 object_table = NULL;
	BOOLEAN peb_test = FALSE;
	BOOLEAN object_table_test = FALSE;
	UINT64 allocation_size_test = NULL;

	if ( MmIsAddressValid( ( UINT64 )Address + KPROCESS_DIRECTORY_TABLE_BASE_OFFSET ) )
		dir_table_base = *( UINT64* )( ( UINT64 )Address + KPROCESS_DIRECTORY_TABLE_BASE_OFFSET );

	if ( MmIsAddressValid( ( UINT64 )Address + EPROCESS_PEAK_VIRTUAL_SIZE_OFFSET ) )
		peak_virtual_size = *( UINT64* )( ( UINT64 )Address + EPROCESS_PEAK_VIRTUAL_SIZE_OFFSET );

	if ( MmIsAddressValid( ( UINT64 )PoolHeader + POOL_HEADER_BLOCK_SIZE_OFFSET ) )
		allocation_size = PoolHeader->BlockSize * CHUNK_SIZE - sizeof( POOL_HEADER );

	if ( MmIsAddressValid( ( UINT64 )Address + EPROCESS_PEB_OFFSET ) )
		peb = *( UINT64* )( ( UINT64 )Address + EPROCESS_PEB_OFFSET );

	if ( MmIsAddressValid((UINT64)Address + EPROCESS_OBJECT_TABLE_OFFSET ) )
		object_table = *( UINT64* )( ( UINT64 )Address + EPROCESS_OBJECT_TABLE_OFFSET );

	peb_test = peb == NULL || ( peb & 0x7ffd0000 == 0x7ffd0000 && peb % 0x1000 == NULL );
	object_table_test = object_table == NULL || ( object_table & 0xe0000000 == 0xe0000000 && object_table % 0x8 == 0 );
	allocation_size_test = allocation_size & 0xfff0;

	if ( peak_virtual_size > 0 && ( dir_table_base & 0x20 ) == 0 && 
		allocation_size > ( EPROCESS_SIZE + OBJECT_HEADER_SIZE + sizeof( POOL_HEADER ) ) &&
		PoolHeader->PoolType != NULL && !( allocation_size_test == 0xfff0 ) && !peb_test && !object_table_test )
	{
		return TRUE;
	}

	return FALSE;
}

/*
* OBJECT_HEADER->InfoMask is a bit mask that tells us which optional
* headers the object has. The bits are as follows:
*
* 0x1 = OBJECT_HEADER_CREATOR_INFO
* 0x2 = OBJECT_HEADER_NAME_INFO
* 0x4 = OBJECT_HEADER_HANDLE_INFO
* 0x8 = OBJECT_HEADER_QUOTA_INFO
* 0x10 = OBJECT_HEADER_PROCESS_INFO
* 0x20 = OBJECT_HEADER_AUDIT_INFO
* 0x40 = OBJECT_HEADER_HANDLE_REVOCATION_INFO
*/

/*
* Idea: since we don't know the number of headers or the exact memory layout of the object
* header section for these proc allocations, we can form an estimate address of base + 0x70
* and then iterate the loaded process list and if theres an address within say 0x50 of it we
* can assume that the process is legitmate. Then to find an unlinked process, it wouldn't
* exist in the loaded module list, check that it hasnt been deallocated and then focus on
* scanning it for name etc. Maybe scan for .exe extension?
*
* Also use the full name so we get the file extension and path not the 15 char long one
*/

VOID ScanPageForKernelObjectAllocation(
	_In_ UINT64 PageBase,
	_In_ ULONG PageSize,
	_In_ ULONG ObjectIndex,
	_In_ PVOID AddressBuffer
)
{
	INT length = 0;
	CHAR current_char;
	CHAR current_sig_byte;
	PPOOL_HEADER pool_header;
	PEPROCESS process = NULL;
	PEPROCESS process_size_one = NULL;
	PEPROCESS process_size_two = NULL;
	PEPROCESS test_process = NULL;
	LPCSTR process_name;
	PUINT64 address_list;
	ULONG allocation_size;
	ULONG minimum_process_allocation_size = EPROCESS_SIZE - sizeof( POOL_HEADER ) - OBJECT_HEADER_SIZE;

	if ( !PageBase || !PageSize )
		return;

	for ( INT offset = 0; offset <= PageSize - POOL_TAG_LENGTH - minimum_process_allocation_size; offset++ )
	{
		for ( INT sig_index = 0; sig_index < POOL_TAG_LENGTH + 1; sig_index++ )
		{
			if ( !MmIsAddressValid( PageBase + offset + sig_index ) )
				break;

			current_char = *( PCHAR )( PageBase + offset + sig_index );
			current_sig_byte = EXECUTIVE_OBJECT_POOL_TAGS[ ObjectIndex ][ sig_index ];

			if ( sig_index == POOL_TAG_LENGTH )
			{
				pool_header = ( UINT64 )PageBase + offset - POOL_HEADER_TAG_OFFSET;

				if ( !MmIsAddressValid( ( PVOID )pool_header ) )
					break;

				/* 
				* Since every executive allocation is required to have an _OBJECT_HEADER, we start
				* iterating from the size of this object header, then jump up in blocks of 0x10 since
				* every object header is divisible by 0x10. We iterate up to 0xb0 which is equal to the following:
				* 
				* 0xb0 = sizeof(ALL_HEADER_OBJECTS) + 0x10 where the 0x10 is 16 bytes of padding.
				*/
				for ( ULONG header_size = OBJECT_HEADER_SIZE; header_size < 0xb0; header_size += 0x10 )
				{
					test_process = ( PEPROCESS )( ( UINT64 )pool_header + sizeof( POOL_HEADER ) + header_size );

					if ( ValidateIfAddressIsProcessStructure( test_process, pool_header ) )
					{
						process = test_process;
						break;
					}
				}

				if ( process == NULL )
					break;

				DEBUG_LOG( "Process: %llx", (UINT64)process );

				address_list = ( PUINT64 )AddressBuffer;

				for ( INT i = 0; i < process_count; i++ )
				{
					if ( address_list[ i ] == NULL )
					{
						address_list[ i ] = ( UINT64 )process;
						break;
					}
				}

				break;
			}

			if ( current_char != current_sig_byte )
				break;
		}
	}
}

/*
* Using MmGetPhysicalMemoryRangesEx2(), we can get a block of structures that
* describe the physical memory layout. With each physical page base we are going
* to enumerate, we want to make sure it lies within an appropriate region of
* physical memory, so this function is to check for exactly that.
*/
BOOLEAN IsPhysicalAddressInPhysicalMemoryRange(
	_In_ UINT64 PhysicalAddress,
	_In_ PPHYSICAL_MEMORY_RANGE PhysicalMemoryRanges
)
{
	ULONG page_index = 0;
	UINT64 start_address = 0;
	UINT64 end_address = 0;

	while ( PhysicalMemoryRanges[ page_index ].NumberOfBytes.QuadPart != NULL )
	{
		start_address = PhysicalMemoryRanges[ page_index ].BaseAddress.QuadPart;
		end_address = start_address + PhysicalMemoryRanges[ page_index ].NumberOfBytes.QuadPart;

		if ( PhysicalAddress >= start_address && PhysicalAddress <= end_address )
			return TRUE;

		page_index++;
	}

	return FALSE;
}

VOID EnumerateKernelLargePages(
	_In_ UINT64 PageBase,
	_In_ ULONG PageSize,
	_In_ PVOID AddressBuffer,
	_In_ ULONG ObjectIndex
)
{
	/*
	* Split the large pages up into blocks of 0x1000 and scan each block
	*/
	for ( INT page_index = 0; page_index < PageSize; page_index++ )
	{
		ScanPageForKernelObjectAllocation(
			PageBase + ( page_index * PAGE_SIZE ),
			PAGE_SIZE,
			ObjectIndex,
			AddressBuffer
		);
	}
}

/*
* This is your basic page table walk function. On intel systems, paging has 4 levels,
* each table holds 512 entries with a total size of 0x1000 (512 * sizeof(QWORD)). Each entry
* in each table contains a value with a subset bitfield containing the physical address
* of the base of the next table in the structure. So for example, a PML4 entry contains
* a physical address that points to the base of the PDPT table, it is the same for a PDPT
* entry -> PD base and so on.
*
* However, as with all good things Windows has implemented security features meaning
* we cannot use functions such as MmCopyMemory or MmMapIoSpace on paging structures,
* so we must find another way to walk the pages. Luckily for us, there exists
* MmGetVirtualForPhysical. This function is self explanatory and returns the corresponding
* virtual address given a physical address. What this means is that we can extract a page
* entry physical address, pass it to MmGetVirtualForPhysical which returns us the virtual
* address of the base of the next page structure. This is because page tables are still
* mapped by the kernel and exist in virtual memory just like everything else and hence
* reading the value at all 512 entries from the virtual base will give us the equivalent
* value as directly reading the physical address.
*
* Using this, we essentially walk the page tables as any regular translation would
* except instead of simply reading the physical we translate it to a virtual address
* and extract the physical address from the value at each virtual address page entry.
*/

VOID WalkKernelPageTables( PVOID AddressBuffer )
{
	CR3 cr3;
	PML4E pml4_base;
	PML4E pml4_entry;
	UINT64 pdpt_base;
	UINT64 pd_base;
	UINT64 pt_base;
	PDPTE pdpt_entry;
	PDPTE_LARGE pdpt_large_entry;
	PDE pd_entry;
	PDE_LARGE pd_large_entry;
	PTE pt_entry;
	UINT64 base_physical_page;
	UINT64 base_virtual_page;
	UINT64 base_2mb_virtual_page;
	UINT64 base_1gb_virtual_page;
	PHYSICAL_ADDRESS physical;
	PPHYSICAL_MEMORY_RANGE physical_memory_ranges;
	KIRQL irql;

	physical_memory_ranges = MmGetPhysicalMemoryRangesEx2( NULL, NULL );

	if ( physical_memory_ranges == NULL )
	{
		DEBUG_ERROR( "LOL stupid cunt not working" );
		return;
	}

	cr3.BitAddress = __readcr3();

	physical.QuadPart = cr3.Bits.PhysicalAddress << PAGE_4KB_SHIFT;

	pml4_base.BitAddress = MmGetVirtualForPhysical( physical );

	if ( !MmIsAddressValid( pml4_base.BitAddress ) || !pml4_base.BitAddress )
		return;

	for ( INT pml4_index = 0; pml4_index < PML4_ENTRY_COUNT; pml4_index++ )
	{
		if ( !MmIsAddressValid( pml4_base.BitAddress + pml4_index * sizeof( UINT64 ) ) )
			continue;

		pml4_entry.BitAddress = *( UINT64* )( pml4_base.BitAddress + pml4_index * sizeof( UINT64 ) );

		if ( pml4_entry.Bits.Present == NULL )
			continue;

		physical.QuadPart = pml4_entry.Bits.PhysicalAddress << PAGE_4KB_SHIFT;

		pdpt_base = MmGetVirtualForPhysical( physical );

		if ( !pdpt_base || !MmIsAddressValid( pdpt_base ) )
			continue;

		for ( INT pdpt_index = 0; pdpt_index < PDPT_ENTRY_COUNT; pdpt_index++ )
		{
			if ( !MmIsAddressValid( pdpt_base + pdpt_index * sizeof( UINT64 ) ) )
				continue;

			pdpt_entry.BitAddress = *( UINT64* )( pdpt_base + pdpt_index * sizeof( UINT64 ) );

			if ( pdpt_entry.Bits.Present == NULL )
				continue;

			if ( IS_LARGE_PAGE( pdpt_entry.BitAddress ) )
			{
				/* 1gb size page */
				pdpt_large_entry.BitAddress = pdpt_entry.BitAddress;

				physical.QuadPart = pdpt_large_entry.Bits.PhysicalAddress << PAGE_1GB_SHIFT;

				if ( IsPhysicalAddressInPhysicalMemoryRange( physical.QuadPart, physical_memory_ranges ) == FALSE )
					continue;

				base_1gb_virtual_page = MmGetVirtualForPhysical( physical );

				if ( !base_1gb_virtual_page || !MmIsAddressValid( base_1gb_virtual_page ) )
					continue;

				EnumerateKernelLargePages(
					base_1gb_virtual_page,
					LARGE_PAGE_1GB_ENTRIES,
					AddressBuffer,
					INDEX_PROCESS_POOL_TAG
				);

				continue;
			}

			physical.QuadPart = pdpt_entry.Bits.PhysicalAddress << PAGE_4KB_SHIFT;

			pd_base = MmGetVirtualForPhysical( physical );

			if ( !pd_base || !MmIsAddressValid( pd_base ) )
				continue;

			for ( INT pd_index = 0; pd_index < PD_ENTRY_COUNT; pd_index++ )
			{
				if ( !MmIsAddressValid( pd_base + pd_index * sizeof( UINT64 ) ) )
					continue;

				pd_entry.BitAddress = *( UINT64* )( pd_base + pd_index * sizeof( UINT64 ) );

				if ( pd_entry.Bits.Present == NULL )
					continue;

				if ( IS_LARGE_PAGE( pd_entry.BitAddress ) )
				{
					/* 2MB size page */
					pd_large_entry.BitAddress = pd_entry.BitAddress;

					physical.QuadPart = pd_large_entry.Bits.PhysicalAddress << PAGE_2MB_SHIFT;

					if ( IsPhysicalAddressInPhysicalMemoryRange( physical.QuadPart, physical_memory_ranges ) == FALSE )
						continue;

					base_2mb_virtual_page = MmGetVirtualForPhysical( physical );

					if ( !base_2mb_virtual_page || !MmIsAddressValid( base_2mb_virtual_page ) )
						continue;

					EnumerateKernelLargePages(
						base_2mb_virtual_page,
						LARGE_PAGE_2MB_ENTRIES,
						AddressBuffer,
						INDEX_PROCESS_POOL_TAG
					);

					continue;
				}

				physical.QuadPart = pd_entry.Bits.PhysicalAddress << PAGE_4KB_SHIFT;

				if ( !MmIsAddressValid( pd_base + pd_index * sizeof( UINT64 ) ) )
					continue;

				pt_base = MmGetVirtualForPhysical( physical );

				if ( !pt_base || !MmIsAddressValid( pt_base ) )
					continue;

				for ( INT pt_index = 0; pt_index < PT_ENTRY_COUNT; pt_index++ )
				{
					if ( !MmIsAddressValid( pt_base + pt_index * sizeof( UINT64 ) ) )
						continue;

					pt_entry.BitAddress = *( UINT64* )( pt_base + pt_index * sizeof( UINT64 ) );

					if ( pt_entry.Bits.Present == NULL )
						continue;

					physical.QuadPart = pt_entry.Bits.PhysicalAddress << PAGE_4KB_SHIFT;

					/* if the page base isnt in a legit region, go next */
					if ( IsPhysicalAddressInPhysicalMemoryRange( physical.QuadPart, physical_memory_ranges ) == FALSE )
						continue;

					base_virtual_page = MmGetVirtualForPhysical( physical );

					/* stupid fucking intellisense error GO AWAY! */
					if ( base_virtual_page == NULL || !MmIsAddressValid( base_virtual_page ) )
						continue;

					ScanPageForKernelObjectAllocation(
						base_virtual_page,
						PAGE_BASE_SIZE,
						INDEX_PROCESS_POOL_TAG,
						AddressBuffer
					);
				}
			}
		}
	}

	DEBUG_LOG( "Finished scanning memory" );
}

VOID IncrementProcessCounter()
{
	process_count++;
}

VOID CheckIfProcessAllocationIsInProcessList(
	_In_ PEPROCESS Process
)
{
	PUINT64 allocation_address;

	for ( INT i = 0; i < process_count; i++ )
	{
		allocation_address = ( PUINT64 )process_buffer;

		if ( ( UINT64 )Process >= allocation_address[ i ] - PROCESS_OBJECT_ALLOCATION_MARGIN &&
			( UINT64 )Process <= allocation_address[ i ] + PROCESS_OBJECT_ALLOCATION_MARGIN )
		{
			RtlZeroMemory( ( UINT64 )process_buffer + i * sizeof( UINT64 ), sizeof( UINT64 ) );
		}
	}
}

NTSTATUS FindUnlinkedProcesses(
	_In_ PIRP Irp
)
{
	PUINT64 allocation_address;
	PINVALID_PROCESS_ALLOCATION_REPORT report_buffer = NULL;

	EnumerateProcessListWithCallbackFunction(
		IncrementProcessCounter,
		NULL
	);

	if ( process_count == NULL )
	{
		DEBUG_ERROR( "Faield to get process count " );
		return STATUS_ABANDONED;
	}

	process_buffer = ExAllocatePool2( POOL_FLAG_NON_PAGED, process_count * 2 * sizeof( UINT64 ), PROCESS_ADDRESS_LIST_TAG );

	if ( !process_buffer )
		return STATUS_ABANDONED;

	WalkKernelPageTables( process_buffer );

	EnumerateProcessListWithCallbackFunction(
		CheckIfProcessAllocationIsInProcessList,
		NULL
	);

	allocation_address = ( PUINT64 )process_buffer;

	for ( INT i = 0; i < process_count; i++ )
	{
		if ( allocation_address[ i ] == NULL )
			continue;

		/* report / do some further analysis etc. */
		DEBUG_ERROR( "INVALID POOL proc OMGGG" );

		report_buffer = ExAllocatePool2( POOL_FLAG_NON_PAGED, sizeof( INVALID_PROCESS_ALLOCATION_REPORT ), REPORT_POOL_TAG );

		if ( !report_buffer )
			goto end;

		report_buffer->report_code = REPORT_INVALID_PROCESS_ALLOCATION;

		RtlCopyMemory(
			report_buffer->process,
		    (UINT64)allocation_address[ i ] - OBJECT_HEADER_SIZE,
			REPORT_INVALID_PROCESS_BUFFER_SIZE 
		);

		InsertReportToQueue( report_buffer );
	}

end:

	if ( process_buffer )
		ExFreePoolWithTag( process_buffer, PROCESS_ADDRESS_LIST_TAG );

	/* todo: make use of the new context variable in the enum proc func */
	process_count = NULL;
	process_buffer = NULL;

	return STATUS_SUCCESS;
}