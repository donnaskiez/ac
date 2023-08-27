#include "pool.h"

#include "common.h"

#include <intrin.h>

#define POOL_TAG_LENGTH 4

CHAR PROCESS_POOL_TAG[ POOL_TAG_LENGTH ] = "\x50\x72\x6f\x63";
CHAR THREAD_POOL_TAG[ POOL_TAG_LENGTH ] = "\x54\x68\x72\x64";
CHAR DESKTOP_POOL_TAG[ POOL_TAG_LENGTH ] = "\x44\x65\x73\x6B";
CHAR WINDOW_STATIONS_POOL_TAG[ POOL_TAG_LENGTH ] = "\x57\x69\x6E\x64";
CHAR MUTANTS_POOL_TAG[ POOL_TAG_LENGTH ] = "\x4D\x75\x74\x65";
CHAR FILE_OBJECTS_POOL_TAG[ POOL_TAG_LENGTH ] = "\x46\x69\x6C\x65";
CHAR DRIVERS_POOL_TAG[ POOL_TAG_LENGTH ] = "\x44\x72\x69\x76";
CHAR SYMBOLIC_LINKS_POOL_TAG[ POOL_TAG_LENGTH ] = "\x4C\x69\x6E\x6B";

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

	RtlCopyMemory( debugger_data, dump_header->KdDebuggerDataBlock,  sizeof( KDDEBUGGER_DATA64 ));

end:

	if ( dump_header )
		ExFreePoolWithTag( dump_header, POOL_DUMP_BLOCK_TAG );

	return debugger_data;
}

VOID ScanPageForKernelObjectAllocation(
	_In_ UINT64 PageBase,
	_In_ ULONG PageSize,
	_In_ LPCSTR ObjectTag
)
{
	INT length = 0;
	CHAR current_char;
	CHAR current_sig_byte;
	PPOOL_HEADER pool_header;
	PEPROCESS process;
	LPCSTR process_name;

	if ( !PageBase || !PageSize || !ObjectTag)
		return;

	PAGED_CODE();

	for ( INT offset = 0; offset <= PageSize - POOL_TAG_LENGTH; offset++ )
	{
		for ( INT sig_index = 0; sig_index < POOL_TAG_LENGTH + 1; sig_index++ )
		{
			if ( !MmIsAddressValid( PageBase + offset + sig_index ) )
				break;

			current_char = *( PCHAR )( PageBase + offset + sig_index );
			current_sig_byte = ObjectTag[ sig_index ];

			if ( sig_index == POOL_TAG_LENGTH )
			{
				pool_header = ( UINT64 )PageBase + offset - 0x04;

				if ( !MmIsAddressValid( (PVOID)pool_header ) )
					break;

				/*
				* This is some hard coded trash, need to figure out how we can differentiate different
				* types of objects since they would each have a varying number of headers, object sizes etc.
				*/
				if ( pool_header->BlockSize * CHUNK_SIZE - sizeof(POOL_HEADER) == WIN_PROCESS_ALLOCATION_SIZE )
				{
					/*
					* For ~70% of EPROCESS structures the header layout is as follows:
					* 
					* Pool base + 0x00 = ?? (not sure what structure lies here)
					* Pool base + 0x10 = OBJECT_HEADER_QUOTA_INFO
					* Pool base + 0x30 = OBJECT_HEADER_HANDLE_INFO
					* Pool base + 0x40 = OBJECT_HEADER
					* Pool base + 0x70 = EPROCESS
					* 
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

					process = (PEPROCESS)( ( UINT64 )pool_header + sizeof( POOL_HEADER ) + 0x70 );

					process_name = PsGetProcessImageFileName( process );

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
					DEBUG_LOG( "Found process: %s", process_name );
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

	if ( !PhysicalAddress || !PhysicalMemoryRanges )
		return FALSE;

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

VOID WalkKernelPageTables()
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
	PHYSICAL_ADDRESS physical;
	PPHYSICAL_MEMORY_RANGE physical_memory_ranges;
	KIRQL irql;

	physical_memory_ranges = MmGetPhysicalMemoryRangesEx2( NULL, NULL );

	if ( physical_memory_ranges == NULL )
	{
		DEBUG_ERROR( "LOL stupid cunt not working" );
		return;
	}

	/* raise our irql to ensure we arent preempted by NOOB threads */
	KeRaiseIrql( DISPATCH_LEVEL, &irql );

	/* disable interrupts to prevent any funny business occuring */
	_disable();

	cr3.BitAddress = __readcr3();

	physical.QuadPart = cr3.Bits.PhysicalAddress << PAGE_4KB_SHIFT;

	pml4_base.BitAddress = MmGetVirtualForPhysical( physical );

	if ( !MmIsAddressValid( pml4_base.BitAddress ) || !pml4_base.BitAddress )
		return;

	for ( INT pml4_index = 0; pml4_index < PML4_ENTRY_COUNT; pml4_index++ )
	{
		pml4_entry.BitAddress = *(UINT64*)( pml4_base.BitAddress + pml4_index * sizeof( UINT64 ) );

		if ( pml4_entry.Bits.Present == NULL )
			continue;

		physical.QuadPart = pml4_entry.Bits.PhysicalAddress << PAGE_4KB_SHIFT;

		pdpt_base = MmGetVirtualForPhysical( physical );

		if ( !pdpt_base || !MmIsAddressValid( pdpt_base ) )
			continue;

		for ( INT pdpt_index = 0; pdpt_index < PDPT_ENTRY_COUNT; pdpt_index++ )
		{
			pdpt_entry.BitAddress = *( UINT64* )( pdpt_base + pdpt_index * sizeof( UINT64 ) );

			if ( pdpt_entry.Bits.Present == NULL )
				continue;

			if ( IS_LARGE_PAGE( pdpt_entry.BitAddress ) )
			{
				/* 2GB size page */
				pdpt_large_entry.BitAddress = pdpt_entry.BitAddress;
				continue;
			}

			physical.QuadPart = pdpt_entry.Bits.PhysicalAddress << PAGE_4KB_SHIFT;

			pd_base = MmGetVirtualForPhysical( physical );

			if ( !pd_base || !MmIsAddressValid( pd_base ) )
				continue;

			for ( INT pd_index = 0; pd_index < PD_ENTRY_COUNT; pd_index++ )
			{
				pd_entry.BitAddress = *( UINT64* )( pd_base + pd_index * sizeof( UINT64 ) );

				if ( pd_entry.Bits.Present == NULL )
					continue;

				if ( IS_LARGE_PAGE( pd_entry.BitAddress ) )
				{
					/* 2MB size page */
					pd_large_entry.BitAddress = pd_entry.BitAddress;
					continue;
				}

				physical.QuadPart = pd_entry.Bits.PhysicalAddress << PAGE_4KB_SHIFT;

				pt_base = MmGetVirtualForPhysical( physical );

				if ( !pt_base || !MmIsAddressValid( pt_base ) )
					continue;

				for ( INT pt_index = 0; pt_index < PT_ENTRY_COUNT; pt_index++ )
				{
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

					ScanPageForKernelObjectAllocation( base_virtual_page, PAGE_BASE_SIZE, (LPCSTR)PROCESS_POOL_TAG );
				}
			}
		}
	}

	_enable();

	KeLowerIrql( irql );

	DEBUG_LOG( "Finished scanning memory" );
}

VOID ScanNonPagedPoolForProcessTags()
{
	NTSTATUS status;
	PKDDEBUGGER_DATA64 debugger_data = NULL;
	UINT64 non_paged_pool_start = NULL;
	UINT64 non_paged_pool_end = NULL;

	/* must free this */
	debugger_data = GetGlobalDebuggerData();

	if ( debugger_data == NULL )
	{
		DEBUG_ERROR( "Debugger data is null" );
		return STATUS_ABANDONED;
	}

	non_paged_pool_start = debugger_data->MmNonPagedPoolStart;
	non_paged_pool_end = debugger_data->MmNonPagedPoolEnd;

	DEBUG_LOG( "NonPagedPool start: %llx, end %llx", non_paged_pool_start, non_paged_pool_end );

	WalkKernelPageTables();

/*	for ( ; non_paged_pool_start <= non_paged_pool_end; non_paged_pool_start++ )
	{
		CHAR current_byte = *( CHAR* )non_paged_pool_start;
		DEBUG_LOG( "Current byte: %c", current_byte );
	*/

	ExFreePoolWithTag( debugger_data, POOL_DEBUGGER_DATA_TAG );
}