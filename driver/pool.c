#include "pool.h"

#include "common.h"

#include <intrin.h>

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

VOID WalkKernelPageTables()
{
	CR3 cr3;
	PML4E pml4_base;
	PML4E pml4_entry;
	PDPTE pdpt_base;
	PDPTE pdpt_entry;
	PDPTE_LARGE pdpt_large_entry;
	PDE pd_base;
	PDE pd_entry;
	PDE_LARGE pd_large_entry;
	PTE pt_base;
	PTE pt_entry;
	UINT64 base_physical_page;
	PHYSICAL_ADDRESS physical;

	cr3.BitAddress = __readcr3();

	DEBUG_LOG( "cr3: %llx", cr3.BitAddress );

	physical.QuadPart = cr3.Bits.PhysicalAddress << 12;

	/* Get our PML4 base address */
	pml4_base.BitAddress = MmGetVirtualForPhysical( physical );

	if ( !MmIsAddressValid(pml4_base.BitAddress) || !pml4_base.BitAddress )
	{
		DEBUG_ERROR( "Pml4 base is null or invalid" );
		return;
	}

	for ( INT pml4_index = 0; pml4_index < 512; pml4_index++ )
	{
		/* get our PML4 entry*/
		pml4_entry.BitAddress = *(UINT64*)( pml4_base.BitAddress + pml4_index * sizeof( UINT64 ) );

		/* check the present bit */
		if ( pml4_entry.Bits.Present == NULL )
			continue;

		/* read our pml4 entry */
		physical.QuadPart = pml4_entry.Bits.PhysicalAddress << 12;

		pdpt_base.BitAddress = MmGetVirtualForPhysical( physical );

		if ( !pdpt_base.BitAddress || !MmIsAddressValid( pdpt_base.BitAddress ) )
			continue;

		for ( INT pdpt_index = 0; pdpt_index < 512; pdpt_index++ )
		{
			pdpt_entry.BitAddress = *( UINT64* )( pdpt_base.BitAddress + pdpt_index * sizeof( UINT64 ) );

			if ( pdpt_entry.Bits.Present == NULL )
				continue;

			if ( IS_LARGE_PAGE( pdpt_entry.BitAddress ) )
			{
				pdpt_large_entry.BitAddress = pdpt_entry.BitAddress;

				//scan large page bla bla 

				continue;
			}

			physical.QuadPart = pdpt_entry.Bits.PhysicalAddress << 12;

			pd_base.BitAddress = MmGetVirtualForPhysical( physical );

			if ( !pd_base.BitAddress || !MmIsAddressValid( pd_base.BitAddress ) )
				continue;

			for ( INT pd_index = 0; pd_index < 512; pd_index++ )
			{
				pd_entry.BitAddress = *( UINT64* )( pd_base.BitAddress + pd_index * sizeof( UINT64 ) );

				if ( pd_entry.Bits.Present == NULL )
					continue;

				if ( IS_LARGE_PAGE( pd_entry.BitAddress ) )
				{
					/* 2MB size page */
					pd_large_entry.BitAddress = pd_entry.BitAddress;

					//scan etc.

					continue;
				}

				physical.QuadPart = pd_entry.Bits.PhysicalAddress << 12;

				pt_base.BitAddress = MmGetVirtualForPhysical( physical );

				if ( !pt_base.BitAddress || !MmIsAddressValid( pt_base.BitAddress ) )
					continue;

				for ( INT pt_index = 0; pt_index < 512; pt_index++ )
				{
					pt_entry.BitAddress = *( UINT64* )( pt_base.BitAddress + pt_index * sizeof( UINT64 ) );

					if ( pt_entry.Bits.Present == NULL )
						continue;

					base_physical_page = pt_entry.Bits.PhysicalAddress << 12;
					

				}
			}
		}
	}

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