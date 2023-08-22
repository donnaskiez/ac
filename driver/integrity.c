#include "integrity.h"

#include "common.h"
#include "modules.h"

NTSTATUS CopyDriverExecutableRegions(
	_In_ PIRP Irp
)
{
	NTSTATUS status;
	SYSTEM_MODULES modules = { 0 };
	PRTL_MODULE_EXTENDED_INFO driver_info;
	MEMORY_BASIC_INFORMATION region_info;
	SIZE_T return_length;
	PVOID current;
	INT count = 0;

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

	current = driver_info->ImageBase;

	Irp->IoStatus.Information = driver_info->ImageSize;

	while (NT_SUCCESS( NtQueryVirtualMemory(
		NtCurrentProcess(),
		current,
		MemoryBasicInformation,
		&region_info,
		sizeof( MEMORY_BASIC_INFORMATION ),
		&return_length
	)))
	{
		if ( region_info.AllocationProtect & PAGE_EXECUTE )
		{
			RtlCopyMemory(
				(UINT64)Irp->AssociatedIrp.SystemBuffer + count * region_info.RegionSize,
				current,
				region_info.RegionSize
			);

			DEBUG_LOG( "Copied region at address: %p, with protect: %lx", current, region_info.AllocationProtect );
		}

		current = (UINT64)current + region_info.RegionSize;
	}

end:

	Irp->IoStatus.Status = status;

	if ( modules.address )
		ExFreePoolWithTag( modules.address, SYSTEM_MODULES_POOL );

	return status;
}