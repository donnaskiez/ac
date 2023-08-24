#include "integrity.h"

#include "common.h"
#include "modules.h"

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

/*
* Instead of copying pages with the EDB (execute disable bit) not set, I am simply
* copying the entire image which we can then send to the server which can then can 
* analyse the executable sections from there. Until I find a better way to enumerate
* kernel memory without having to walk the pages tables to check the EDB bit this 
* is how I will be doing it. c:
* 
* TODO: We will hash this based on timestamp sent from the server.
*/
NTSTATUS CopyDriverExecutableRegions(
	_In_ PIRP Irp
)
{
	NTSTATUS status;
	SYSTEM_MODULES modules = { 0 };
	PRTL_MODULE_EXTENDED_INFO driver_info;
	MM_COPY_ADDRESS address;
	PVOID mapped_address;
	PHYSICAL_ADDRESS physical_address;
	SIZE_T bytes_returned;

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

	Irp->IoStatus.Information = driver_info->ImageSize;

	/*
	* Map the drivers physical memory into our IO space, then copy it into
	* our IRP buffer.
	*/
	physical_address.QuadPart = MmGetPhysicalAddress( driver_info->ImageBase ).QuadPart;

	mapped_address = MmMapIoSpace(
		physical_address,
		driver_info->ImageSize,
		MmNonCached
	);

	if ( !mapped_address )
	{
		DEBUG_ERROR( "Failed to MmMapIoSpace " );
		goto end;
	}

	RtlCopyMemory(
		Irp->AssociatedIrp.SystemBuffer,
		mapped_address,
		driver_info->ImageSize
	);

	if ( !NT_SUCCESS( status ) )
		DEBUG_ERROR( "MmCopyMemory failed with status %x", status );

end:

	Irp->IoStatus.Status = status;

	if ( modules.address )
		ExFreePoolWithTag( modules.address, SYSTEM_MODULES_POOL );

	return status;
}