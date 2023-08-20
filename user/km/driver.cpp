#include "driver.h"

#include <iostream>

#include "../common.h"

kernelmode::Driver::Driver( LPCWSTR DriverName, std::shared_ptr<global::Report> ReportInterface )
{
	this->driver_name = DriverName;
	this->report_interface = ReportInterface;
	this->driver_handle = CreateFileW(
		DriverName,
		GENERIC_WRITE | GENERIC_READ | GENERIC_EXECUTE,
		0,
		0,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
		0
	);

	if ( this->driver_handle == INVALID_HANDLE_VALUE )
		LOG_ERROR( "Failed to open handle to driver with status 0x%x", GetLastError() );
}

void kernelmode::Driver::RunNmiCallbacks()
{
	BOOLEAN status;
	DWORD bytes_returned;
	global::report_structures::NMI_CALLBACK_FAILURE report;

	status = DeviceIoControl(
		this->driver_handle,
		IOCCTL_RUN_NMI_CALLBACKS,
		NULL,
		NULL,
		&report,
		sizeof( global::report_structures::NMI_CALLBACK_FAILURE ),
		&bytes_returned,
		( LPOVERLAPPED )NULL
	);

	if ( status == NULL )
	{
		LOG_ERROR( "DeviceIoControl failed with status code 0x%x", GetLastError() );
		return;
	}

	if ( bytes_returned == NULL )
	{
		LOG_INFO( "All threads valid, nmis fine." );
		return;
	}

	/* else, report */
	this->report_interface->ReportViolation( &report );
}

/*
* 1. Checks that every device object has a system module to back it
* 2. Checks the IOCTL dispatch routines to ensure they lie within the module
*/

void kernelmode::Driver::VerifySystemModules()
{
	BOOLEAN status;
	DWORD bytes_returned;
	PVOID buffer;
	SIZE_T buffer_size;
	SIZE_T header_size;
	global::report_structures::MODULE_VALIDATION_FAILURE_HEADER header;
	global::report_structures::MODULE_VALIDATION_FAILURE report;

	/*
	* allocate enough to report 5 invalid driver objects + header. The reason we use a raw
	* pointer here is so we can pass the address to DeviceIoControl. You are not able (atleast
	* as far as im concerned) to pass a shared ptr to DeviceIoControl.
	*/
	header_size = sizeof( global::report_structures::MODULE_VALIDATION_FAILURE_HEADER );

	buffer_size = sizeof( global::report_structures::MODULE_VALIDATION_FAILURE ) *
		MODULE_VALIDATION_FAILURE_MAX_REPORT_COUNT +
		header_size;

	buffer = malloc( buffer_size );

	if ( !buffer )
		return;

	status = DeviceIoControl(
		this->driver_handle,
		IOCTL_VALIDATE_DRIVER_OBJECTS,
		NULL,
		NULL,
		buffer,
		buffer_size,
		&bytes_returned,
		NULL
	);

	if ( status == NULL )
	{
		LOG_ERROR( "DeviceIoControl failed with status code 0x%x", GetLastError() );
		free( buffer );
		return;
	}

	if ( bytes_returned == NULL )
	{
		LOG_INFO( "All modules valid :)" );
		free( buffer );
		return;
	}

	/*
	* We are splitting up each packet here and passing them on one by one since
	* if I am being honest it is just easier in c++ and that way the process
	* is streamlined just like all other report packets.
	*/
	memcpy( &header, buffer, sizeof( header_size ) );

	LOG_INFO( "module report count: %lx", header.module_count );

	UINT64 base = ( UINT64 )buffer + sizeof( header_size );

	for ( int i = 0; i < header.module_count; i++ )
	{
		memcpy(
			&report,
			PVOID( base + i * sizeof( global::report_structures::MODULE_VALIDATION_FAILURE ) ),
			sizeof( global::report_structures::MODULE_VALIDATION_FAILURE )
		);

		std::cout << report.report_code << " " << report.report_type << " " 
			<< report.driver_base_address << " " << report.driver_size << " "
			<< report.driver_name << std::endl;

		this->report_interface->ReportViolation( &report );

		/* sanity clear just in case ;) */
		RtlZeroMemory( &report, sizeof( global::report_structures::MODULE_VALIDATION_FAILURE ) );
	}

	free( buffer );
}

void kernelmode::Driver::EnableObRegisterCallbacks()
{
}

void kernelmode::Driver::DisableObRegisterCallbacks()
{
}

void kernelmode::Driver::EnableProcessLoadNotifyCallbacks()
{
}

void kernelmode::Driver::DisableProcessLoadNotifyCallbacks()
{
}

void kernelmode::Driver::ValidateKPRCBThreads()
{
}

void kernelmode::Driver::CheckForHypervisor()
{
}

void kernelmode::Driver::CheckDriverHeartbeat()
{
}
