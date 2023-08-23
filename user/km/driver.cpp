#include "driver.h"

#include <iostream>

#include "../common.h"

kernelmode::Driver::Driver( LPCWSTR DriverName, std::shared_ptr<global::Client> ReportInterface )
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

VOID kernelmode::Driver::RunNmiCallbacks()
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

VOID kernelmode::Driver::VerifySystemModules()
{
	BOOLEAN status;
	DWORD bytes_returned;
	PVOID buffer;
	SIZE_T buffer_size;
	SIZE_T header_size;

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
	global::report_structures::MODULE_VALIDATION_FAILURE_HEADER* header =
		( global::report_structures::MODULE_VALIDATION_FAILURE_HEADER* )buffer;

	for ( int i = 0; i < header->module_count; i++ )
	{
		global::report_structures::MODULE_VALIDATION_FAILURE* report =
			( global::report_structures::MODULE_VALIDATION_FAILURE* )( 
				( UINT64 )buffer + sizeof( global::report_structures::MODULE_VALIDATION_FAILURE_HEADER ) + 
				i * sizeof( global::report_structures::MODULE_VALIDATION_FAILURE ) );

		this->report_interface->ReportViolation( report );
	}

	free( buffer );
}

/*
* HOW THIS WILL WORK:
* 
* 1. On driver initiation, ObRegisterCallbacks will be registered 
* 2. Each time a process that is not whitelisted tries to open a handle
*	 to our game we will store the report in an a report queue
* 3. the user mode app will then periodically query the driver asking
*	 how many pending reports there are
* 4. once the number is received, the app will allocate a buffer large enough
*	 for all the reports and once again call CompleteQueuedCallbackReports
* 5. This will then retrieve the reports into the buffer and from there
*    we can iteratively report them the same way as we do with the system
*	 modules.
*/

VOID kernelmode::Driver::QueryReportQueue()
{
	BOOLEAN status;
	DWORD bytes_returned;
	PVOID buffer;
	LONG buffer_size;
	global::report_structures::OPEN_HANDLE_FAILURE_REPORT report;

	buffer_size = sizeof( global::report_structures::OPEN_HANDLE_FAILURE_REPORT ) * MAX_HANDLE_REPORTS_PER_IRP + 
		sizeof( global::report_structures::OPEN_HANDLE_FAILURE_REPORT_HEADER );

	buffer = malloc( buffer_size );

	status = DeviceIoControl(
		this->driver_handle,
		IOCTL_HANDLE_REPORTS_IN_CALLBACK_QUEUE,
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

	global::report_structures::OPEN_HANDLE_FAILURE_REPORT_HEADER* header =
		( global::report_structures::OPEN_HANDLE_FAILURE_REPORT_HEADER* )buffer;

	if ( !header )
		goto end;

	if ( header->count == 0 )
		goto end;

	for ( int i = 0; i < header->count; i++ )
	{
		global::report_structures::OPEN_HANDLE_FAILURE_REPORT* report =
			( global::report_structures::OPEN_HANDLE_FAILURE_REPORT* )(
				( UINT64 )buffer + sizeof( global::report_structures::OPEN_HANDLE_FAILURE_REPORT_HEADER ) +
				i * sizeof( global::report_structures::OPEN_HANDLE_FAILURE_REPORT ) );

		this->report_interface->ReportViolation( report );
	}

end:
	free( buffer );
}

VOID kernelmode::Driver::RunCallbackReportQueue()
{
	/*TODO have some volatile flag instead */
	while ( true )
	{
		this->QueryReportQueue();
		std::this_thread::sleep_for( std::chrono::seconds( 10 ) );
	}
}

VOID kernelmode::Driver::NotifyDriverOnProcessLaunch()
{
	BOOLEAN status;
	kernelmode::DRIVER_INITIATION_INFORMATION information;
	information.protected_process_id = GetCurrentProcessId();

	status = DeviceIoControl(
		this->driver_handle,
		IOCTL_NOTIFY_DRIVER_ON_PROCESS_LAUNCH,
		&information,
		sizeof( kernelmode::DRIVER_INITIATION_INFORMATION ),
		NULL,
		NULL,
		NULL,
		NULL
	);

	if ( status == NULL )
		LOG_ERROR( "DeviceIoControl failed with status code 0x%x", GetLastError() );
}

VOID kernelmode::Driver::DetectSystemVirtualization()
{
	BOOLEAN status;
	HYPERVISOR_DETECTION_REPORT report;
	DWORD bytes_returned;

	status = DeviceIoControl(
		this->driver_handle,
		IOCTL_PERFORM_VIRTUALIZATION_CHECK,
		NULL,
		NULL,
		&report,
		sizeof( HYPERVISOR_DETECTION_REPORT ),
		&bytes_returned,
		NULL
	);

	if ( status == NULL )
	{
		LOG_ERROR( "DeviceIoControl failed virtualization detect with status %x", GetLastError() );
		return;
	}

	if ( report.aperf_msr_timing_check == TRUE || report.invd_emulation_check == TRUE )
		LOG_INFO( "HYPERVISOR DETECTED!!!" );

	/* shutdown the application or smth lmao */
}

VOID kernelmode::Driver::CheckHandleTableEntries()
{
	BOOLEAN status;
	DWORD bytes_returned;

	/*
	* Only pass the IOCTL code and nothing else since the reports are bundled
	* with the handle ObRegisterCallbacks report queue hence the QueryReportQueue
	* function will handle these reports.
	*/
	status = DeviceIoControl(
		this->driver_handle,
		IOCTL_ENUMERATE_HANDLE_TABLES,
		NULL,
		NULL,
		NULL,
		NULL,
		&bytes_returned,
		NULL
	);

	if ( status == NULL )
		LOG_ERROR( "CheckHandleTableEntries failed with status %x", status );
}

VOID kernelmode::Driver::RequestModuleExecutableRegions()
{
	BOOLEAN status;
	DWORD bytes_returned;
	ULONG module_size;
	PVOID buffer;

	module_size = this->RequestTotalModuleSize();

	if ( module_size == NULL )
	{
		LOG_ERROR( "RequestTotalModuleSize failed lolz" );
		return;
	}

	LOG_INFO( "module size: %lx", module_size );

	buffer = malloc( module_size );

	if ( !buffer )
		return;

	status = DeviceIoControl(
		this->driver_handle,
		IOCTL_RETRIEVE_MODULE_EXECUTABLE_REGIONS,
		NULL,
		NULL,
		buffer,
		module_size,
		&bytes_returned,
		NULL
	);

	if ( status == NULL )
	{
		LOG_ERROR( "failed to retrieve module executable regions lozl %x", GetLastError() );
		goto end;
	}

	LOG_INFO( "bytes returned: %lx", bytes_returned );

	this->report_interface->ServerSend( buffer, module_size, SERVER_SEND_MODULE_INTEGRITY_CHECK );

end:
	free( buffer );
}

ULONG kernelmode::Driver::RequestTotalModuleSize()
{
	BOOLEAN status;
	DWORD bytes_returned;
	ULONG module_size;

	status = DeviceIoControl(
		this->driver_handle,
		IOCTL_REQUEST_TOTAL_MODULE_SIZE,
		NULL,
		NULL,
		&module_size,
		sizeof(ULONG),
		&bytes_returned,
		NULL
	);

	if ( status == NULL )
		LOG_ERROR( "CheckHandleTableEntries failed with status %x", status );

	return module_size;
}

VOID kernelmode::Driver::ValidateKPRCBThreads()
{

}

VOID kernelmode::Driver::CheckDriverHeartbeat()
{

}
