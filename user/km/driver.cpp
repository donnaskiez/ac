#include "driver.h"

#include <iostream>

#include "../common.h"
#include <winternl.h>

typedef BOOLEAN( NTAPI* RtlDosPathNameToNtPathName_U )(
	PCWSTR DosPathName, PUNICODE_STRING NtPathName, PCWSTR* NtFileNamePart, PVOID DirectoryInfo );

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
	{
		LOG_ERROR( "Failed to open handle to driver with status 0x%x", GetLastError() );
		return;
	}

	this->NotifyDriverOnProcessLaunch();
}

kernelmode::Driver::~Driver()
{
	this->NotifyDriverOnProcessTermination();
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

struct REPORT_ID
{
	INT report_id;
};

VOID kernelmode::Driver::QueryReportQueue()
{
	BOOLEAN status;
	DWORD bytes_returned;
	PVOID buffer;
	LONG buffer_size;
	REPORT_ID* report_header;
	SIZE_T total_size = NULL;
	global::report_structures::OPEN_HANDLE_FAILURE_REPORT* handle_report;
	global::report_structures::ATTACH_PROCESS_REPORT* attach_report;

	buffer_size = 1024 * 2;
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

	LOG_INFO( "Report count: %d", header->count );

	if ( header->count == 0 )
		goto end;

	for ( INT i = 0; i < header->count; i++ )
	{
		report_header = (REPORT_ID*)( ( UINT64 )buffer + 
			sizeof( global::report_structures::OPEN_HANDLE_FAILURE_REPORT_HEADER ) + total_size );

		LOG_INFO( "Report id: %d", report_header->report_id );

		if ( report_header->report_id == REPORT_ILLEGAL_ATTACH_PROCESS )
		{
			attach_report = ( global::report_structures::ATTACH_PROCESS_REPORT* )(
				( UINT64 )buffer + sizeof( global::report_structures::OPEN_HANDLE_FAILURE_REPORT_HEADER ) + total_size );

			this->report_interface->ReportViolation( attach_report );

			total_size += sizeof( global::report_structures::ATTACH_PROCESS_REPORT );

			continue;
		}
		
		if ( report_header->report_id == REPORT_ILLEGAL_HANDLE_OPERATION )
		{
			handle_report = ( global::report_structures::OPEN_HANDLE_FAILURE_REPORT* )(
				( UINT64 )buffer + sizeof( global::report_structures::OPEN_HANDLE_FAILURE_REPORT_HEADER ) + total_size );

			this->report_interface->ReportViolation( handle_report );

			total_size += sizeof( global::report_structures::OPEN_HANDLE_FAILURE_REPORT );

			continue;
		}
	}

end:
	free( buffer );
}

VOID kernelmode::Driver::RunCallbackReportQueue()
{
	/*TODO have some volatile flag instead */
	this->QueryReportQueue();
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

	/*
	* allocate a buffer big enough for the entire module not including section headers or
	* packet headers, however it should be big enough since executable sections do not
	* make up 100% of the image size. Bit hacky but it works.
	*/
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

	this->report_interface->ServerSend( buffer, bytes_returned, CLIENT_REQUEST_MODULE_INTEGRITY_CHECK );

end:
	free( buffer );
}

VOID kernelmode::Driver::ScanForUnlinkedProcess()
{
	BOOLEAN status;
	DWORD bytes_returned;
	global::report_structures::INVALID_PROCESS_ALLOCATION_REPORT report;

	status = DeviceIoControl(
		this->driver_handle,
		IOCTL_SCAN_FOR_UNLINKED_PROCESS,
		NULL,
		NULL,
		&report,
		sizeof(report),
		&bytes_returned,
		NULL
	);

	if ( status == NULL || bytes_returned == NULL)
	{
		LOG_ERROR( "failed to scan for unlinked processes %x", GetLastError() );
		return;
	}

	this->report_interface->ServerSend( &report, bytes_returned, CLIENT_REQUEST_MODULE_INTEGRITY_CHECK );
}

VOID kernelmode::Driver::PerformIntegrityCheck()
{
	BOOLEAN status;

	status = DeviceIoControl(
		this->driver_handle,
		IOCTL_PERFORM_INTEGRITY_CHECK,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	);

	if ( status == NULL )
		LOG_ERROR( "Failed to perform integrity check with status %x", status );
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

VOID kernelmode::Driver::NotifyDriverOnProcessTermination()
{
	BOOLEAN status;
	
	status = DeviceIoControl(
		this->driver_handle,
		IOCTL_NOTIFY_DRIVER_ON_PROCESS_TERMINATION,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	);

	if ( status == NULL )
		LOG_ERROR( "NotifyDriverOnProcessTermination failed with status %x", status );
}

VOID kernelmode::Driver::ValidateKPRCBThreads()
{
	BOOLEAN status;
	DWORD bytes_returned;
	global::report_structures::HIDDEN_SYSTEM_THREAD_REPORT report;

	status = DeviceIoControl(
		this->driver_handle,
		IOCTL_VALIDATE_KPRCB_CURRENT_THREAD,
		NULL,
		NULL,
		&report,
		sizeof( report ),
		&bytes_returned,
		NULL
	);

	if ( status == NULL)
	{
		LOG_ERROR( "failed to validate kpcrb threads with status %x", GetLastError() );
		return;
	}

	if ( bytes_returned == NULL )
		return;

	this->report_interface->ServerSend( &report, bytes_returned, CLIENT_REQUEST_MODULE_INTEGRITY_CHECK );
}

VOID kernelmode::Driver::CheckForAttachedThreads()
{
	BOOLEAN status;

	status = DeviceIoControl(
		this->driver_handle,
		IOCTL_DETECT_ATTACHED_THREADS,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	);

	if ( status == NULL )
		LOG_ERROR( "failed to check for attached threads %x", GetLastError() );
}

VOID kernelmode::Driver::CheckDriverHeartbeat()
{

}

VOID kernelmode::Driver::VerifyProcessLoadedModuleExecutableRegions()
{
	HANDLE process_modules_handle;
	MODULEENTRY32 module_entry;
	BOOLEAN status;
	PROCESS_MODULE_INFORMATION module_information;
	PROCESS_MODULE_VALIDATION_RESULT validation_result;
	DWORD bytes_returned;
	RtlDosPathNameToNtPathName_U pRtlDosPathNameToNtPathName_U = NULL;
	UNICODE_STRING nt_path_name;

	pRtlDosPathNameToNtPathName_U = ( RtlDosPathNameToNtPathName_U )
		GetProcAddress( GetModuleHandle( L"ntdll.dll" ), "RtlDosPathNameToNtPathName_U" );

	process_modules_handle = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId() );

	if ( process_modules_handle == INVALID_HANDLE_VALUE )
	{
		LOG_ERROR( "CreateToolHelp32Snapshot with TH32CS_SNAPMODULE failed with status 0x%x", GetLastError() );
		return;
	}

	module_entry.dwSize = sizeof( MODULEENTRY32 );

	if ( !Module32First( process_modules_handle, &module_entry ) )
	{
		LOG_ERROR( "Module32First failed with status 0x%x", GetLastError() );
		return;
	}

	do
	{
		module_information.module_base = module_entry.modBaseAddr;
		module_information.module_size = module_entry.modBaseSize;

		( *pRtlDosPathNameToNtPathName_U )(
			module_entry.szExePath,
			&nt_path_name,
			NULL,
			NULL
		);

		memcpy( module_information.module_path, nt_path_name.Buffer, MAX_MODULE_PATH );

		status = DeviceIoControl(
			this->driver_handle,
			IOCTL_VALIDATE_PROCESS_LOADED_MODULE,
			&module_information,
			sizeof( module_information ),
			&validation_result,
			sizeof( validation_result ),
			&bytes_returned,
			NULL
		);

		if ( status == NULL || bytes_returned == NULL )
		{
			LOG_ERROR( "failed to validate process module with status %x", GetLastError() );
			continue;
		}

		if ( validation_result.is_module_valid == FALSE )
		{
			/*TODO: copy module aswell from an anomaly offset */
			global::report_structures::PROCESS_MODULES_INTEGRITY_CHECK_FAILURE report;
			report.report_code = REPORT_CODE_MODULE_VERIFICATION;
			report.module_base_address = (UINT64)module_entry.modBaseAddr;
			report.module_size = module_entry.modBaseSize;
			std::wstring wstr( module_entry.szModule );
			std::string module_name_string = std::string( wstr.begin(), wstr.end() );
			memcpy( &report.module_name, &module_name_string, module_name_string.length() );
			this->report_interface->ReportViolation( &report );
		}
		else
		{
			LOG_INFO("Module %S is valid", module_entry.szModule );
		}

	} while ( Module32Next( process_modules_handle, &module_entry ) );

end:
	CloseHandle( process_modules_handle );
}

VOID kernelmode::Driver::SendClientHardwareInformation()
{
	BOOLEAN status;
	global::headers::SYSTEM_INFORMATION system_information;
	DWORD bytes_returned;

	status = DeviceIoControl(
		this->driver_handle,
		IOCTL_REQUEST_HARDWARE_INFORMATION,
		NULL,
		NULL,
		&system_information,
		sizeof( global::headers::SYSTEM_INFORMATION ),
		&bytes_returned,
		NULL
	);

	if ( status == NULL || bytes_returned == NULL)
	{
		LOG_ERROR( "DeviceIoControl failed with status %x", GetLastError() );
		return;
	}

	this->report_interface->ServerSend( 
		&system_information, sizeof( global::headers::SYSTEM_INFORMATION ), CLIENT_SEND_SYSTEM_INFORMATION );
}

#pragma comment(lib, "debuglib")

VOID GetKernelStructureOffsets()
{
	KERNEL_STRUCTURE_OFFSETS offsets = { 0 };
	GetKernelStructureOffsets( &offsets );

	LOG_INFO( "KPROCESS->ThreadListHead: %lx", offsets.KPROCESS.thread_list_head );
	LOG_INFO( "KPROCESS->DirectoryTableBase: %lx", offsets.KPROCESS.directory_table_base );

	LOG_INFO( "EPROCESS->PeakVirtualSize: %lx", offsets.EPROCESS.peak_virtual_size );
	LOG_INFO( "EPROCESS->VadRoot: %lx", offsets.EPROCESS.vad_root );
	LOG_INFO( "EPROCESS->ObjectTable: %lx", offsets.EPROCESS.object_table );
	LOG_INFO( "EPROCESS->ImageFileName: %lx", offsets.EPROCESS.image_name );
	LOG_INFO( "EPROCESS->Peb: %lx", offsets.EPROCESS.process_environment_block );

	LOG_INFO( "KTHREAD->StackBase: %lx", offsets.KTHREAD.stack_base );
	LOG_INFO( "KTHREAD->StackLimit: %lx", offsets.KTHREAD.stack_limit );
	LOG_INFO( "KTHREAD->ThreadListEntry: %lx", offsets.KTHREAD.threadlist );
	LOG_INFO( "KTHREAD->ApcState: %lx", offsets.KTHREAD.apc_state );
	LOG_INFO( "KTHREAD->StartAddress: %lx", offsets.KTHREAD.start_address );
}
