#include "process.h"

#include "../common.h"
#include "../um/imports.h"
#include "memory.h"

#include "../client.h"

#include <ImageHlp.h>
#include <iostream>

const static char MASK_BYTE = '\x00';

usermode::Process::Process( std::shared_ptr<global::Client> ReportInterface )
{
	this->process_handle = GetCurrentProcess();
	this->process_id = GetCurrentProcessId();
	this->function_imports = std::make_unique<Imports>();
	this->report_interface = ReportInterface;
}

void usermode::Process::ValidateProcessThreads()
{
	HANDLE thread_snapshot_handle = INVALID_HANDLE_VALUE;
	THREADENTRY32 thread_entry;
	NTSTATUS status;
	HANDLE thread_handle;
	UINT64 start_address;
	bool result;

	pNtQueryInformationThread NtQueryInfo = 
		( pNtQueryInformationThread )this->function_imports->ImportMap["NtQueryInformationThread"];

	/* th32ProcessId ignored for TH32CS_SNAPTHREAD value */
	thread_snapshot_handle = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );

	if ( thread_snapshot_handle == INVALID_HANDLE_VALUE )
	{
		LOG_ERROR( "thread snapshot handle invalid with error 0x%x", GetLastError() );
		return;
	}

	thread_entry.dwSize = sizeof( THREADENTRY32 );

	if ( !Thread32First( thread_snapshot_handle, &thread_entry ))
	{
		LOG_ERROR( "Thread32First failed with status 0x%x", GetLastError() );
		CloseHandle( thread_snapshot_handle );
		return;
	}

	do
	{
		if ( thread_entry.th32OwnerProcessID != process_id )
			continue;

		thread_handle = OpenThread( THREAD_ALL_ACCESS, FALSE, thread_entry.th32ThreadID );

		if ( thread_handle == INVALID_HANDLE_VALUE )
			continue;

		status = NtQueryInfo(
			thread_handle,
			( THREADINFOCLASS )ThreadQuerySetWin32StartAddress,
			&start_address,
			sizeof( UINT64 ),
			NULL
		);

		if ( !NT_SUCCESS( status ) )
		{
			LOG_ERROR( "NtQueryInfo failed with status code 0x%lx", status );
			continue;
		}

		if ( CheckIfAddressLiesWithinValidProcessModule( start_address, &result ) )
		{
			if ( result == false )
			{
				global::report_structures::PROCESS_THREAD_START_FAILURE report;
				report.report_code = REPORT_CODE_START_ADDRESS_VERIFICATION;
				report.start_address = start_address;
				report.thread_id = thread_entry.th32ThreadID;
				this->report_interface->ReportViolation( &report );
			}
		}

	} while ( Thread32Next( thread_snapshot_handle, &thread_entry ) );
}

/*
* Iterates through a processes modules and confirms whether the address lies within the memory region
* of the module. A simple way to check if a thread is a valid thread, however there are ways around
* this check so it is not a perfect solution.
*/
bool usermode::Process::CheckIfAddressLiesWithinValidProcessModule( UINT64 Address, bool* Result )
{
	HANDLE process_modules_handle;
	MODULEENTRY32 module_entry;

	process_modules_handle = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, this->process_id );

	LOG_INFO( "Address: %llx", Address );

	if ( process_modules_handle == INVALID_HANDLE_VALUE )
	{
		LOG_ERROR( "CreateToolHelp32Snapshot with TH32CS_SNAPMODULE failed with status 0x%x", GetLastError() );
		return false;
	}

	module_entry.dwSize = sizeof( MODULEENTRY32 );

	if ( !Module32First( process_modules_handle, &module_entry ) )
	{
		LOG_ERROR( "Module32First failed with status 0x%x", GetLastError() );
		CloseHandle( process_modules_handle );
		return false;
	}

	do
	{
		UINT64 base = (UINT64)module_entry.modBaseAddr;
		UINT64 end = base + module_entry.modBaseSize;

		if ( Address >= base && Address <= end )
		{
			LOG_INFO( "found valid module LOL" );
			CloseHandle( process_modules_handle );
			*Result = true;
			return true;
		}

	} while ( Module32Next( process_modules_handle, &module_entry ) );

	CloseHandle( process_modules_handle );
	*Result = false;
	return true;
}


HANDLE usermode::Process::GetHandleToProcessGivenName( std::string ProcessName )
{
	std::wstring wide_process_name;
	std::wstring target_process_name;
	HANDLE process_snapshot_handle;
	HANDLE process_handle;
	PROCESSENTRY32 process_entry;

	wide_process_name = std::wstring( ProcessName.begin(), ProcessName.end() );
	process_snapshot_handle = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

	if ( process_snapshot_handle == INVALID_HANDLE_VALUE )
	{
		LOG_ERROR( "Failed to create snapshot of current running processes error: 0x%x", GetLastError() );
		return INVALID_HANDLE_VALUE;
	}

	process_entry.dwSize = sizeof( PROCESSENTRY32 );

	if ( !Process32First( process_snapshot_handle, &process_entry ) )
	{
		LOG_ERROR( "Failed to get the first process using Process32First error: 0x%x", GetLastError() );
		CloseHandle( process_snapshot_handle );
		return INVALID_HANDLE_VALUE;
	}

	do
	{
		process_handle = OpenProcess( 
			PROCESS_ALL_ACCESS,
			FALSE, 
			process_entry.th32ProcessID 
		);

		/*
		* this will generally fail due to a process being an elevated process and denying
		* us access so we dont really care if OpenProcess fails in most cases
		*/
		if ( process_handle == NULL )
			continue;

		target_process_name = std::wstring( process_entry.szExeFile );

		if ( wide_process_name == target_process_name )
		{
			LOG_INFO( "Found target process" );
			CloseHandle( process_snapshot_handle );
			return process_handle;
		}

	} while ( Process32Next( process_snapshot_handle, &process_entry ) );

	CloseHandle( process_snapshot_handle );
	return INVALID_HANDLE_VALUE;
}

bool usermode::Process::GetProcessBaseAddress( UINT64* Result )
{
	HANDLE process_modules_handle;
	MODULEENTRY32 module_entry;

	process_modules_handle = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, this->process_id );

	if ( process_modules_handle == INVALID_HANDLE_VALUE )
	{
		LOG_ERROR( "CreateToolHelp32Snapshot with TH32CS_SNAPMODULE failed with status 0x%x", GetLastError() );
		return false;
	}

	module_entry.dwSize = sizeof( MODULEENTRY32 );

	if ( !Module32First( process_modules_handle, &module_entry ) )
	{
		LOG_ERROR( "Module32First failed with status 0x%x", GetLastError() );
		CloseHandle( process_modules_handle );
		return false;
	}

	*Result = (UINT64)module_entry.modBaseAddr;
	CloseHandle( process_modules_handle );
	return true;
}

void usermode::Process::ScanProcessMemory()
{
	MEMORY_BASIC_INFORMATION memory_info = { 0 };
	UINT64 address;

	if ( !GetProcessBaseAddress( &address) )
	{
		LOG_ERROR( "Failed to get process base address with status 0x%x", GetLastError() );
		return;
	}

	while ( VirtualQueryEx(
			this->process_handle,
			( PVOID )address,
			&memory_info,
			sizeof( MEMORY_BASIC_INFORMATION )))
	{
		this->CheckPageProtection( &memory_info );
		this->PatternScanRegion(address, &memory_info);

		address += memory_info.RegionSize;
	}
}

void usermode::Process::PatternScanRegion( UINT64 Address, MEMORY_BASIC_INFORMATION* Page )
{
	/* todo: stream signatures from server */
	//char buf[] = "\x85\xc0\x74\x00\xb9\x00\x00\x00\x00\xcd";
	char buf[] = "\x55\x8B\xEC\xFF\x75\x00\xD9\x45\x00\x51\xD9\x1C\x00\xE8\x00\x00\x00\x00\x5D\xC2\x00\x00\xCC\xCC\xCC\xCC\xCC\xCC\xCC";
	std::vector<char> signature;

	for ( int i = 0; i < 10; i++ )
		signature.push_back( buf[ i ] );

	/* skip free or reserved pages */
	if ( Page->State == MEM_RESERVE || Page->State == MEM_FREE )
		return;

	char* base = ( char* )Address;

	for ( unsigned int i = 0; i < Page->RegionSize; i++ )
	{
		for ( unsigned j = 0; j < signature.size(); j++ )
		{
			char current_byte = *( base + i );
			char current_sig_byte = signature[j];

			/* if we've found the signature, report */
			if ( j + 1 == signature.size())
			{
				global::report_structures::PATTERN_SCAN_FAILURE report;
				report.report_code = REPORT_PATTERN_SCAN_FAILURE;
				report.address = (UINT64)base + i;
				report.signature_id = 1; /* this will be taken from the vector in future */
				this->report_interface->ReportViolation( &report );

				/* 
				* for now return, however when we stream the signatures we iterate over
				* each signature for every page
				*/
				return;
			}

			/* else, continue searching */
			if ( current_byte != current_sig_byte && current_sig_byte != MASK_BYTE )
				break;

			i++;
		}
	}
}

void usermode::Process::CheckPageProtection( MEMORY_BASIC_INFORMATION* Page )
{
	/* MEM_IMAGE indicates the pages are mapped into view of an image section */
	if ( Page->Type == MEM_IMAGE )
		return;

	if ( Page->AllocationProtect & PAGE_EXECUTE ||
		Page->AllocationProtect & PAGE_EXECUTE_READ ||
		Page->AllocationProtect & PAGE_EXECUTE_READWRITE ||
		Page->AllocationProtect & PAGE_EXECUTE_WRITECOPY
		)
	{
		//Not etirely sure about this check, needs to be looked into further.
		global::report_structures::PAGE_PROTECTION_FAILURE report;
		report.report_code = REPORT_PAGE_PROTECTION_VERIFICATION;
		report.page_base_address = (UINT64)Page->AllocationBase;
		report.allocation_protection = Page->AllocationProtect;
		report.allocation_state = Page->State;
		report.allocation_type = Page->Type;
		this->report_interface->ReportViolation( &report );
	}
}