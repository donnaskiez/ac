#include "process.h"

#include "../common.h"
#include "../um/imports.h"

#include <iostream>

#define ThreadQuerySetWin32StartAddress 9

usermode::Process::Process( int ThreadCount, std::string ProcessName )
{
	this->process_name = ProcessName;
	this->thread_pool = std::make_unique<ThreadPool>( ThreadCount );
	this->process_handle = GetHandleToProcessGivenName( ProcessName );
	this->function_imports = std::make_unique<Imports>();

	if ( this->process_handle == INVALID_HANDLE_VALUE )
	{
		this->thread_pool->Stop();
		throw std::invalid_argument("Failed to initiate process class handle with error");
	}
}

usermode::Process::~Process()
{
	/* Wait for our jobs to be finished, then safely stop our pool */
	while ( true )
	{
		if ( this->thread_pool->Busy() == FALSE ) { this->thread_pool->Stop(); }
	}
}

void usermode::Process::ValidateProcessThreads()
{
	std::vector<UINT64> threads = GetProcessThreadsStartAddresses();
}

std::vector<UINT64> usermode::Process::GetProcessThreadsStartAddresses()
{
	HANDLE thread_snapshot_handle = INVALID_HANDLE_VALUE;
	THREADENTRY32 thread_entry;
	NTSTATUS status;
	HANDLE thread_handle;
	UINT64 start_address;
	std::vector<UINT64> start_addresses;

	pNtQueryInformationThread NtQueryInfo = ( pNtQueryInformationThread )this->function_imports->ImportMap["NtQueryInformationThread"];

	thread_snapshot_handle = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );

	if ( thread_snapshot_handle == INVALID_HANDLE_VALUE )
	{
		LOG_ERROR( "thread snapshot handle invalid with error 0x%x", GetLastError() );
		return {};
	}

	thread_entry.dwSize = sizeof( THREADENTRY32 );

	if ( !Thread32First( thread_snapshot_handle, &thread_entry ))
	{
		LOG_ERROR( "Thread32First failed with status 0x%x", GetLastError() );
		CloseHandle( thread_snapshot_handle );
		return {};
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

		start_addresses.push_back( start_address );

	} while ( Thread32Next( thread_snapshot_handle, &thread_entry ) );

	return start_addresses;
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
			this->process_id = process_entry.th32ProcessID;
			return process_handle;
		}

	} while ( Process32Next( process_snapshot_handle, &process_entry ) );

	CloseHandle( process_snapshot_handle );
	return INVALID_HANDLE_VALUE;
}
