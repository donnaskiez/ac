#include "process.h"

#include "../common.h"

#include <iostream>

HANDLE usermode::process::GetHandleToProcessGivenName( std::string ProcessName )
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

		if ( process_handle == NULL )
		{
			LOG_ERROR( "OpenProcess failed with error 0x%x", GetLastError() );
			continue;
		}

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
