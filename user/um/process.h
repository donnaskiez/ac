#ifndef PROCESS_H
#define PROCESS_H

#include <windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <string>

#include "../client.h"
#include "../threadpool.h"
#include "../um/imports.h"
#include "../km/kmanager.h"

#define ThreadQuerySetWin32StartAddress 9

namespace usermode 
{
	/*
	* This class represents a process and the usermode functions responsible for
	* the protection of it. This class represents the protected process and allows
	* us to split protection class into methods which can then be easily managed
	* by the usermode manager class.
	*/
	class Process
	{
		HANDLE process_handle;
		DWORD process_id;
		std::mutex mutex;
		std::unique_ptr<Imports> function_imports;
		std::vector<DWORD> in_memory_module_checksums;
		std::shared_ptr<global::Client> client_interface;

		HANDLE GetHandleToProcessGivenName( std::string ProcessName );
		bool CheckIfAddressLiesWithinValidProcessModule( UINT64 Address, bool* Result );
		bool GetProcessBaseAddress( UINT64* Result );
		void CheckPageProtection( MEMORY_BASIC_INFORMATION* Page );
		void PatternScanRegion( UINT64 Address, MEMORY_BASIC_INFORMATION* Page );

	public:

		Process( std::shared_ptr<global::Client> ClientInterface );

		void ValidateProcessThreads();
		void ScanProcessMemory();
	};
}

#endif