#ifndef PROCESS_H
#define PROCESS_H

#include <windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <string>

#include "../um/threadpool.h"
#include "../um/imports.h"

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
		std::string process_name;
		std::mutex mutex;
		std::unique_ptr<Imports> function_imports;

		HANDLE GetHandleToProcessGivenName( std::string ProcessName );
		std::vector<UINT64> GetProcessThreadsStartAddresses();
		bool CheckIfAddressLiesWithinValidProcessModule( UINT64 Address, bool* result );

	public:

		std::unique_ptr<ThreadPool> thread_pool;

		Process( int ThreadCount, std::string ProcessName );
		~Process();

		void ValidateProcessThreads();
	};
}

#endif