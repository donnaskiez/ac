#ifndef IMPORTS_H
#define IMPORTS_H

#include <winternl.h>
#include <Windows.h>
#include <map>
#include <string>

typedef NTSTATUS( WINAPI* pNtQueryInformationThread )( HANDLE, LONG, PVOID, ULONG, PULONG );

namespace usermode
{
	class Imports
	{
	public:
		std::map<std::string, void*> ImportMap;

		void* NtQueryInformationThread;
		void* NtQueryVirtualMemory;

		Imports();
	};
}

#endif