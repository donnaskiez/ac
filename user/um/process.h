#ifndef PROCESS_H
#define PROCESS_H

#include <Windows.h>
#include <TlHelp32.h>
#include <string>

namespace usermode 
{
	namespace process
	{
		HANDLE GetHandleToProcessGivenName( std::string ProcessName );
	}
}

#endif