#ifndef PROCESS_H
#define PROCESS_H

#include <Windows.h>
#include <TlHelp32.h>
#include <string>

namespace UserMode 
{
	namespace Process
	{
		HANDLE GetHandleToProcessGivenName( std::string ProcessName );
	}
}

#endif