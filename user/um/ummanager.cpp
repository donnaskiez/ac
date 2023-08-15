#include "ummanager.h"

#include "../common.h"
#include "process.h"

#include <TlHelp32.h>

UserMode::Manager::Manager( std::string ProcessName )
{
	this->process_name = ProcessName;
	this->process_handle = GetHandleToProcessGivenName( ProcessName );
}
