#ifndef UMMANAGER_H
#define UMMANAGER_H

#include <string>
#include <Windows.h>

namespace UserMode
{
	class Manager
	{
		std::string process_name;
		HANDLE process_handle;

	public:
		Manager( std::string ProcessName );
	};
}

#endif