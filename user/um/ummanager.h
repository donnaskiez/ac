#ifndef UMMANAGER_H
#define UMMANAGER_H

#include <string>
#include <winternl.h>
#include <Windows.h>
#include <mutex>
#include <thread>
#include <vector>

#include "process.h"

namespace usermode
{
	class Manager
	{
		std::string process_name;
		std::unique_ptr<Process> process;

	public:
		Manager( std::string ProcessName );
		~Manager();

		void ValidateProcessThreads();
	};
}

#endif