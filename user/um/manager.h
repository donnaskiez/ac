#ifndef MANAGER_H
#define MANAGER_H

#include <string>
#include <winternl.h>
#include <Windows.h>
#include <mutex>
#include <thread>
#include <vector>

#include "process.h"

namespace usermode
{
	/*
	* The manager class is meant to abstract away the interaction between the Process
	* class and the threadpool class to allow a single thread (or multiple) to easily run
	* the core business logic of running tasks in a certain order.
	*/
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