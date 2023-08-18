#ifndef UMANAGER_H
#define UMANAGER_H

#include <string>
#include <winternl.h>
#include <Windows.h>
#include <mutex>
#include <thread>
#include <vector>

#include "../report.h"

#include "process.h"

namespace usermode
{
	/*
	* The manager class is meant to abstract away the interaction between the Process
	* class and the threadpool class to allow a single thread (or multiple) to easily run
	* the core business logic of running tasks in a certain order.
	*/
	class UManager
	{
		std::unique_ptr<Process> process;
		std::shared_ptr<global::ThreadPool> thread_pool;

	public:
		UManager( std::shared_ptr<global::ThreadPool> ThreadPool, std::shared_ptr<global::Report> ReportInterface );
		~UManager();

		void ValidateProcessThreads();
		void ValidateProcessMemory();
		void ValidateProcessModules();
	};
}

#endif