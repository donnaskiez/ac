#ifndef DRIVER_H
#define DRIVER_H

#include <Windows.h>

#include "../threadpool.h"
#include "../report.h"

namespace kernelmode
{
	class Driver
	{
		HANDLE driver_handle;
		LPCWSTR driver_name;
		std::shared_ptr<global::Report> report_interface;
	public:

		std::shared_ptr<global::ThreadPool> thread_pool;

		Driver(LPCWSTR DriverName, std::shared_ptr<global::Report> ReportInterface );
	};
}

#endif
