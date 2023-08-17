#ifndef DRIVER_H
#define DRIVER_H

#include <Windows.h>

#include "../threadpool.h"

namespace kernelmode
{
	class Driver
	{
		HANDLE driver_handle;
		LPCWSTR driver_name;
	public:

		std::shared_ptr<global::ThreadPool> thread_pool;

		Driver(LPCWSTR DriverName);
	};
}

#endif
