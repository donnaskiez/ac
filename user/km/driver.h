#ifndef DRIVER_H
#define DRIVER_H

#include <Windows.h>

#include "../threadpool.h"
#include "../report.h"

#define IOCCTL_RUN_NMI_CALLBACKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VALIDATE_DRIVER_OBJECTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2002, METHOD_BUFFERED, FILE_ANY_ACCESS)

namespace kernelmode
{
	class Driver
	{
		HANDLE driver_handle;
		LPCWSTR driver_name;
		std::shared_ptr<global::Report> report_interface;
	public:

		Driver(LPCWSTR DriverName, std::shared_ptr<global::Report> ReportInterface );

		void RunNmiCallbacks();
		void VerifySystemModules();
		void EnableObRegisterCallbacks();
		void DisableObRegisterCallbacks();
		void EnableProcessLoadNotifyCallbacks();
		void DisableProcessLoadNotifyCallbacks();
		void ValidateKPRCBThreads();
		void CheckForHypervisor();
		void CheckDriverHeartbeat();
		/* todo: driver integrity check */
	};
}

#endif
