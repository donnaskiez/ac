#ifndef DRIVER_H
#define DRIVER_H

#include <Windows.h>

#include "../threadpool.h"
#include "../report.h"

#define IOCCTL_RUN_NMI_CALLBACKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VALIDATE_DRIVER_OBJECTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2002, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MONITOR_CALLBACKS_FOR_REPORTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2003, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NOTIFY_DRIVER_ON_PROCESS_LAUNCH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2004, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HANDLE_REPORTS_IN_CALLBACK_QUEUE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2005, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MAX_HANDLE_REPORTS_PER_IRP 10

namespace kernelmode
{
	class Driver
	{
		HANDLE driver_handle;
		LPCWSTR driver_name;
		std::shared_ptr<global::Report> report_interface;

		void QueryReportQueue();
	public:

		Driver(LPCWSTR DriverName, std::shared_ptr<global::Report> ReportInterface );

		void RunNmiCallbacks();
		void VerifySystemModules();
		void RunCallbackReportQueue();
		void NotifyDriverOnProcessLaunch();
		void CompleteQueuedCallbackReports();
		void EnableProcessLoadNotifyCallbacks();
		void DisableProcessLoadNotifyCallbacks();
		void ValidateKPRCBThreads();
		void CheckDriverHeartbeat();
		/* todo: driver integrity check */
	};

	struct DRIVER_INITIATION_INFORMATION
	{
		LONG protected_process_id;
	};
}

#endif
