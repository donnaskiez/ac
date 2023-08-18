#ifndef REPORT_H
#define REPORT_H

#include <Windows.h>

#include "threadpool.h"
#include "client.h"

namespace global
{
	struct TestReport
	{
		UINT64 value1;
		UINT64 value2;
	};

	class Report
	{
		std::shared_ptr<global::ThreadPool> thread_pool;
		std::shared_ptr<global::Client> client;
	public:
		Report( std::shared_ptr<global::ThreadPool> ThreadPool, LPTSTR PipeName );
		void ReportViolation( TestReport* Report );
	};
}

#endif
