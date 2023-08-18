#ifndef REPORT_H
#define REPORT_H

#include <Windows.h>

#include "threadpool.h"
#include "client.h"

struct TestReport
{
	UINT64 value1;
	UINT64 value2;
};

namespace global
{
	class Report
	{
		std::shared_ptr<global::ThreadPool> thread_pool;
		std::unique_ptr<global::Client> client;
	public:
		Report( std::shared_ptr<global::ThreadPool> ThreadPool, LPTSTR PipeName );
		void ReportViolation( TestReport* Report );
	};
}

#endif
