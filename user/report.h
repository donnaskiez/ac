#ifndef REPORT_H
#define REPORT_H

#include <Windows.h>

#include "threadpool.h"
#include "client.h"
#include <TlHelp32.h>

#define REPORT_BUFFER_SIZE 1024

#define REPORT_CODE_MODULE_VERIFICATION 10

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
		std::mutex mutex;
		byte buffer[ REPORT_BUFFER_SIZE ];
	public:
		Report( std::shared_ptr<global::ThreadPool> ThreadPool, LPTSTR PipeName );

		template <typename T>
		void ReportViolation( T* Report )
		{
			mutex.lock();
			memcpy( this->buffer, Report, sizeof( T ) );
			this->client->WriteToPipe( buffer, sizeof(T) );
			RtlZeroMemory( this->buffer, REPORT_BUFFER_SIZE );
			mutex.unlock();
		}
	};

	namespace report_structures
	{
		struct MODULE_VERIFICATION_CHECKSUM_FAILURE
		{
			INT report_code;
			UINT64 module_base_address;
			UINT64 module_size;
			std::string module_name;
		};
	}
}

#endif
