#ifndef REPORT_H
#define REPORT_H

#include <Windows.h>

#include "threadpool.h"
#include "client.h"
#include <TlHelp32.h>

#define REPORT_BUFFER_SIZE 1024
#define MAX_SIGNATURE_SIZE 256

#define REPORT_CODE_MODULE_VERIFICATION 10
#define REPORT_CODE_START_ADDRESS_VERIFICATION 20
#define REPORT_PAGE_PROTECTION_VERIFICATION 30
#define REPORT_PATTERN_SCAN_FAILURE 40

namespace global
{
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

		struct PROCESS_THREAD_START_FAILURE
		{
			INT report_code;
			LONG thread_id;
			UINT64 start_address;
		};

		struct PAGE_PROTECTION_FAILURE
		{
			INT report_code;
			UINT64 page_base_address;
			LONG allocation_protection;
			LONG allocation_state;
			LONG allocation_type;
		};

		struct PATTERN_SCAN_FAILURE
		{
			INT report_code;
			INT signature_id;
			UINT64 address;
		};
	}
}

#endif
