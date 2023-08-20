#ifndef REPORT_H
#define REPORT_H

#include <Windows.h>

#include "threadpool.h"
#include "client.h"
#include <TlHelp32.h>

#define REPORT_BUFFER_SIZE 1024
#define MAX_SIGNATURE_SIZE 256
#define MODULE_VALIDATION_FAILURE_MAX_REPORT_COUNT 5

#define REPORT_CODE_MODULE_VERIFICATION 10
#define REPORT_CODE_START_ADDRESS_VERIFICATION 20
#define REPORT_PAGE_PROTECTION_VERIFICATION 30
#define REPORT_PATTERN_SCAN_FAILURE 40
#define REPORT_NMI_CALLBACK_FAILURE 50
#define REPORT_MODULE_VALIDATION_FAILURE 60



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

		/* lock buffer, copy report, send to service then clear buffer */
		template <typename T>
		void ReportViolation( T* Report )
		{
			mutex.lock();

			global::headers::PIPE_PACKET_HEADER header;
			header.message_type = REPORT_PACKET_ID;
			memcpy( this->buffer, &header, sizeof( global::headers::PIPE_PACKET_HEADER ) );

			memcpy( this->buffer + sizeof( global::headers::PIPE_PACKET_HEADER ), Report, sizeof(T));
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

		struct NMI_CALLBACK_FAILURE
		{
			INT report_code;
			INT were_nmis_disabled;
			UINT64 kthread_address;
			UINT64 invalid_rip;
		};

		struct MODULE_VALIDATION_FAILURE_HEADER
		{
			INT module_count;
		};

		struct MODULE_VALIDATION_FAILURE
		{
			INT report_code;
			INT report_type;
			UINT64 driver_base_address;
			UINT64 driver_size;
			CHAR driver_name[ 128 ];
		};
	}
}

#endif
