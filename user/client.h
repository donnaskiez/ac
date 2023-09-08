#ifndef REPORT_H
#define REPORT_H

#include <Windows.h>

#include "threadpool.h"
#include "pipe.h"
#include <TlHelp32.h>
#include "common.h"

#define REPORT_BUFFER_SIZE 8192
#define SEND_BUFFER_SIZE 8192

#define MAX_SIGNATURE_SIZE 256

#define MODULE_VALIDATION_FAILURE_MAX_REPORT_COUNT 20

#define REPORT_CODE_MODULE_VERIFICATION 10
#define REPORT_CODE_START_ADDRESS_VERIFICATION 20
#define REPORT_PAGE_PROTECTION_VERIFICATION 30
#define REPORT_PATTERN_SCAN_FAILURE 40
#define REPORT_NMI_CALLBACK_FAILURE 50
#define REPORT_MODULE_VALIDATION_FAILURE 60
#define REPORT_ILLEGAL_HANDLE_OPERATION 70
#define REPORT_INVALID_PROCESS_ALLOCATION 80
#define REPORT_HIDDEN_SYSTEM_THREAD 90
#define REPORT_ILLEGAL_ATTACH_PROCESS 100

#define TEST_STEAM_64_ID 123456789;

enum REPORT_CODES
{
	USERMODE_MODULE = 10,
	START_ADDRESS = 20,
	PAGE_PROTECTION = 30,
	PATTERN_SCAN = 40,
	NMI_CALLBACK = 50,
	SYSTEM_MODULE = 60,
	HANDLE_OPERATION = 70
};

#define SERVER_SEND_MODULE_INTEGRITY_CHECK 10

enum SERVER_SEND_CODES
{
	MODULE_INTEGRITY_CHECK = 10
};

namespace global
{
	class Client
	{
		std::shared_ptr<global::ThreadPool> thread_pool;
		std::shared_ptr<global::Pipe> pipe;
		std::mutex mutex;
		global::headers::SYSTEM_INFORMATION* system_information;

		byte report_buffer[ REPORT_BUFFER_SIZE ];
		byte send_buffer[ SEND_BUFFER_SIZE ];

	public:

		Client( std::shared_ptr<global::ThreadPool> ThreadPool, LPTSTR PipeName );
		~Client();

		void UpdateSystemInformation( global::headers::SYSTEM_INFORMATION* SystemInformation );

		/* lock buffer, attach header, copy report, send to service then clear buffer */
		template <typename T>
		void ReportViolation( T* Report )
		{
			mutex.lock();

			global::headers::PIPE_PACKET_HEADER header;
			header.message_type = REPORT_PACKET_ID;
			header.steam64_id = TEST_STEAM_64_ID;
			memcpy( &header.system_information.drive_0_serial, &this->system_information->drive_0_serial, sizeof(this->system_information->drive_0_serial) );
			memcpy( &header.system_information.motherboard_serial, &this->system_information->motherboard_serial, sizeof( this->system_information->motherboard_serial ) );

			memcpy( &this->report_buffer, &header, sizeof( global::headers::PIPE_PACKET_HEADER ) );
			memcpy( PVOID( ( UINT64 )this->report_buffer + sizeof( global::headers::PIPE_PACKET_HEADER ) ), Report, sizeof( T ) );
			this->pipe->WriteToPipe( this->report_buffer, sizeof(T) + sizeof( global::headers::PIPE_PACKET_HEADER ) );
			RtlZeroMemory( this->report_buffer, REPORT_BUFFER_SIZE );

			mutex.unlock();
		}

		void ServerReceive();

		void ServerSend( PVOID Buffer, SIZE_T Size, INT RequestId );
	};

	namespace report_structures
	{
		struct PROCESS_MODULES_INTEGRITY_CHECK_FAILURE
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

		struct OPEN_HANDLE_FAILURE_REPORT_HEADER
		{
			INT count;
		};

		struct OPEN_HANDLE_FAILURE_REPORT
		{
			INT report_code;
			INT is_kernel_handle;
			LONG process_id;
			LONG thread_id;
			LONG desired_access;
			CHAR process_name[ 64 ];
		};

		struct INVALID_PROCESS_ALLOCATION_REPORT
		{
			INT report_code;
			CHAR process[ 4096 ];
		};

		/*
		* No point copying data from the start address here
		* since people can easily change it.
		*/
		struct HIDDEN_SYSTEM_THREAD_REPORT
		{
			INT report_code;
			INT found_in_kthreadlist;
			INT found_in_pspcidtable;
			UINT64 thread_address;
			LONG thread_id;
			CHAR thread[ 4096 ];
		};


		struct ATTACH_PROCESS_REPORT
		{
			INT report_code;
			UINT32 thread_id;
			UINT64 thread_address;
		};
	}
}

#endif
