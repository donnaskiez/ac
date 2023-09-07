#ifndef PIPE_H
#define PIPE_H

#include <Windows.h>

#define REPORT_PACKET_ID 1
#define SERVER_REQUEST_PACKET_ID 2
#define SERVER_SEND_PACKET_ID 3

namespace global
{
	class Pipe
	{
		HANDLE pipe_handle;
		LPTSTR pipe_name;

	public:
		Pipe(LPTSTR PipeName);

		void WriteToPipe( PVOID Buffer, SIZE_T Size );
		void ReadPipe( PVOID Buffer, SIZE_T Size );
	};

	namespace headers
	{
		struct PIPE_PACKET_HEADER
		{
			INT message_type;
			UINT64 steam64_id;
		};

		struct PIPE_PACKET_REQUEST_EXTENSION_HEADER
		{
			INT request_id;
		};

		struct PIPE_PACKET_SEND_EXTENSION_HEADER
		{
			INT request_id;
			INT current_packet_number;
			INT total_incoming_packet_count;
			LONG packet_size;
			LONG total_incoming_packet_size;
		};

	}
}

#endif