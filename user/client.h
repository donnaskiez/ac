#ifndef CLIENT_H
#define CLIENT_H

#include <Windows.h>

#define REPORT_PACKET_ID 1
#define REQUEST_PATTERNS_TO_BE_SCANNED 2

namespace global
{
	class Client
	{
		HANDLE pipe_handle;
		LPTSTR pipe_name;

	public:
		Client(LPTSTR PipeName);

		void WriteToPipe( PVOID Buffer, SIZE_T Size );
		void ReadPipe( PVOID Buffer, SIZE_T Size );
	};

	namespace headers
	{
		struct PIPE_PACKET_HEADER
		{
			int message_type;
		};
	}
}

#endif