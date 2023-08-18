#ifndef CLIENT_H
#define CLIENT_H

#include <Windows.h>

#include "report.h"

namespace global
{
	class Client
	{
		HANDLE pipe_handle;
		LPTSTR pipe_name;

	public:
		Client(LPTSTR PipeName);
		void WriteToPipe( TestReport* Report );
	};
}

#endif