#pragma once

#include <string>
#include <iostream>

#include <Windows.h>

class DriverInterface
{
	HANDLE driver_handle;

	bool validate_process_name()
	{

	}
	
public:
	DriverInterface(std::string& process_name)
	{
		this->driver_handle = CreateFileW(
			L"donna-ac-test",
			GENERIC_WRITE | GENERIC_READ | GENERIC_EXECUTE,
			0,
			0,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
			0
		);

		if (this->driver_handle == INVALID_HANDLE_VALUE)
		{
			std::cerr << "Failed to open handle to driver" << std::endl;
			return;
		}


	}
};