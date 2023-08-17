#include "driver.h"

kernelmode::Driver::Driver(LPCWSTR DriverName)
{
	this->driver_name = DriverName;
}
