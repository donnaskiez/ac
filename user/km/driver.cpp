#include "driver.h"

kernelmode::Driver::Driver(LPCWSTR DriverName, std::shared_ptr<global::Report> ReportInterface )
{
	this->driver_name = DriverName;
	this->report_interface = ReportInterface;
}
