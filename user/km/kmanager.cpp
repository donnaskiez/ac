#include "kmanager.h"

kernelmode::KManager::KManager( LPCWSTR DriverName, std::shared_ptr<global::ThreadPool> ThreadPool, std::shared_ptr<global::Report> ReportInterface)
{
	this->driver_interface = std::make_unique<Driver>(DriverName, ReportInterface);
	this->thread_pool = ThreadPool;
}

void kernelmode::KManager::RunNmiCallbacks()
{
	this->thread_pool->QueueJob( [ this ]() { this->driver_interface->RunNmiCallbacks(); } );
}

void kernelmode::KManager::VerifySystemModules()
{
	this->thread_pool->QueueJob( [ this ]() { this->driver_interface->VerifySystemModules(); } );
}

void kernelmode::KManager::MonitorCallbackReports()
{
	this->thread_pool->QueueJob( [ this ]() { this->driver_interface->QueryReportQueue(); } );
}
