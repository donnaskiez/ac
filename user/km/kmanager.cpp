#include "kmanager.h"

kernelmode::KManager::KManager( LPCWSTR DriverName, std::shared_ptr<global::ThreadPool> ThreadPool, std::shared_ptr<global::Client> ReportInterface)
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

void kernelmode::KManager::DetectSystemVirtualization()
{
	this->thread_pool->QueueJob( [ this ]() { this->driver_interface->DetectSystemVirtualization(); } );
}

void kernelmode::KManager::EnumerateHandleTables()
{
	this->thread_pool->QueueJob( [ this ]() { this->driver_interface->CheckHandleTableEntries(); } );
}

void kernelmode::KManager::RequestModuleExecutableRegionsForIntegrityCheck()
{
	this->thread_pool->QueueJob( [ this ]() { this->driver_interface->RequestModuleExecutableRegions(); } );
}

VOID kernelmode::KManager::ScanPoolsForUnlinkedProcesses()
{
	this->thread_pool->QueueJob( [ this ]() { this->driver_interface->ScanForUnlinkedProcess(); } );
}

VOID kernelmode::KManager::PerformIntegrityCheck()
{
	this->thread_pool->QueueJob( [ this ]() { this->driver_interface->PerformIntegrityCheck(); } );
}
