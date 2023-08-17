#include "kmanager.h"

kernelmode::KManager::KManager( LPCWSTR DriverName, std::shared_ptr<global::ThreadPool> ThreadPool )
{
	this->driver_interface = std::make_unique<Driver>(DriverName);
	this->thread_pool = ThreadPool;
}
