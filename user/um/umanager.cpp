#include "umanager.h"

#include "../common.h"
#include "process.h"
#include "../um/imports.h"

#include <TlHelp32.h>

usermode::UManager::UManager( std::shared_ptr<global::ThreadPool> ThreadPool )
{
	this->thread_pool = ThreadPool;
	this->process = std::make_unique<Process>();
}

usermode::UManager::~UManager()
{
	/* Wait for our jobs to be finished, then safely stop our pool */
	while ( true )
	{
		if ( this->thread_pool->Busy() == FALSE ) 
		{
			this->thread_pool->Stop(); 
			break;
		}
	}
}

void usermode::UManager::ValidateProcessThreads()
{
	this->thread_pool->QueueJob( [ this ]() {this->process->ValidateProcessThreads(); } );
}

void usermode::UManager::ValidateProcessMemory()
{
	this->thread_pool->QueueJob( [ this ]() {this->process->ScanProcessMemory(); } );
}

void usermode::UManager::ValidateProcessModules()
{
	this->thread_pool->QueueJob( [ this ]() {this->process->VerifyLoadedModuleChecksums(); } );
}

