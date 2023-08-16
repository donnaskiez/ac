#include "manager.h"

#include "../common.h"
#include "process.h"
#include "../um/imports.h"

#include <TlHelp32.h>

usermode::Manager::Manager( std::string ProcessName )
{
	this->process_name = ProcessName;
	this->process = std::make_unique<Process>( 4, ProcessName );
}

usermode::Manager::~Manager()
{

}

void usermode::Manager::ValidateProcessThreads()
{
	this->process->thread_pool->QueueJob( [ this ]() {this->process->ValidateProcessThreads(); } );
}
