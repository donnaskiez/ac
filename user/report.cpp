#include "report.h"

#include "common.h"

global::Report::Report( std::shared_ptr<global::ThreadPool> ThreadPool, LPTSTR PipeName )
{
	this->thread_pool = ThreadPool;
	this->client = std::make_shared<global::Client>( PipeName );
}
