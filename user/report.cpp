#include "report.h"

global::Report::Report( std::shared_ptr<global::ThreadPool> ThreadPool, LPTSTR PipeName )
{
	this->thread_pool = ThreadPool;
	this->client = std::make_unique<global::Client>( PipeName );
}

void global::Report::ReportViolation( TestReport* Report )
{
	this->thread_pool->QueueJob( [ this, Report ]() {this->client->WriteToPipe( Report ); } );
}
