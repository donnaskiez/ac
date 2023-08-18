#include "report.h"

#include "common.h"

global::Report::Report( std::shared_ptr<global::ThreadPool> ThreadPool, LPTSTR PipeName )
{
	this->thread_pool = ThreadPool;
	this->client = std::make_shared<global::Client>( PipeName );

	//test report
	TestReport report;
	report.value1 = 10;
	report.value2 = 1337;
	this->ReportViolation( &report );
}

void global::Report::ReportViolation( TestReport* Report )
{
	byte buffer[ 1024 ];
	int size = sizeof( TestReport );
	memcpy( buffer, Report, size );
	LOG_INFO( "sending report over pipe" );

	this->thread_pool->QueueJob( [ this, buffer, size ]() {this->client->WriteToPipe( (PVOID)buffer, size ); } );
}
