#include "client.h"

#include "common.h"

global::Client::Client( LPTSTR PipeName )
{
	this->pipe_name = PipeName;
	this->pipe_handle = CreateFile(
		this->pipe_name,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);

	if ( this->pipe_handle == INVALID_HANDLE_VALUE )
	{
		LOG_ERROR( "CreateFile failed with status 0x%x", GetLastError() );
		return;
	}

	/* test the write function */
	//global::headers::PIPE_PACKET_HEADER header;
	//header.message_type = REQUEST_PATTERNS_TO_BE_SCANNED;
	//this->WriteToPipe( &header, sizeof( global::headers::PIPE_PACKET_HEADER ) );
}

void global::Client::WriteToPipe( PVOID Buffer, SIZE_T Size )
{
	DWORD bytes_written;

	WriteFile(
		this->pipe_handle,
		Buffer,
		Size,
		&bytes_written,
		NULL
	);

	if ( bytes_written == 0 )
	{
		LOG_ERROR( "WriteFile failed with status code 0x%x", GetLastError() );
		return;
	}

	LOG_INFO( "Sent bytes over pipe" );
}

void global::Client::ReadPipe(PVOID Buffer, SIZE_T Size)
{
	BOOL status = FALSE;
	DWORD bytes_read;

	do
	{
		status = ReadFile(
			this->pipe_handle,
			Buffer,
			Size,
			&bytes_read,
			NULL
		);

		if ( !status && GetLastError() != ERROR_MORE_DATA )
			break;

	} while ( !status );

	if ( !status )
	{
		LOG_ERROR( "ReadFile failed with status 0x%x", GetLastError() );
		return;
	}
}
