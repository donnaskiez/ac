#include "client.h"

#include "common.h"

#include <cmath>

global::Client::Client( std::shared_ptr<global::ThreadPool> ThreadPool, LPTSTR PipeName )
{
	this->thread_pool = ThreadPool;
	this->pipe = std::make_shared<global::Pipe>( PipeName );
}

/*
* Request an item from the server
*/
void global::Client::ServerRequest()
{
}

/*
* Send an item to the server
*/
void global::Client::ServerSend(PVOID Buffer, SIZE_T Size, INT RequestId)
{
	mutex.lock();

	global::headers::PIPE_PACKET_HEADER header;
	header.message_type = SERVER_SEND_PACKET_ID;
	memcpy( this->send_buffer, &header, sizeof( global::headers::PIPE_PACKET_HEADER ) );

	LONG total_size_of_headers = sizeof( global::headers::PIPE_PACKET_HEADER ) + sizeof( global::headers::PIPE_PACKET_SEND_EXTENSION_HEADER );

	if ( Size > ( SEND_BUFFER_SIZE - total_size_of_headers ) )
	{
		INT total_packets = std::ceil( Size / ( SEND_BUFFER_SIZE - total_size_of_headers ) );
		LONG remaining_bytes = Size;

		for ( INT count = 0; count < total_packets; count++ )
		{
			global::headers::PIPE_PACKET_SEND_EXTENSION_HEADER header_extension;
			header_extension.request_id = RequestId;
			header_extension.total_incoming_packet_count = total_packets;
			header_extension.total_incoming_packet_size = Size;
			header_extension.current_packet_number = count;
			header_extension.packet_size = ( count + 1 ) == total_packets ? remaining_bytes : SEND_BUFFER_SIZE;

			memcpy( PVOID( ( UINT64 )this->send_buffer + sizeof( global::headers::PIPE_PACKET_HEADER ) ),
				&header_extension, sizeof(global::headers::PIPE_PACKET_SEND_EXTENSION_HEADER));

			memcpy(
				PVOID( ( UINT64 )this->send_buffer + total_size_of_headers ), Buffer,
				( UINT64 )header_extension.packet_size - total_size_of_headers
			);

			this->pipe->WriteToPipe( this->send_buffer, header_extension.packet_size );

			remaining_bytes = remaining_bytes - header_extension.packet_size;
		}
	}
	else
	{
		global::headers::PIPE_PACKET_SEND_EXTENSION_HEADER header_extension;
		header_extension.request_id = RequestId;
		header_extension.total_incoming_packet_count = 1;
		header_extension.total_incoming_packet_size = Size;
		header_extension.current_packet_number = 1;
		header_extension.packet_size = Size;

		memcpy( PVOID( ( UINT64 )this->send_buffer + sizeof( global::headers::PIPE_PACKET_HEADER ) ),
			&header_extension, sizeof( global::headers::PIPE_PACKET_SEND_EXTENSION_HEADER ) );

		this->pipe->WriteToPipe( this->send_buffer, header_extension.packet_size );
	}

	RtlZeroMemory( this->send_buffer, SEND_BUFFER_SIZE );
	mutex.unlock();
}
