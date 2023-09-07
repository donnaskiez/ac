#include "client.h"

#include "common.h"

#include <cmath>

#define TEST_STEAM_64_ID 123456789;

global::Client::Client( std::shared_ptr<global::ThreadPool> ThreadPool, LPTSTR PipeName )
{
	this->thread_pool = ThreadPool;
	this->pipe = std::make_shared<global::Pipe>( PipeName );
}

void global::Client::UpdateSystemInformation(global::headers::SYSTEM_INFORMATION* SystemInformation)
{
	memcpy( &this->system_information, SystemInformation, sizeof( global::headers::SYSTEM_INFORMATION ) );
}

/*
* Request an item from the server
*/
void global::Client::ServerReceive()
{

}

/*
* Send an item to the server
*/
void global::Client::ServerSend(PVOID Buffer, SIZE_T Size, INT RequestId )
{
	mutex.lock();
	global::headers::PIPE_PACKET_HEADER header;
	header.message_type = SERVER_SEND_PACKET_ID;
	header.steam64_id = TEST_STEAM_64_ID;
	memcpy( &header.system_information, &this->system_information, sizeof( global::headers::SYSTEM_INFORMATION ) );

	memcpy( this->send_buffer, &header, sizeof( global::headers::PIPE_PACKET_HEADER ) );

	LONG total_size_of_headers = sizeof( global::headers::PIPE_PACKET_HEADER ) + sizeof( global::headers::PIPE_PACKET_SEND_EXTENSION_HEADER );

	if ( Size > ( SEND_BUFFER_SIZE - total_size_of_headers ) )
	{
		INT total_packets = std::ceil( Size / ( SEND_BUFFER_SIZE - total_size_of_headers ) );
		LONG remaining_bytes = Size + total_packets * total_size_of_headers;

		for ( INT count = 0; count < total_packets + 1; count++ )
		{
			global::headers::PIPE_PACKET_SEND_EXTENSION_HEADER header_extension;
			header_extension.request_id = RequestId;
			header_extension.total_incoming_packet_count = total_packets + 1;
			header_extension.total_incoming_packet_size = Size + total_packets * total_size_of_headers;
			header_extension.current_packet_number = count;
			header_extension.packet_size = count == total_packets ? remaining_bytes : SEND_BUFFER_SIZE;

			LOG_INFO( "current packet number: %lx, packet size: %lx", header_extension.current_packet_number, header_extension.packet_size );

			memcpy( PVOID( ( UINT64 )this->send_buffer + sizeof( global::headers::PIPE_PACKET_HEADER ) ),
				&header_extension, sizeof(global::headers::PIPE_PACKET_SEND_EXTENSION_HEADER));

			memcpy(
				PVOID( ( UINT64 )this->send_buffer + total_size_of_headers ), Buffer,
				( UINT64 )header_extension.packet_size - total_size_of_headers
			);

			this->pipe->WriteToPipe( this->send_buffer, header_extension.packet_size );

			LOG_INFO( "remainiong bytes: %lx", remaining_bytes );
			remaining_bytes = remaining_bytes - header_extension.packet_size;
		}
	}
	else
	{
		global::headers::PIPE_PACKET_SEND_EXTENSION_HEADER header_extension;
		header_extension.request_id = RequestId;
		header_extension.total_incoming_packet_count = 1;
		header_extension.total_incoming_packet_size = Size + total_size_of_headers;
		header_extension.current_packet_number = 1;
		header_extension.packet_size = Size + total_size_of_headers;

		memcpy( PVOID( ( UINT64 )this->send_buffer + sizeof( global::headers::PIPE_PACKET_HEADER ) ),
			&header_extension, sizeof( global::headers::PIPE_PACKET_SEND_EXTENSION_HEADER ) );

		this->pipe->WriteToPipe( this->send_buffer, header_extension.packet_size );
	}

	RtlZeroMemory( this->send_buffer, SEND_BUFFER_SIZE );
	mutex.unlock();
}
