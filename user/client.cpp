#include "client.h"

#include "common.h"

#include <cmath>

#define TEST_STEAM_64_ID 123456789;

global::Client::Client(std::shared_ptr<global::ThreadPool> ThreadPool, LPTSTR PipeName)
{
        this->thread_pool = ThreadPool;
#if NO_SERVER
        LOG_INFO("No_Server build used. Not opening named pipe.");
#else 
        this->pipe        = std::make_shared<global::Pipe>(PipeName);
#endif
}

/*
 * Request an item from the server
 */
void
global::Client::ServerReceive(PVOID Buffer, SIZE_T Size)
{
        this->pipe->ReadPipe(Buffer, Size);
}

/*
 * Send an item to the server
 */
void
global::Client::ServerSend(PVOID Buffer, SIZE_T Size, INT RequestId)
{
#if NO_SERVER
        return;
#else
        mutex.lock();

        SIZE_T total_header_size = sizeof(global::headers::CLIENT_SEND_PACKET_HEADER) +
                                   sizeof(global::headers::PIPE_PACKET_HEADER);

        if (Size + total_header_size > MAX_CLIENT_SEND_PACKET_SIZE)
        {
                LOG_ERROR("Packet is too large to send");
                mutex.unlock();
                return;
        }

        PVOID send_buffer = malloc(total_header_size + Size);

        if (send_buffer == nullptr)
        {
                mutex.unlock();
                return;
        }

        RtlZeroMemory(send_buffer, total_header_size + Size);

        global::headers::PIPE_PACKET_HEADER header = {0};
        header.message_type                        = MESSAGE_TYPE_CLIENT_SEND;
        header.steam64_id                          = TEST_STEAM_64_ID;

        memcpy(send_buffer, &header, sizeof(global::headers::PIPE_PACKET_HEADER));

        global::headers::CLIENT_SEND_PACKET_HEADER header_extension = {0};
        header_extension.request_id                                 = RequestId;
        header_extension.packet_size                                = Size + total_header_size;

        memcpy(PVOID((UINT64)send_buffer + sizeof(global::headers::PIPE_PACKET_HEADER)),
               &header_extension,
               sizeof(global::headers::CLIENT_SEND_PACKET_HEADER));

        memcpy(PVOID((UINT64)send_buffer + total_header_size), Buffer, Size);

        LOG_INFO("Writing to pipe");

        this->pipe->WriteToPipe(send_buffer, header_extension.packet_size);

        mutex.unlock();
        free(send_buffer);
#endif

}
