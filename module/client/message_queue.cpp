#include "message_queue.h"

#include <Windows.h>

#define TEST_STEAM_64_ID 123456789;

client::message_queue::message_queue(LPTSTR PipeName)
{
#if NO_SERVER
        LOG_INFO("No_Server build used. Not opening named pipe.");
#else
        this->pipe_interface = std::make_unique<client::pipe>(PipeName);
#endif
}

void
client::message_queue::dequeue_message(void* Buffer, size_t Size)
{
#if NO_SERVER
        return;
#else
        this->pipe_interface->read_pipe(Buffer, Size);
#endif
}

void
client::message_queue::enqueue_message(void* Buffer, size_t Size)
{
#if NO_SERVER
        return;
#else
        return;
#endif
}
