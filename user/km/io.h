#pragma once

#include <windows.h>

#include <mutex>
#include <vector>
#include <optional>
#include <atomic>

namespace kernelmode {

struct event_dispatcher
{
        bool          in_use;
        OVERLAPPED    overlapped;
        void*         buffer;
        unsigned long buffer_size;

        event_dispatcher(void* buffer, unsigned long buffer_size)
        {
                this->in_use            = false;
                this->overlapped.hEvent = CreateEvent(nullptr, true, false, nullptr);
                this->buffer            = buffer;
                this->buffer_size       = buffer_size;
        }
};

class completion_port
{
        HANDLE                        driver;
        HANDLE                        port;
        std::mutex                    lock;
        std::vector<event_dispatcher> events;

        event_dispatcher* get_free_event_entry();
        void              run_completion_port();

    public:
        completion_port(HANDLE driver);
        ~completion_port();
        event_dispatcher* get_event_object();
        void              release_event_object(OVERLAPPED* event);
        void*             get_buffer_from_event_object(OVERLAPPED* event);
};
}