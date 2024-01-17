#pragma once

#include <windows.h>

#include <mutex>
#include <vector>
#include <optional>
#include <atomic>

namespace kernelmode {
class completion_port
{
        HANDLE                                   driver;
        HANDLE                                   port;
        std::mutex                               lock;
        std::vector<std::pair<bool, OVERLAPPED>> events;

        std::pair<bool, OVERLAPPED>* get_free_event_entry();
        void                         run_completion_port();

    public:
        completion_port(HANDLE driver);
        OVERLAPPED* get_event_object();
        void        release_event_object(OVERLAPPED* event);
};
}