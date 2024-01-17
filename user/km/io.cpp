#include "io.h"

#include "../common.h"

std::pair<bool, OVERLAPPED>*
kernelmode::completion_port::get_free_event_entry()
{
        LOG_INFO("Retrieving first free event object");
        std::lock_guard<std::mutex> lock(this->lock);
        for (std::vector<std::pair<bool, OVERLAPPED>>::iterator it = events.begin();
             it != events.end();
             it++)
        {
                if (it->first == false)
                {
                        it->first = true;
                        return &(*it);
                }
        }
        return nullptr;
}

void
kernelmode::completion_port::run_completion_port()
{
        DWORD       bytes = 0;
        OVERLAPPED* io    = nullptr;
        ULONG_PTR   key   = 0;
        LOG_INFO("Beginning IO Completeion port");
        while (true)
        {
                BOOL result = GetQueuedCompletionStatus(this->port, &bytes, &key, &io, INFINITE);

                if (io == nullptr)
                        continue;

                LOG_INFO("notification received at io port!");
                release_event_object(io);
        }
}

kernelmode::completion_port::completion_port(HANDLE driver)
{
        this->driver = driver;
        for (int index = 0; index < MAXIMUM_WAIT_OBJECTS; index++)
        {
                OVERLAPPED io = {0};
                io.hEvent     = CreateEvent(nullptr, true, false, nullptr);
                bool flag     = false;
                this->events.push_back(std::make_pair(flag, io));
        }
        LOG_INFO("Creating IO completion port");
        this->port = CreateIoCompletionPort(this->driver, nullptr, 0, 0);

        if (!this->port)
        {
                LOG_ERROR("CreateIoCompletePort failed with status %x", GetLastError());
                return;
        }

        std::thread thread([this] { run_completion_port(); });
        thread.detach();
}

OVERLAPPED*
kernelmode::completion_port::get_event_object()
{
        std::pair<bool, OVERLAPPED>* event = get_free_event_entry();
        return reinterpret_cast<OVERLAPPED*>(&event->second);
}

void
kernelmode::completion_port::release_event_object(OVERLAPPED* event)
{
        LOG_INFO("Releasing event object");
        std::lock_guard<std::mutex> lock(this->lock);
        for (std::vector<std::pair<bool, OVERLAPPED>>::iterator it = events.begin();
             it != events.end();
             it++)
        {
                if (&it->second == event)
                {
                        it->first = false;
                        ResetEvent(it->second.hEvent);
                        return;
                }
        }
}