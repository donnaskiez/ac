#include "io.h"

#include "../common.h"

kernelmode::event_dispatcher*
kernelmode::completion_port::get_free_event_entry()
{
        LOG_INFO("Retrieving first free event object");

        std::lock_guard<std::mutex> lock(this->lock);
        for (std::vector<kernelmode::event_dispatcher>::iterator it =
                 events.begin();
             it != events.end();
             it++)
        {
                if (it->in_use == false)
                {
                        it->in_use = true;
                        return &(*it);
                }
        }

        return nullptr;
}

kernelmode::completion_port::~completion_port()
{
        std::lock_guard<std::mutex> lock(this->lock);
        for (std::vector<kernelmode::event_dispatcher>::iterator it = events.begin();
             it != events.end();
             it++)
        {
                free(it->buffer);
                CloseHandle(it->overlapped.hEvent);
        }
}

void
kernelmode::completion_port::run_completion_port()
{
        DWORD       bytes = 0;
        OVERLAPPED* io    = nullptr;
        ULONG_PTR   key   = 0;

        while (true)
        {
                BOOL result = GetQueuedCompletionStatus(this->port, &bytes, &key, &io, INFINITE);

                if (io == nullptr)
                        continue;

                void* buffer = get_buffer_from_event_object(io);

                PUINT32 report_id = (PUINT32)buffer;
                LOG_INFO("report id: %lx", *report_id);

                release_event_object(io);
        }
}

kernelmode::completion_port::completion_port(HANDLE driver)
{
        this->driver = driver;

        /* we probably dont need this many even objects */
        for (int index = 0; index < MAXIMUM_WAIT_OBJECTS; index++)
        {
                void* buffer = malloc(1000);
                this->events.push_back(kernelmode::event_dispatcher(buffer, 1000));
        }

        this->port = CreateIoCompletionPort(this->driver, nullptr, 0, 0);

        if (!this->port)
        {
                LOG_ERROR("CreateIoCompletePort failed with status %x", GetLastError());
                return;
        }

        std::thread thread([this] { run_completion_port(); });
        thread.detach();
}

kernelmode::event_dispatcher*
kernelmode::completion_port::get_event_object()
{
        return get_free_event_entry();
}

void
kernelmode::completion_port::release_event_object(OVERLAPPED* event)
{
        std::lock_guard<std::mutex> lock(this->lock);
        for (std::vector<event_dispatcher>::iterator it = events.begin();
             it != events.end();
             it++)
        {
                if (&it->overlapped == event)
                {
                        LOG_INFO("Freeing event: %llx  back to array.", (UINT64)event);
                        memset(it->buffer, 0, it->buffer_size);
                        it->in_use = false;
                        ResetEvent(it->overlapped.hEvent);
                }
        }
}

void*
kernelmode::completion_port::get_buffer_from_event_object(OVERLAPPED* event)
{
        std::lock_guard<std::mutex> lock(this->lock);
        for (std::vector<event_dispatcher>::iterator it = events.begin(); it != events.end(); it++)
        {
                if (&it->overlapped == event)
                {
                        LOG_INFO("Found event buffer: %llx", (UINT64)it->buffer);
                        return it->buffer;
                }
        }
        return nullptr;
}