#pragma once

#include <mutex>
#include <vector>
#include <queue>
#include <functional>

namespace dispatcher {
/*
 * This ThreadPool class is a simple threadpool implementation that will allow us
 * to delegate jobs to a set number of threads without the constant need to close
 * and open new threads.
 */
class thread_pool
{
        int                               thread_count;
        bool                              should_terminate;
        std::mutex                        queue_mutex;
        std::condition_variable           mutex_condition;
        std::vector<std::thread>          threads;
        std::queue<std::function<void()>> jobs;

        void wait_for_task();

    public:
        thread_pool(int thread_count);
        void queue_job(const std::function<void()>& job);
        void terminate();
        bool busy_wait();
};
}