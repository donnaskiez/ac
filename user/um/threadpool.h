#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <mutex>
#include <vector>
#include <queue>
#include <functional>

namespace usermode
{
	class ThreadPool
	{
		int thread_count;
		bool should_terminate;
		std::mutex queue_mutex;
		std::condition_variable mutex_condition;
		std::vector<std::thread> threads;
		std::queue<std::function<void()>> jobs;

		void ThreadLoop();

	public:

		ThreadPool( int ThreadCount );
		void QueueJob(const std::function<void()>& job);
		void Stop();
		bool Busy();
	};
}

#endif