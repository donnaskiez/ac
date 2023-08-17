#include "threadpool.h"

/*
* This is the idle loop each thread will be running until a job is ready 
* for execution
*/
void global::ThreadPool::ThreadLoop()
{
	while ( true )
	{
		std::function<void()> job;
		{
			std::unique_lock<std::mutex> lock( this->queue_mutex );

			/*
			* This is equivalent to :
			* 
			*		while (!this->jobs.empty() || should_terminate)
			*			mutex_condition.wait(lock);
			* 
			* we are essentially waiting for a job to be queued up or the terminate flag to be set.
			* Another piece of useful information is that the predicate is checked under the lock
			* as the precondition for .wait() is that the calling thread owns the lock.
			* 
			* Now, when .wait() is run, the lock is unlocked the the executing thread is blocked and 
			* is added to a list of threads current waiting on the predicate. In our case whether
			* there are new jobs available for the terminate flag is set. Once the condition variables 
			* are true i.e there are new jobs or we are terminating, the lock is reacquired by the thread
			* and the thread is unblocked. 
			*/
			mutex_condition.wait( lock, [ this ] { return !this->jobs.empty() || this->should_terminate; } );

			if ( this->should_terminate )
				return;

			/* get the first job in the queue*/
			job = jobs.front();
			jobs.pop();
		}
		/* run the job */
		job();
	}
}

global::ThreadPool::ThreadPool(int ThreadCount)
{
	this->thread_count = ThreadCount;
	this->should_terminate = false;

	/* Initiate our threads and store them in our threads vector */
	for ( int i = 0; i < this->thread_count; i++ )
	{
		this->threads.emplace_back( std::thread( &ThreadPool::ThreadLoop, this ) );
	}
}

void global::ThreadPool::QueueJob( const std::function<void()>& job )
{
	/* push a job into our job queue safely by holding our queue lock */
	std::unique_lock<std::mutex> lock( this->queue_mutex );
	this->jobs.push( job );
	lock.unlock();
	mutex_condition.notify_one();
}

void global::ThreadPool::Stop()
{
	/* safely set our termination flag to true */
	std::unique_lock<std::mutex> lock( this->queue_mutex );
	should_terminate = true;
	lock.unlock();
	/* unlock all threads waiting on our condition */
	mutex_condition.notify_all();
	/* join the threads and clear our threads vector */
	for ( std::thread& thread : threads ) { thread.join(); }
	threads.clear();
}

bool global::ThreadPool::Busy()
{
	/* allows us to wait for when the job queue is empty allowing us to safely call the destructor */
	std::unique_lock<std::mutex> lock( this->queue_mutex );
	bool pool_busy = !jobs.empty();
	this->queue_mutex.unlock();
	return pool_busy;
}
