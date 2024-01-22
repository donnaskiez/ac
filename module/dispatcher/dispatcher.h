#pragma once

#include "threadpool.h"

um-rewrite-final
#include "timer.h"
=======
master
#include "../kernel_interface/kernel_interface.h"

namespace dispatcher {

static const int DISPATCH_LOOP_SLEEP_TIME = 10;
static const int KERNEL_DISPATCH_FUNCTION_COUNT = 11;
static const int DISPATCHER_THREAD_COUNT = 4;

class dispatcher {
um-rewrite-final
  timer timers;
=======
master
  thread_pool thread_pool;
  kernel_interface::kernel_interface k_interface;

  void issue_kernel_job();
um-rewrite-final
  void timer_test_callback();
  void init_timer_callbacks();
  void run_timer_thread();
  void run_io_port_thread();
=======
master

public:
  dispatcher(LPCWSTR driver_name, client::message_queue &queue);
  void run();
};
} // namespace dispatcher