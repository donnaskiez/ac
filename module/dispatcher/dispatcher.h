#pragma once

#include "threadpool.h"

#include "timer.h"
#include "../kernel_interface/kernel_interface.h"

namespace dispatcher {

constexpr int DISPATCH_LOOP_SLEEP_TIME = 30;
constexpr int KERNEL_DISPATCH_FUNCTION_COUNT = 12;
constexpr int DISPATCHER_THREAD_COUNT = 4;
constexpr int TIMER_CALLBACK_DELAY = 15;
constexpr int WRITE_SHARED_MAPPING_PERIOD = 30;
constexpr int WRITE_SHARED_MAPPING_DUE_TIME = 30;

class dispatcher {
  timer timers;
  thread_pool thread_pool;
  kernel_interface::kernel_interface k_interface;

  void issue_kernel_job();
  void write_shared_mapping_operation();
  void init_timer_callbacks();
  void run_timer_thread();
  void run_io_port_thread();
  void request_session_pk();

public:
  dispatcher(LPCWSTR driver_name, client::message_queue &queue);
  void run();
};
} // namespace dispatcher