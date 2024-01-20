#pragma once

#include "threadpool.h"

#include "../kernel_interface/kernel_interface.h"
#include "../user_interface/user_interface.h"

namespace dispatcher {
class dispatcher {
  thread_pool thread_pool;
  kernel_interface::kernel_interface k_interface;
  user_interface::user_interface u_interface;

public:
  dispatcher(LPCWSTR driver_name, client::message_queue &queue);
  void run();
};
} // namespace dispatcher