#include "dispatcher.h"

#include "../client/message_queue.h"
#include "../helper.h"

#include <chrono>

dispatcher::dispatcher::dispatcher(LPCWSTR driver_name,
                                   client::message_queue &message_queue)
    : thread_pool(DISPATCHER_THREAD_COUNT),
      k_interface(driver_name, message_queue) {}

um-rewrite-final
void dispatcher::dispatcher::timer_test_callback() {
  LOG_INFO("Timer callback invoked from dispatcher class!!");
}

void dispatcher::dispatcher::init_timer_callbacks() {
  this->timers.insert_callback(
      std::bind(&dispatcher::dispatcher::timer_test_callback, this), 10, 10);
}

void dispatcher::dispatcher::run_timer_thread() {
  thread_pool.queue_job([this]() { this->timers.run_timer_thread(); });
}

void dispatcher::dispatcher::run_io_port_thread() {
  thread_pool.queue_job([this]() { k_interface.run_completion_port(); });
}

void dispatcher::dispatcher::run() {
  helper::generate_rand_seed();
  this->init_timer_callbacks();
  this->run_timer_thread();
  this->run_io_port_thread();
=======
void dispatcher::dispatcher::run() {
  helper::generate_rand_seed();
  thread_pool.queue_job([this]() { k_interface.run_completion_port(); });
master
  while (true) {
    this->issue_kernel_job();
    helper::sleep_thread(DISPATCH_LOOP_SLEEP_TIME);
  }
}

void dispatcher::dispatcher::issue_kernel_job() {
  switch (helper::generate_rand_int(KERNEL_DISPATCH_FUNCTION_COUNT)) {
  case 0:
    thread_pool.queue_job([this]() { k_interface.enumerate_handle_tables(); });
    break;
  case 1:
    thread_pool.queue_job([this]() { k_interface.perform_integrity_check(); });
    break;
  case 2:
    thread_pool.queue_job(
        [this]() { k_interface.scan_for_unlinked_processes(); });
    break;
  case 3:
    thread_pool.queue_job(
        [this]() { k_interface.verify_process_module_executable_regions(); });
    break;
  case 4:
    thread_pool.queue_job(
        [this]() { k_interface.validate_system_driver_objects(); });
    break;
  case 5:
    thread_pool.queue_job([this]() { k_interface.run_nmi_callbacks(); });
    break;
  case 6:
    thread_pool.queue_job(
        [this]() { k_interface.scan_for_attached_threads(); });
    break;
  case 7:
    thread_pool.queue_job([this]() { k_interface.initiate_apc_stackwalk(); });
    break;
  case 8:
    thread_pool.queue_job([this]() { k_interface.scan_for_ept_hooks(); });
    break;
  case 9:
    thread_pool.queue_job([this]() { k_interface.perform_dpc_stackwalk(); });
    break;
  case 10:
    thread_pool.queue_job([this]() { k_interface.validate_system_modules(); });
    break;
  }
}