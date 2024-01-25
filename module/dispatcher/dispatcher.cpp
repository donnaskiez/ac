#include "dispatcher.h"

#include "../client/message_queue.h"
#include "../helper.h"

#include <chrono>

dispatcher::dispatcher::dispatcher(LPCWSTR driver_name,
                                   client::message_queue &message_queue)
    : thread_pool(DISPATCHER_THREAD_COUNT),
      k_interface(driver_name, message_queue) {}

void dispatcher::dispatcher::write_shared_mapping_operation() {
  int operation =
      helper::generate_rand_int(kernel_interface::SHARED_STATE_OPERATION_COUNT);
  LOG_INFO("Shared mapping operation callback received. operation: %lx",
           operation);
  this->k_interface.write_shared_mapping_operation(
      *reinterpret_cast<kernel_interface::shared_state_operation_id *>(
          &operation));
}

void dispatcher::dispatcher::init_timer_callbacks() {
  /* we want to offset when our driver routines are called */
  this->k_interface.initiate_shared_mapping();
  std::optional<HANDLE> result = this->timers.insert_callback(
      std::bind(&dispatcher::dispatcher::write_shared_mapping_operation, this),
      WRITE_SHARED_MAPPING_DUE_TIME, WRITE_SHARED_MAPPING_PERIOD);
  helper::sleep_thread(TIMER_CALLBACK_DELAY);
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
  thread_pool.queue_job([this]() { k_interface.run_completion_port(); });
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