#include "helper.h"

#include <chrono>
#include <random>

void helper::generate_rand_seed() { srand(time(0)); }

int helper::generate_rand_int(int max) { return std::rand() % max; }

void helper::sleep_thread(int seconds) {
  std::this_thread::sleep_for(std::chrono::seconds(seconds));
}

int helper::get_report_id_from_buffer(void *buffer) {
  kernel_interface::report_header *header =
      reinterpret_cast<kernel_interface::report_header *>(buffer);
  return header->report_id;
}

kernel_interface::report_id helper::get_kernel_report_type(void *buffer) {
  switch (helper::get_report_id_from_buffer(buffer)) {
  case kernel_interface::report_id::report_nmi_callback_failure:
    return kernel_interface::report_id::report_nmi_callback_failure;

  case kernel_interface::report_id::report_module_validation_failure:
    return kernel_interface::report_id::report_module_validation_failure;

  case kernel_interface::report_id::report_illegal_handle_operation:
    return kernel_interface::report_id::report_illegal_handle_operation;

  case kernel_interface::report_id::report_invalid_process_allocation:
    return kernel_interface::report_id::report_invalid_process_allocation;

  case kernel_interface::report_id::report_hidden_system_thread:
    return kernel_interface::report_id::report_hidden_system_thread;

  case kernel_interface::report_id::report_illegal_attach_process:
    return kernel_interface::report_id::report_illegal_attach_process;

  case kernel_interface::report_id::report_apc_stackwalk:
    return kernel_interface::report_id::report_apc_stackwalk;

  case kernel_interface::report_id::report_dpc_stackwalk:
    return kernel_interface::report_id::report_dpc_stackwalk;

  case kernel_interface::report_id::report_data_table_routine:
    return kernel_interface::report_id::report_data_table_routine;
  }
}

void helper::print_kernel_report(void *buffer) {
  switch (get_kernel_report_type(buffer)) {
  case kernel_interface::report_id::report_nmi_callback_failure: {
    kernel_interface::nmi_callback_failure *r1 =
        reinterpret_cast<kernel_interface::nmi_callback_failure *>(buffer);
    LOG_INFO("report type: nmi_callback_failure");
    LOG_INFO("report code: %lx", r1->report_code);
    LOG_INFO("were_nmis_disabled: %lx", r1->were_nmis_disabled);
    LOG_INFO("kthread_address: %llx", r1->kthread_address);
    LOG_INFO("invalid_rip: %llx", r1->invalid_rip);
    LOG_INFO("********************************");
    break;
  }
  case kernel_interface::report_id::report_invalid_process_allocation: {
    kernel_interface::invalid_process_allocation_report *r2 =
        reinterpret_cast<kernel_interface::invalid_process_allocation_report *>(
            buffer);
    LOG_INFO("report type: invalid_process_allocation_report");
    LOG_INFO("report code: %d", r2->report_code);
    LOG_INFO("********************************");
    break;
  }
  case kernel_interface::report_id::report_hidden_system_thread: {
    kernel_interface::hidden_system_thread_report *r3 =
        reinterpret_cast<kernel_interface::hidden_system_thread_report *>(
            buffer);
    LOG_INFO("report type: hidden_system_thread_report");
    LOG_INFO("report code: %lx", r3->report_code);
    LOG_INFO("found_in_kthreadlist: %lx", r3->found_in_kthreadlist);
    LOG_INFO("found_in_pspcidtable: %lx", r3->found_in_pspcidtable);
    LOG_INFO("thread_address: %llx", r3->thread_address);
    LOG_INFO("thread_id: %lx", r3->thread_id);
    LOG_INFO("********************************");
    break;
  }
  case kernel_interface::report_id::report_illegal_attach_process: {
    kernel_interface::attach_process_report *r4 =
        reinterpret_cast<kernel_interface::attach_process_report *>(buffer);
    LOG_INFO("report type: attach_process_report");
    LOG_INFO("report code: %lx", r4->report_code);
    LOG_INFO("thread_id: %lx", r4->thread_id);
    LOG_INFO("thread_address: %llx", r4->thread_address);
    LOG_INFO("********************************");
    break;
  }
  case kernel_interface::report_id::report_illegal_handle_operation: {
    kernel_interface::open_handle_failure_report *r5 =
        reinterpret_cast<kernel_interface::open_handle_failure_report *>(
            buffer);
    LOG_INFO("report type: open_handle_failure_report");
    LOG_INFO("report code: %lx", r5->report_code);
    LOG_INFO("is_kernel_handle: %lx", r5->is_kernel_handle);
    LOG_INFO("process_id: %lx", r5->process_id);
    LOG_INFO("thread_id: %lx", r5->thread_id);
    LOG_INFO("access: %lx", r5->access);
    LOG_INFO("process_name: %s", r5->process_name);
    LOG_INFO("********************************");
    break;
  }
  case kernel_interface::report_id::report_invalid_process_module: {
    kernel_interface::process_module_validation_report *r6 =
        reinterpret_cast<kernel_interface::process_module_validation_report *>(
            buffer);
    LOG_INFO("report type: process_module_validation_report");
    LOG_INFO("report code: %d", r6->report_code);
    LOG_INFO("image_base: %llx", r6->image_base);
    LOG_INFO("image_size: %u", r6->image_size);
    LOG_INFO("module_path: %ls", r6->module_path);
    LOG_INFO("********************************");
    break;
  }
  case kernel_interface::report_id::report_apc_stackwalk: {
    kernel_interface::apc_stackwalk_report *r7 =
        reinterpret_cast<kernel_interface::apc_stackwalk_report *>(buffer);
    LOG_INFO("report type: apc_stackwalk_report");
    LOG_INFO("report code: %d", r7->report_code);
    LOG_INFO("kthread_address: %llx", r7->kthread_address);
    LOG_INFO("invalid_rip: %llx", r7->invalid_rip);
    LOG_INFO("********************************");
    break;
  }
  case kernel_interface::report_id::report_dpc_stackwalk: {
    kernel_interface::dpc_stackwalk_report *r8 =
        reinterpret_cast<kernel_interface::dpc_stackwalk_report *>(buffer);
    LOG_INFO("report type: dpc_stackwalk_report");
    LOG_INFO("report code: %d", r8->report_code);
    LOG_INFO("kthread_address: %llx", r8->kthread_address);
    LOG_INFO("invalid_rip: %llx", r8->invalid_rip);
    LOG_INFO("********************************");
    break;
  }
  case kernel_interface::report_id::report_data_table_routine: {
    kernel_interface::data_table_routine_report *r9 =
        reinterpret_cast<kernel_interface::data_table_routine_report *>(buffer);
    LOG_INFO("report type: data_table_routine_report");
    LOG_INFO("report code: %d", r9->report_code);
    LOG_INFO("id: %d", r9->id);
    LOG_INFO("address: %llx", r9->address);
    LOG_INFO("routine: %s", r9->routine);
    LOG_INFO("********************************");
    break;
  }
  case kernel_interface::report_id::report_module_validation_failure: {
    kernel_interface::module_validation_failure *r10 =
        reinterpret_cast<kernel_interface::module_validation_failure *>(buffer);
    LOG_INFO("report type: module_validation_failure");
    LOG_INFO("report code: %lx", r10->report_code);
    LOG_INFO("report type: %lx", r10->report_type);
    LOG_INFO("driver_base_address: %llx", r10->driver_base_address);
    LOG_INFO("driver_size: %llx", r10->driver_size);
    LOG_INFO("driver_name: %s", r10->driver_name);
    LOG_INFO("********************************");
    break;
  }
  default:
    LOG_INFO("Invalid report type.");
    break;
  }
}

unsigned __int64 helper::seconds_to_nanoseconds(int seconds) {
  return ABSOLUTE(SECONDS(seconds));
}

unsigned __int32 helper::seconds_to_milliseconds(int seconds) {
  return seconds * 1000;
}