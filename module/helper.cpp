#include "helper.h"

#include <chrono>
#include <random>

#include "crypt/crypt.h"

void
helper::generate_rand_seed()
{
    srand(time(0));
}

int
helper::generate_rand_int(int max)
{
    return std::rand() % max;
}

void
helper::sleep_thread(int seconds)
{
    std::this_thread::sleep_for(std::chrono::seconds(seconds));
}

int
helper::get_report_id_from_buffer(void* buffer)
{
    kernel_interface::report_header* header =
        reinterpret_cast<kernel_interface::report_header*>(
            (uint64_t)buffer + sizeof(kernel_interface::report_header));
    return header->report_code;
}

kernel_interface::report_id
helper::get_kernel_report_type(void* buffer)
{
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

void
print_report_packet(void* buffer)
{
    kernel_interface::report_header* report_header =
        (kernel_interface::report_header*)buffer;

    LOG_INFO("report code: %lx", report_header->report_code);
    LOG_INFO("report sub code: %lx", report_header->report_sub_type);

    switch (report_header->report_code) {
    case kernel_interface::report_id::report_nmi_callback_failure: {
        kernel_interface::nmi_callback_failure* r1 =
            reinterpret_cast<kernel_interface::nmi_callback_failure*>(buffer);
        LOG_INFO("were_nmis_disabled: %lx", r1->were_nmis_disabled);
        LOG_INFO("kthread_address: %llx", r1->kthread_address);
        LOG_INFO("invalid_rip: %llx", r1->invalid_rip);
        LOG_INFO("********************************");
        break;
    }
    case kernel_interface::report_id::report_invalid_process_allocation: {
        kernel_interface::invalid_process_allocation_report* r2 =
            reinterpret_cast<
                kernel_interface::invalid_process_allocation_report*>(buffer);
        LOG_INFO("********************************");
        break;
    }
    case kernel_interface::report_id::report_hidden_system_thread: {
        kernel_interface::hidden_system_thread_report* r3 =
            reinterpret_cast<kernel_interface::hidden_system_thread_report*>(
                buffer);
        LOG_INFO("found_in_kthreadlist: %lx", r3->found_in_kthreadlist);
        LOG_INFO("found_in_pspcidtable: %lx", r3->found_in_pspcidtable);
        LOG_INFO("thread_address: %llx", r3->thread_address);
        LOG_INFO("thread_id: %lx", r3->thread_id);
        LOG_INFO("********************************");
        break;
    }
    case kernel_interface::report_id::report_illegal_attach_process: {
        kernel_interface::attach_process_report* r4 =
            reinterpret_cast<kernel_interface::attach_process_report*>(buffer);
        LOG_INFO("report type: attach_process_report");
        LOG_INFO("report code: %lx", r4->report_code);
        LOG_INFO("thread_id: %lx", r4->thread_id);
        LOG_INFO("thread_address: %llx", r4->thread_address);
        LOG_INFO("********************************");
        break;
    }
    case kernel_interface::report_id::report_illegal_handle_operation: {
        kernel_interface::open_handle_failure_report* r5 =
            reinterpret_cast<kernel_interface::open_handle_failure_report*>(
                buffer);
        LOG_INFO("is_kernel_handle: %lx", r5->is_kernel_handle);
        LOG_INFO("process_id: %lx", r5->process_id);
        LOG_INFO("thread_id: %lx", r5->thread_id);
        LOG_INFO("access: %lx", r5->access);
        LOG_INFO("process_name: %s", r5->process_name);
        LOG_INFO("********************************");
        break;
    }
    case kernel_interface::report_id::report_invalid_process_module: {
        kernel_interface::process_module_validation_report* r6 =
            reinterpret_cast<
                kernel_interface::process_module_validation_report*>(buffer);
        LOG_INFO("image_base: %llx", r6->image_base);
        LOG_INFO("image_size: %u", r6->image_size);
        LOG_INFO("module_path: %ls", r6->module_path);
        LOG_INFO("********************************");
        break;
    }
    case kernel_interface::report_id::report_apc_stackwalk: {
        kernel_interface::apc_stackwalk_report* r7 =
            reinterpret_cast<kernel_interface::apc_stackwalk_report*>(buffer);
        LOG_INFO("kthread_address: %llx", r7->kthread_address);
        LOG_INFO("invalid_rip: %llx", r7->invalid_rip);
        LOG_INFO("********************************");
        break;
    }
    case kernel_interface::report_id::report_dpc_stackwalk: {
        kernel_interface::dpc_stackwalk_report* r8 =
            reinterpret_cast<kernel_interface::dpc_stackwalk_report*>(buffer);
        LOG_INFO("kthread_address: %llx", r8->kthread_address);
        LOG_INFO("invalid_rip: %llx", r8->invalid_rip);
        LOG_INFO("********************************");
        break;
    }
    case kernel_interface::report_id::report_data_table_routine: {
        kernel_interface::data_table_routine_report* r9 =
            reinterpret_cast<kernel_interface::data_table_routine_report*>(
                buffer);
        LOG_INFO("id: %d", r9->id);
        LOG_INFO("address: %llx", r9->address);
        LOG_INFO("routine: %s", r9->routine);
        LOG_INFO("********************************");
        break;
    }
    case kernel_interface::report_id::report_module_validation_failure: {
        kernel_interface::module_validation_failure* r10 =
            reinterpret_cast<kernel_interface::module_validation_failure*>(
                buffer);
        LOG_INFO("driver_base_address: %llx", r10->driver_base_address);
        LOG_INFO("driver_size: %llx", r10->driver_size);
        LOG_INFO("driver_name: %s", r10->driver_name);
        LOG_INFO("********************************");
        break;
    }
    case kernel_interface::report_id::report_patched_system_module: {
        kernel_interface::system_module_integrity_check_report* r11 =
            reinterpret_cast<
                kernel_interface::system_module_integrity_check_report*>(
                buffer);
        LOG_INFO("image_base: %llx", r11->image_base);
        LOG_INFO("image_size: %lx", r11->image_size);
        LOG_INFO("path_name: %s", r11->path_name);
        LOG_INFO("********************************");
        break;
    }
    case kernel_interface::report_id::report_self_driver_patched: {
        kernel_interface::driver_self_integrity_check_report* r12 =
            reinterpret_cast<
                kernel_interface::driver_self_integrity_check_report*>(buffer);
        LOG_INFO("image_base: %llx", r12->image_base);
        LOG_INFO("image_size: %lx", r12->image_size);
        LOG_INFO("path_name: %s", r12->path_name);
        LOG_INFO("********************************");
        break;
    }
    case kernel_interface::report_id::report_blacklisted_pcie_device: {
        kernel_interface::blacklisted_pcie_device_report* r13 =
            reinterpret_cast<kernel_interface::blacklisted_pcie_device_report*>(
                buffer);
        LOG_INFO("device_object: %llx", r13->device_object);
        LOG_INFO("device_id: %x", r13->device_id);
        LOG_INFO("vendor_id: %x", r13->vendor_id);
        LOG_INFO("********************************");
        break;
    }
    case kernel_interface::report_id::report_ept_hook: {
        kernel_interface::ept_hook_failure* r14 =
            reinterpret_cast<kernel_interface::ept_hook_failure*>(buffer);
        LOG_INFO("control_average: %llx", r14->control_average);
        LOG_INFO("read_average: %llx", r14->read_average);
        LOG_INFO("function_name: %s", r14->function_name);
        LOG_INFO("********************************");
        break;
    }
    default: LOG_INFO("Invalid report type."); break;
    }
}

void
print_heartbeat_packet(void* buffer)
{
    kernel_interface::heartbeat_packet* hb =
        reinterpret_cast<kernel_interface::heartbeat_packet*>(buffer);
    LOG_INFO("Heartbeat Count: %lx", hb->heartbeat_count);
    LOG_INFO("Total Reports Completed: %lx", hb->total_reports_completed);
    LOG_INFO("Total IRPs Completed: %lx", hb->total_irps_completed);
    LOG_INFO("Total Heartbeats Completed: %lx", hb->total_heartbeats_completed);
    LOG_INFO("********************************");
}

void
helper::print_kernel_report(void* buffer)
{
    uint32_t size = crypt::get_padded_packet_size(
        sizeof(kernel_interface::open_handle_failure_report));
    crypt::decrypt_packet(buffer, size);

    kernel_interface::packet_header* header =
        reinterpret_cast<kernel_interface::packet_header*>(buffer);

    LOG_INFO("packet type: %lx", header->packet_type);

    switch (header->packet_type) {
    case 0: print_report_packet(buffer); break;
    case 1: print_heartbeat_packet(buffer); break;
    }
}

unsigned __int64
helper::seconds_to_nanoseconds(int seconds)
{
    return ABSOLUTE(SECONDS(seconds));
}

unsigned __int32
helper::seconds_to_milliseconds(int seconds)
{
    return seconds * 1000;
}