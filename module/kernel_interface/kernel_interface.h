#pragma once

#include <Windows.h>

#include "../client/message_queue.h"

#define MAX_MODULE_PATH 256

namespace kernel_interface {
enum apc_operation
{
        operation_stackwalk = 0x1
};

// clang-format off
enum ioctl_code
{
        RunNmiCallbacks =                       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20001, METHOD_BUFFERED, FILE_ANY_ACCESS),
        ValidateDriverObjects =                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20002, METHOD_BUFFERED, FILE_ANY_ACCESS),
        NotifyDriverOnProcessLaunch =           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20004, METHOD_BUFFERED, FILE_ANY_ACCESS),
        QueryForApcCompletion =                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20005, METHOD_BUFFERED, FILE_ANY_ACCESS),
        PerformVirtualisationCheck =            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20006, METHOD_BUFFERED, FILE_ANY_ACCESS),
        EnumerateHandleTables =                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20007, METHOD_BUFFERED, FILE_ANY_ACCESS),
        NotifyDriverOnProcessTermination =      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20010, METHOD_BUFFERED, FILE_ANY_ACCESS),
        ScanForUnlinkedProcesses =              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20011, METHOD_BUFFERED, FILE_ANY_ACCESS),
        PerformModuleIntegrityCheck =           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20013, METHOD_BUFFERED, FILE_ANY_ACCESS),
        ScanFroAttachedThreads =                CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20014, METHOD_BUFFERED, FILE_ANY_ACCESS),
        ValidateProcessLoadedModule =           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20015, METHOD_BUFFERED, FILE_ANY_ACCESS),
        RequestHardwareInformation =            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20016, METHOD_BUFFERED, FILE_ANY_ACCESS),
        InitiateApcStackwalkOperation =         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20017, METHOD_BUFFERED, FILE_ANY_ACCESS),
        ScanForEptHooks =                       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20018, METHOD_BUFFERED, FILE_ANY_ACCESS),
        InitiateDpcStackwalk =                  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20019, METHOD_BUFFERED, FILE_ANY_ACCESS),
        ValidateSystemModules =                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20020, METHOD_BUFFERED, FILE_ANY_ACCESS),
        InsertIrpIntoIrpQueue =                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20021, METHOD_BUFFERED, FILE_ANY_ACCESS)
};
// clang-format on

struct event_dispatcher
{
        bool          in_use;
        OVERLAPPED    overlapped;
        void*         buffer;
        unsigned long buffer_size;

        event_dispatcher(void* buffer, unsigned long buffer_size)
        {
                this->in_use            = false;
                this->overlapped.hEvent = CreateEvent(nullptr, true, false, nullptr);
                this->buffer            = buffer;
                this->buffer_size       = buffer_size;
        }
};

class kernel_interface
{
        struct process_load_packet
        {
                unsigned long protected_process_id;
        };

        struct hv_detection_packet
        {
                unsigned long aperf_msr_timing_check;
                unsigned long invd_emulation_check;
        };

        struct process_module
        {
                void*   module_base;
                size_t  module_size;
                wchar_t module_path[MAX_MODULE_PATH];
        };

        struct apc_operation_init
        {
                int operation_id;
        };

        HANDLE                        driver_handle;
        LPCWSTR                       driver_name;
        client::message_queue&        message_queue;
        HANDLE                        port;
        std::mutex                    lock;
        std::vector<event_dispatcher> events;

        void              run_completion_port();
        void              initiaite_completion_port();
        void              terminate_completion_port();
        event_dispatcher* get_free_event_entry();
        void              release_event_object(OVERLAPPED* event);
        void*             get_buffer_from_event_object(OVERLAPPED* event);

        void         notify_driver_on_process_launch();
        void         notify_driver_on_process_termination();
        void         generic_driver_call(ioctl_code ioctl);
        unsigned int generic_driver_call_output(ioctl_code     ioctl,
                                                void*          output_buffer,
                                                size_t         buffer_size,
                                                unsigned long* bytes_returned);
        void         generic_driver_call_input(ioctl_code     ioctl,
                                               void*          input_buffer,
                                               size_t         buffer_size,
                                               unsigned long* bytes_returned);
        void         generic_driver_call_apc(apc_operation operation);

    public:
        kernel_interface(LPCWSTR driver_name, client::message_queue& queue);
        ~kernel_interface();

        void run_nmi_callbacks();
        void validate_system_driver_objects();
        void detect_system_virtualization();
        void enumerate_handle_tables();
        void scan_for_unlinked_processes();
        void perform_integrity_check();
        void scan_for_attached_threads();
        void scan_for_ept_hooks();
        void perform_dpc_stackwalk();
        void validate_system_modules();
        void verify_process_module_executable_regions();
        void initiate_apc_stackwalk();
        void send_pending_irp();
};
}