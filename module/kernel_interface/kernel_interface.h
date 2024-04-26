#pragma once

#include <Windows.h>

#include "../client/message_queue.h"

namespace kernel_interface {

static constexpr int EVENT_COUNT = 5;
static constexpr int MAX_MODULE_PATH = 256;
static constexpr int MAXIMUM_REPORT_BUFFER_SIZE = 1000;
static constexpr int QUERY_DEFERRED_REPORT_COUNT = 10;
static constexpr int AES_128_KEY_SIZE = 16;

enum report_id {
  report_nmi_callback_failure = 50,
  report_module_validation_failure = 60,
  report_illegal_handle_operation = 70,
  report_invalid_process_allocation = 80,
  report_hidden_system_thread = 90,
  report_illegal_attach_process = 100,
  report_apc_stackwalk = 110,
  report_dpc_stackwalk = 120,
  report_data_table_routine = 130,
  report_invalid_process_module = 140
};

struct report_header {
  int report_id;
};

constexpr int APC_STACKWALK_BUFFER_SIZE = 500;
constexpr int DATA_TABLE_ROUTINE_BUF_SIZE = 256;
constexpr int REPORT_INVALID_PROCESS_BUFFER_SIZE = 500;
constexpr int HANDLE_REPORT_PROCESS_NAME_MAX_LENGTH = 64;
constexpr int MODULE_PATH_LEN = 256;

struct apc_stackwalk_report {
  int report_code;
  uint64_t kthread_address;
  uint64_t invalid_rip;
  char driver[APC_STACKWALK_BUFFER_SIZE];
};

struct dpc_stackwalk_report {
  uint32_t report_code;
  uint64_t kthread_address;
  uint64_t invalid_rip;
  char driver[APC_STACKWALK_BUFFER_SIZE];
};

struct module_validation_failure {
  int report_code;
  int report_type;
  uint64_t driver_base_address;
  uint64_t driver_size;
  char driver_name[128];
};

enum table_id { hal_dispatch = 0, hal_private_dispatch };

struct data_table_routine_report {
  uint32_t report_code;
  table_id id;
  uint64_t address;
  uint32_t index;
  char routine[DATA_TABLE_ROUTINE_BUF_SIZE];
};

struct nmi_callback_failure {
  int report_code;
  int were_nmis_disabled;
  uint64_t kthread_address;
  uint64_t invalid_rip;
};

struct invalid_process_allocation_report {
  int report_code;
  char process[REPORT_INVALID_PROCESS_BUFFER_SIZE];
};

struct hidden_system_thread_report {
  int report_code;
  int found_in_kthreadlist;
  int found_in_pspcidtable;
  uint64_t thread_address;
  long thread_id;
  char thread[500];
};

struct attach_process_report {
  int report_code;
  uint32_t thread_id;
  uint64_t thread_address;
};

struct kprcb_thread_validation_ctx {
  uint64_t thread;
  bool thread_found_in_pspcidtable;
  bool finished;
};

struct open_handle_failure_report {
  int report_code;
  int is_kernel_handle;
  long process_id;
  long thread_id;
  long access;
  char process_name[HANDLE_REPORT_PROCESS_NAME_MAX_LENGTH];
};

struct process_module_validation_report {
  int report_code;
  uint64_t image_base;
  uint32_t image_size;
  wchar_t module_path[MODULE_PATH_LEN];
};

enum apc_operation { operation_stackwalk = 0x1 };

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
        InsertIrpIntoIrpQueue =                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20021, METHOD_BUFFERED, FILE_ANY_ACCESS),
        QueryDeferredReports =                  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20022, METHOD_BUFFERED, FILE_ANY_ACCESS),
        InitiateSharedMapping =                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20023, METHOD_BUFFERED, FILE_ANY_ACCESS),
        ValidatePciDevices =                    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20024, METHOD_BUFFERED, FILE_ANY_ACCESS),
        ValidateWin32kDispatchTables =          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20025, METHOD_BUFFERED, FILE_ANY_ACCESS)
};

constexpr int SHARED_STATE_OPERATION_COUNT = 10;

enum shared_state_operation_id
{
        ssRunNmiCallbacks = 0,
        ssValidateDriverObjects,
        ssEnumerateHandleTables,
        ssScanForUnlinkedProcesses,
        ssPerformModuleIntegrityCheck,
        ssScanForAttachedThreads,
        ssScanForEptHooks,
        ssInitiateDpcStackwalk,
        ssValidateSystemModules,
        ssValidateWin32kDispatchTables
};

// clang-format on

struct event_dispatcher {
  bool in_use;
  OVERLAPPED overlapped;
  void *buffer;
  unsigned long buffer_size;

  event_dispatcher(void *buffer, unsigned long buffer_size) {
    this->in_use = false;
    this->overlapped.hEvent = CreateEvent(nullptr, false, false, nullptr);
    this->buffer = buffer;
    this->buffer_size = buffer_size;
  }
};

class kernel_interface {
  struct session_initiation_packet {
    unsigned __int32 session_cookie;
    char session_aes_key[AES_128_KEY_SIZE];
    void *protected_process_id;
  };

  struct hv_detection_packet {
    unsigned long aperf_msr_timing_check;
    unsigned long invd_emulation_check;
  };

  struct process_module {
    void *module_base;
    size_t module_size;
    wchar_t module_path[MAX_MODULE_PATH];
  };

  struct apc_operation_init {
    int operation_id;
  };

  HANDLE driver_handle;
  LPCWSTR driver_name;
  client::message_queue &message_queue;
  HANDLE port;
  std::mutex lock;
  std::vector<event_dispatcher> events;

  struct shared_data {
    unsigned __int32 status;
    unsigned __int16 operation_id;
  };

  struct shared_mapping {
    shared_data *buffer;
    size_t size;
  };

  shared_mapping mapping;

  void initiate_completion_port();
  void terminate_completion_port();
  event_dispatcher *get_free_event_entry();
  void release_event_object(OVERLAPPED *event);
  void *get_buffer_from_event_object(OVERLAPPED *event);

  void notify_driver_on_process_launch();
  void notify_driver_on_process_termination();
  void generic_driver_call(ioctl_code ioctl);
  unsigned int generic_driver_call_output(ioctl_code ioctl, void *output_buffer,
                                          size_t buffer_size,
                                          unsigned long *bytes_returned);
  void generic_driver_call_input(ioctl_code ioctl, void *input_buffer,
                                 size_t buffer_size,
                                 unsigned long *bytes_returned);
  void generic_driver_call_apc(apc_operation operation);

public:
  kernel_interface(LPCWSTR driver_name, client::message_queue &queue);
  ~kernel_interface();

  void run_completion_port();
  void run_nmi_callbacks();
  void validate_pci_devices();
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
  void write_shared_mapping_operation(shared_state_operation_id operation_id);
  void initiate_shared_mapping();
  void validate_win32k_dispatch_tables();
};
} // namespace kernel_interface