#include "kernel_interface.h"

#include <iostream>

#include "../common.h"
#include "../helper.h"
#include "../crypt/crypt.h"

#include <TlHelp32.h>
#include <winternl.h>

typedef BOOLEAN(NTAPI *RtlDosPathNameToNtPathName_U)(PCWSTR DosPathName,
                                                     PUNICODE_STRING NtPathName,
                                                     PCWSTR *NtFileNamePart,
                                                     PVOID DirectoryInfo);

kernel_interface::event_dispatcher *
kernel_interface::kernel_interface::get_free_event_entry() {
  std::lock_guard<std::mutex> lock(this->lock);
  for (std::vector<event_dispatcher>::iterator it = events.begin();
       it != events.end(); it++) {
    if (it->in_use == false) {
      it->in_use = true;
      return &(*it);
    }
  }
  return nullptr;
}

void kernel_interface::kernel_interface::terminate_completion_port() {
  std::lock_guard<std::mutex> lock(this->lock);
  for (std::vector<event_dispatcher>::iterator it = events.begin();
       it != events.end(); it++) {
    free(it->buffer);
    CloseHandle(it->overlapped.hEvent);
  }
}

void kernel_interface::kernel_interface::run_completion_port() {
  DWORD bytes = 0;
  OVERLAPPED *io = nullptr;
  ULONG_PTR key = 0;
  while (true) {
    GetQueuedCompletionStatus(this->port, &bytes, &key, &io, INFINITE);
    if (io == nullptr)
      continue;
    void *buffer = get_buffer_from_event_object(io);
    helper::print_kernel_report(buffer);
    release_event_object(io);
    send_pending_irp();
  }
}

void kernel_interface::kernel_interface::initiate_completion_port() {
  for (int index = 0; index < EVENT_COUNT; index++) {
    void *buffer = malloc(MAXIMUM_REPORT_BUFFER_SIZE);
    this->events.push_back(
        event_dispatcher(buffer, MAXIMUM_REPORT_BUFFER_SIZE));
  }
  this->port = CreateIoCompletionPort(this->driver_handle, nullptr, 0, 0);
  if (!this->port) {
    LOG_ERROR("CreateIoCompletePort failed with status %x", GetLastError());
    return;
  }
  for (int index = 0; index < EVENT_COUNT; index++) {
    send_pending_irp();
  }
  LOG_INFO("Finished initialising completion port.");
}

void kernel_interface::kernel_interface::release_event_object(
    OVERLAPPED *event) {
  std::lock_guard<std::mutex> lock(this->lock);
  for (std::vector<event_dispatcher>::iterator it = events.begin();
       it != events.end(); it++) {
    if (&it->overlapped == event) {
      /* simply zero our the buffer, no need to free and realloc */
      memset(it->buffer, 0, it->buffer_size);
      it->in_use = false;
      ResetEvent(it->overlapped.hEvent);
    }
  }
}

void *kernel_interface::kernel_interface::get_buffer_from_event_object(
    OVERLAPPED *event) {
  std::lock_guard<std::mutex> lock(this->lock);
  for (std::vector<event_dispatcher>::iterator it = events.begin();
       it != events.end(); it++) {
    if (&it->overlapped == event) {
      return it->buffer;
    }
  }
  return nullptr;
}

kernel_interface::kernel_interface::kernel_interface(
    LPCWSTR driver_name, client::message_queue &queue)
    : message_queue(queue) {
  this->driver_name = driver_name;
  this->port = INVALID_HANDLE_VALUE;
  this->driver_handle = CreateFileW(
      driver_name, GENERIC_WRITE | GENERIC_READ | GENERIC_EXECUTE, 0, 0,
      OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
  if (this->driver_handle == INVALID_HANDLE_VALUE) {
    LOG_ERROR("Failed to open handle to driver with status 0x%x",
              GetLastError());
    return;
  }
  this->notify_driver_on_process_launch();
  this->initiate_completion_port();
}

kernel_interface::kernel_interface::~kernel_interface() {
  this->terminate_completion_port();
  this->notify_driver_on_process_termination();
}

unsigned int kernel_interface::kernel_interface::generic_driver_call_output(
    ioctl_code ioctl, void *output_buffer, size_t buffer_size,
    unsigned long *bytes_returned) {
  return DeviceIoControl(this->driver_handle, ioctl, nullptr, 0, output_buffer,
                         buffer_size, bytes_returned, nullptr);
}

void kernel_interface::kernel_interface::generic_driver_call_input(
    ioctl_code ioctl, void *input_buffer, size_t buffer_size,
    unsigned long *bytes_returned) {
  if (!DeviceIoControl(this->driver_handle, ioctl, input_buffer, buffer_size,
                       nullptr, 0, bytes_returned, nullptr))
    LOG_ERROR("DeviceIoControl failed with status %x", GetLastError());
}

void kernel_interface::kernel_interface::generic_driver_call_apc(
    apc_operation operation) {
  apc_operation_init init = {0};
  init.operation_id = operation;
  this->generic_driver_call_input(ioctl_code::InitiateApcStackwalkOperation,
                                  &init, sizeof(init), nullptr);
}

void kernel_interface::kernel_interface::notify_driver_on_process_launch() {
  unsigned long bytes_returned = 0;
  session_initiation_packet packet = {0};
  packet.process_id = reinterpret_cast<void *>(GetCurrentProcessId());
  packet.session_cookie = 123;
  memcpy(packet.aes_key, crypt::get_test_key(), 32);
  memcpy(packet.aes_iv, crypt::get_test_iv(), 16);
  generic_driver_call_input(ioctl_code::NotifyDriverOnProcessLaunch, &packet,
                            sizeof(session_initiation_packet), &bytes_returned);
}

void kernel_interface::kernel_interface::detect_system_virtualization() {
  unsigned int status = 0;
  unsigned long bytes_returned = 0;
  hv_detection_packet packet = {0};
  status = generic_driver_call_output(ioctl_code::PerformVirtualisationCheck,
                                      &packet, sizeof(packet), &bytes_returned);
  if (!status) {
    LOG_ERROR("Failed virtualization detection with status %x", GetLastError());
    return;
  }
  if (packet.aperf_msr_timing_check == true ||
      packet.invd_emulation_check == true)
    LOG_INFO("HYPERVISOR DETECTED!!!");
}

void kernel_interface::kernel_interface::generic_driver_call(ioctl_code ioctl) {
  if (!DeviceIoControl(this->driver_handle, ioctl, nullptr, 0, nullptr, 0,
                       nullptr, nullptr))
    LOG_ERROR("DeviceIoControl failed with status %x", GetLastError());
}

void kernel_interface::kernel_interface::run_nmi_callbacks() {
  this->generic_driver_call(ioctl_code::RunNmiCallbacks);
}

void kernel_interface::kernel_interface::validate_pci_devices() {
  this->generic_driver_call(ioctl_code::ValidatePciDevices);
}

void kernel_interface::kernel_interface::validate_system_driver_objects() {
  this->generic_driver_call(ioctl_code::ValidateDriverObjects);
}

void kernel_interface::kernel_interface::enumerate_handle_tables() {
  this->generic_driver_call(ioctl_code::EnumerateHandleTables);
}

void kernel_interface::kernel_interface::scan_for_unlinked_processes() {
  this->generic_driver_call(ioctl_code::ScanForUnlinkedProcesses);
}

void kernel_interface::kernel_interface::perform_integrity_check() {
  this->generic_driver_call(ioctl_code::PerformModuleIntegrityCheck);
}

void kernel_interface::kernel_interface::
    notify_driver_on_process_termination() {
  this->generic_driver_call(ioctl_code::NotifyDriverOnProcessTermination);
}

void kernel_interface::kernel_interface::scan_for_attached_threads() {
  this->generic_driver_call(ioctl_code::ScanFroAttachedThreads);
}

void kernel_interface::kernel_interface::scan_for_ept_hooks() {
  this->generic_driver_call(ioctl_code::ScanForEptHooks);
}

void kernel_interface::kernel_interface::perform_dpc_stackwalk() {
  this->generic_driver_call(ioctl_code::InitiateDpcStackwalk);
}

void kernel_interface::kernel_interface::validate_system_modules() {
  this->generic_driver_call(ioctl_code::ValidateSystemModules);
}

void kernel_interface::kernel_interface::validate_win32k_dispatch_tables() {
  this->generic_driver_call(ioctl_code::ValidateWin32kDispatchTables);
}

void kernel_interface::kernel_interface::
    verify_process_module_executable_regions() {
  //  HANDLE handle = INVALID_HANDLE_VALUE;
  //  MODULEENTRY32 module_entry = {0};
  //  BOOLEAN status = FALSE;
  //  process_module module = {0};
  //  unsigned long bytes_returned = 0;
  //  RtlDosPathNameToNtPathName_U pRtlDosPathNameToNtPathName_U = NULL;
  //  UNICODE_STRING nt_path_name = {0};
  //  pRtlDosPathNameToNtPathName_U =
  //  (RtlDosPathNameToNtPathName_U)GetProcAddress(
  //      GetModuleHandle("ntdll.dll"), "RtlDosPathNameToNtPathName_U");
  //  handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
  //                                    GetCurrentProcessId());
  //  if (handle == INVALID_HANDLE_VALUE) {
  //    LOG_ERROR("CreateToolHelp32Snapshot with TH32CS_SNAPMODULE failed with "
  //              "status 0x%x",
  //              GetLastError());
  //    return;
  //  }
  //  module_entry.dwSize = sizeof(MODULEENTRY32);
  //  if (!Module32First(handle, &module_entry)) {
  //    LOG_ERROR("Module32First failed with status 0x%x", GetLastError());
  //    return;
  //  }
  //  do {
  //    module.module_base = module_entry.modBaseAddr;
  //    module.module_size = module_entry.modBaseSize;
  //    status = (*pRtlDosPathNameToNtPathName_U)(module_entry.szExePath,
  //                                              &nt_path_name, NULL, NULL);
  //    if (!status) {
  //      LOG_ERROR("RtlDosPathNameToNtPathName_U failed with no status.");
  //      continue;
  //    }
  //    memcpy(module.module_path, nt_path_name.Buffer, MAX_MODULE_PATH);
  //    this->generic_driver_call_input(ioctl_code::ValidateProcessLoadedModule,
  //                                    &module, sizeof(module),
  //                                    &bytes_returned);
  //  } while (Module32Next(handle, &module_entry));
  // end:
  //  CloseHandle(handle);
}

void kernel_interface::kernel_interface::initiate_apc_stackwalk() {
  this->generic_driver_call_apc(apc_operation::operation_stackwalk);
}

void kernel_interface::kernel_interface::send_pending_irp() {
  DWORD status = 0;
  event_dispatcher *event = get_free_event_entry();
  if (!event) {
    LOG_ERROR("All event objects in use.");
    return;
  }
  status = DeviceIoControl(
      this->driver_handle, ioctl_code::InsertIrpIntoIrpQueue, NULL, NULL,
      event->buffer, event->buffer_size, NULL, &event->overlapped);
  /*
   * im not sure why this returns a status of ERROR_INVALID_FUNCTION when we use
   * the inserted irp to complete a deferred irp - even though that procedure
   * should return STATUS_SUCCESS? Weird.. Anyhow it works.
   */
  if (status == ERROR_IO_PENDING || status == ERROR_SUCCESS ||
      status == ERROR_INVALID_FUNCTION)
    return;
  LOG_ERROR("failed to insert irp into irp queue %x", status);
}

// void kernel_interface::kernel_interface::query_deferred_reports() {
//   unsigned long bytes_returned = 0;
//   void *buffer = malloc(MAXIMUM_REPORT_BUFFER_SIZE);
//   if (!buffer)
//     return;
//   for (int i = 0; i < QUERY_DEFERRED_REPORT_COUNT; i++) {
//     unsigned int status =
//         generic_driver_call_output(ioctl_code::QueryDeferredReports, buffer,
//                                    MAXIMUM_REPORT_BUFFER_SIZE,
//                                    &bytes_returned);
//     if (status && bytes_returned > 0)
//       helper::print_kernel_report(buffer);
//     memset(buffer, 0, MAXIMUM_REPORT_BUFFER_SIZE);
//   }
//   free(buffer);
// }

void kernel_interface::kernel_interface::write_shared_mapping_operation(
    shared_state_operation_id operation_id) {
  InterlockedExchange16(
      reinterpret_cast<SHORT *>(&this->mapping.buffer->operation_id),
      operation_id);
}

void kernel_interface::kernel_interface::initiate_shared_mapping() {
  LOG_INFO("Initialising shared memory buffer!");
  unsigned long bytes_returned = 0;
  unsigned long result = this->generic_driver_call_output(
      ioctl_code::InitiateSharedMapping, &this->mapping,
      sizeof(kernel_interface::shared_mapping), &bytes_returned);
  if (!result) {
    LOG_ERROR("DeviceIoControl failed with status %x", GetLastError());
    return;
  }
}