#include "driver.h"

#include <iostream>

#include "../common.h"
#include <winternl.h>

typedef BOOLEAN(NTAPI* RtlDosPathNameToNtPathName_U)(PCWSTR          DosPathName,
                                                     PUNICODE_STRING NtPathName,
                                                     PCWSTR*         NtFileNamePart,
                                                     PVOID           DirectoryInfo);

using namespace global::report_structures;

kernelmode::Driver::Driver(LPCWSTR DriverName, std::shared_ptr<global::Client> ReportInterface)
{
        this->driver_name      = DriverName;
        this->report_interface = ReportInterface;
        this->driver_handle    = CreateFileW(DriverName,
                                          GENERIC_WRITE | GENERIC_READ | GENERIC_EXECUTE,
                                          0,
                                          0,
                                          OPEN_EXISTING,
                                          FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
                                          0);

        if (this->driver_handle == INVALID_HANDLE_VALUE)
        {
                LOG_ERROR("Failed to open handle to driver with status 0x%x", GetLastError());
                return;
        }

        this->NotifyDriverOnProcessLaunch();
}

kernelmode::Driver::~Driver()
{
        this->NotifyDriverOnProcessTermination();
}

VOID
kernelmode::Driver::RunNmiCallbacks()
{
        BOOLEAN              status         = FALSE;
        DWORD                bytes_returned = 0;
        NMI_CALLBACK_FAILURE report         = {0};

        status = DeviceIoControl(this->driver_handle,
                                 IOCCTL_RUN_NMI_CALLBACKS,
                                 NULL,
                                 NULL,
                                 &report,
                                 sizeof(NMI_CALLBACK_FAILURE),
                                 &bytes_returned,
                                 (LPOVERLAPPED)NULL);

        if (status == NULL)
        {
                LOG_ERROR("DeviceIoControl failed with status code 0x%x", GetLastError());
                return;
        }

        if (bytes_returned == NULL)
        {
                LOG_INFO("All threads valid, nmis fine.");
                return;
        }

        /* else, report */
        this->report_interface->ReportViolation(&report);
}

/*
 * 1. Checks that every device object has a system module to back it
 * 2. Checks the IOCTL dispatch routines to ensure they lie within the module
 */

VOID
kernelmode::Driver::VerifySystemModuleDriverObjects()
{
        BOOLEAN status         = FALSE;
        DWORD   bytes_returned = 0;
        PVOID   buffer         = NULL;
        SIZE_T  buffer_size    = 0;
        SIZE_T  header_size    = 0;

        /*
         * allocate enough to report 5 invalid driver objects + header. The reason we use a raw
         * pointer here is so we can pass the address to DeviceIoControl. You are not able (atleast
         * as far as im concerned) to pass a shared ptr to DeviceIoControl.
         */
        header_size = sizeof(MODULE_VALIDATION_FAILURE_HEADER);

        buffer_size =
            sizeof(MODULE_VALIDATION_FAILURE) * MODULE_VALIDATION_FAILURE_MAX_REPORT_COUNT +
            header_size;

        buffer = malloc(buffer_size);

        if (!buffer)
                return;

        status = DeviceIoControl(this->driver_handle,
                                 IOCTL_VALIDATE_DRIVER_OBJECTS,
                                 NULL,
                                 NULL,
                                 buffer,
                                 buffer_size,
                                 &bytes_returned,
                                 NULL);

        if (status == NULL)
        {
                LOG_ERROR("DeviceIoControl failed with status code 0x%x", GetLastError());
                free(buffer);
                return;
        }

        if (bytes_returned == NULL)
        {
                LOG_INFO("All modules valid :)");
                free(buffer);
                return;
        }

        /*
         * We are splitting up each packet here and passing them on one by one since
         * if I am being honest it is just easier in c++ and that way the process
         * is streamlined just like all other report packets.
         */
        MODULE_VALIDATION_FAILURE_HEADER* header = (MODULE_VALIDATION_FAILURE_HEADER*)buffer;

        LOG_INFO("Module count: %lx", header->module_count);

        for (int i = 0; i < header->module_count; i++)
        {
                MODULE_VALIDATION_FAILURE* report =
                    (MODULE_VALIDATION_FAILURE*)((UINT64)buffer +
                                                 sizeof(MODULE_VALIDATION_FAILURE_HEADER) +
                                                 i * sizeof(MODULE_VALIDATION_FAILURE));

                this->report_interface->ReportViolation(report);
        }

        free(buffer);
}

/*
 * HOW THIS WILL WORK:
 *
 * 1. On driver initiation, ObRegisterCallbacks will be registered
 * 2. Each time a process that is not whitelisted tries to open a handle
 *	 to our game we will store the report in an a report queue
 * 3. the user mode app will then periodically query the driver asking
 *	 how many pending reports there are
 * 4. once the number is received, the app will allocate a buffer large enough
 *	 for all the reports and once again call CompleteQueuedCallbackReports
 * 5. This will then retrieve the reports into the buffer and from there
 *    we can iteratively report them the same way as we do with the system
 *	 modules.
 */

struct REPORT_ID
{
        INT report_id;
};

VOID
kernelmode::Driver::QueryReportQueue()
{
        BOOLEAN                           status            = FALSE;
        DWORD                             bytes_returned    = 0;
        PVOID                             buffer            = NULL;
        LONG                              buffer_size       = 0;
        REPORT_ID*                        report_header     = NULL;
        SIZE_T                            total_size        = NULL;
        OPEN_HANDLE_FAILURE_REPORT        handle_report     = {0};
        ATTACH_PROCESS_REPORT             attach_report     = {0};
        INVALID_PROCESS_ALLOCATION_REPORT allocation_report = {0};
        APC_STACKWALK_REPORT              apc_report        = {0};
        HIDDEN_SYSTEM_THREAD_REPORT       hidden_report     = {0};

        /* allocate enough for the largest report buffer * max reports */
        buffer_size =
            sizeof(APC_STACKWALK_REPORT) * MAX_REPORTS_PER_IRP + sizeof(REPORT_QUEUE_HEADER);

        /* this isnt very c++ of us... */
        buffer = malloc(buffer_size);

        status = DeviceIoControl(this->driver_handle,
                                 IOCTL_HANDLE_REPORTS_IN_CALLBACK_QUEUE,
                                 NULL,
                                 NULL,
                                 buffer,
                                 buffer_size,
                                 &bytes_returned,
                                 NULL);

        if (status == NULL)
        {
                LOG_ERROR("DeviceIoControl failed with status code 0x%x", GetLastError());
                free(buffer);
                return;
        }

        REPORT_QUEUE_HEADER* header = (REPORT_QUEUE_HEADER*)buffer;

        if (!header)
                goto end;

        if (header->count == 0)
                goto end;

        for (INT index = 0; index < header->count; index++)
        {
                report_header =
                    (REPORT_ID*)((UINT64)buffer + sizeof(REPORT_QUEUE_HEADER) + total_size);

                LOG_INFO("Report id: %d", report_header->report_id);

                switch (report_header->report_id)
                {
                case REPORT_ILLEGAL_ATTACH_PROCESS:
                        ReportTypeFromReportQueue<ATTACH_PROCESS_REPORT>(
                            buffer, &total_size, &attach_report);
                        break;
                case REPORT_ILLEGAL_HANDLE_OPERATION:
                        ReportTypeFromReportQueue<OPEN_HANDLE_FAILURE_REPORT>(
                            buffer, &total_size, &handle_report);
                        break;
                case REPORT_INVALID_PROCESS_ALLOCATION:
                        ReportTypeFromReportQueue<INVALID_PROCESS_ALLOCATION_REPORT>(
                            buffer, &total_size, &allocation_report);
                        break;
                case REPORT_APC_STACKWALK:
                        ReportTypeFromReportQueue<APC_STACKWALK_REPORT>(
                            buffer, &total_size, &apc_report);
                        break;
                case REPORT_HIDDEN_SYSTEM_THREAD:
                        ReportTypeFromReportQueue<HIDDEN_SYSTEM_THREAD_REPORT>(
                            buffer, &total_size, &hidden_report);
                        break;
                case REPORT_DPC_STACKWALK:
                        ReportTypeFromReportQueue<DPC_STACKWALK_REPORT>(
                            buffer, &total_size, &hidden_report);
                        break;
                default: break;
                }
        }

end:
        free(buffer);
}

VOID
kernelmode::Driver::RunCallbackReportQueue()
{
        /*TODO have some volatile flag instead */
        this->QueryReportQueue();
}

VOID
kernelmode::Driver::NotifyDriverOnProcessLaunch()
{
        BOOLEAN                                   status      = FALSE;
        kernelmode::DRIVER_INITIATION_INFORMATION information = {0};
        information.protected_process_id                      = GetCurrentProcessId();

        status = DeviceIoControl(this->driver_handle,
                                 IOCTL_NOTIFY_DRIVER_ON_PROCESS_LAUNCH,
                                 &information,
                                 sizeof(kernelmode::DRIVER_INITIATION_INFORMATION),
                                 NULL,
                                 NULL,
                                 NULL,
                                 NULL);

        if (status == NULL)
                LOG_ERROR("Failed to notify driver on process launch 0x%x", GetLastError());
}

VOID
kernelmode::Driver::DetectSystemVirtualization()
{
        BOOLEAN                     status         = FALSE;
        HYPERVISOR_DETECTION_REPORT report         = {0};
        DWORD                       bytes_returned = 0;

        status = DeviceIoControl(this->driver_handle,
                                 IOCTL_PERFORM_VIRTUALIZATION_CHECK,
                                 NULL,
                                 NULL,
                                 &report,
                                 sizeof(HYPERVISOR_DETECTION_REPORT),
                                 &bytes_returned,
                                 NULL);

        if (status == NULL)
        {
                LOG_ERROR("DeviceIoControl failed virtualization detect with status %x",
                          GetLastError());
                return;
        }

        if (report.aperf_msr_timing_check == TRUE || report.invd_emulation_check == TRUE)
                LOG_INFO("HYPERVISOR DETECTED!!!");

        /* shutdown the application or smth lmao */
}

VOID
kernelmode::Driver::CheckHandleTableEntries()
{
        BOOLEAN status         = FALSE;
        DWORD   bytes_returned = {0};

        /*
         * Only pass the IOCTL code and nothing else since the reports are bundled
         * with the handle ObRegisterCallbacks report queue hence the QueryReportQueue
         * function will handle these reports.
         */
        status = DeviceIoControl(this->driver_handle,
                                 IOCTL_ENUMERATE_HANDLE_TABLES,
                                 NULL,
                                 NULL,
                                 NULL,
                                 NULL,
                                 &bytes_returned,
                                 NULL);

        if (status == NULL)
                LOG_ERROR("CheckHandleTableEntries failed with status %x", status);
}

VOID
kernelmode::Driver::RequestModuleExecutableRegions()
{
        BOOLEAN status         = FALSE;
        DWORD   bytes_returned = 0;
        ULONG   module_size    = 0;
        PVOID   buffer         = NULL;

        module_size = this->RequestTotalModuleSize();

        if (module_size == NULL)
        {
                LOG_ERROR("RequestTotalModuleSize failed lolz");
                return;
        }

        LOG_INFO("module size: %lx", module_size);

        /*
         * allocate a buffer big enough for the entire module not including section headers or
         * packet headers, however it should be big enough since executable sections do not
         * make up 100% of the image size. Bit hacky but it works.
         */
        buffer = malloc(module_size);

        if (!buffer)
                return;

        status = DeviceIoControl(this->driver_handle,
                                 IOCTL_RETRIEVE_MODULE_EXECUTABLE_REGIONS,
                                 NULL,
                                 NULL,
                                 buffer,
                                 module_size,
                                 &bytes_returned,
                                 NULL);

        if (status == NULL)
        {
                LOG_ERROR("failed to retrieve module executable regions lozl %x", GetLastError());
                goto end;
        }

        LOG_INFO("bytes returned: %lx", bytes_returned);

        this->report_interface->ServerSend(
            buffer, bytes_returned, CLIENT_REQUEST_MODULE_INTEGRITY_CHECK);

end:
        free(buffer);
}

VOID
kernelmode::Driver::ScanForUnlinkedProcess()
{
        BOOLEAN                           status         = FALSE;
        DWORD                             bytes_returned = 0;
        INVALID_PROCESS_ALLOCATION_REPORT report         = {0};

        status = DeviceIoControl(this->driver_handle,
                                 IOCTL_SCAN_FOR_UNLINKED_PROCESS,
                                 NULL,
                                 NULL,
                                 &report,
                                 sizeof(report),
                                 &bytes_returned,
                                 NULL);

        if (status == NULL)
        {
                LOG_ERROR("failed to scan for unlinked processes %x", GetLastError());
                return;
        }
}

VOID
kernelmode::Driver::PerformIntegrityCheck()
{
        BOOLEAN status = FALSE;

        status = DeviceIoControl(
            this->driver_handle, IOCTL_PERFORM_INTEGRITY_CHECK, NULL, NULL, NULL, NULL, NULL, NULL);

        if (status == NULL)
                LOG_ERROR("Failed to perform integrity check with status %x", status);
}

ULONG
kernelmode::Driver::RequestTotalModuleSize()
{
        BOOLEAN status         = FALSE;
        DWORD   bytes_returned = 0;
        ULONG   module_size    = 0;

        status = DeviceIoControl(this->driver_handle,
                                 IOCTL_REQUEST_TOTAL_MODULE_SIZE,
                                 NULL,
                                 NULL,
                                 &module_size,
                                 sizeof(ULONG),
                                 &bytes_returned,
                                 NULL);

        if (status == NULL)
                LOG_ERROR("CheckHandleTableEntries failed with status %x", status);

        return module_size;
}

VOID
kernelmode::Driver::NotifyDriverOnProcessTermination()
{
        BOOLEAN status = FALSE;

        status = DeviceIoControl(this->driver_handle,
                                 IOCTL_NOTIFY_DRIVER_ON_PROCESS_TERMINATION,
                                 NULL,
                                 NULL,
                                 NULL,
                                 NULL,
                                 NULL,
                                 NULL);

        if (status == NULL)
                LOG_ERROR("NotifyDriverOnProcessTermination failed with status %x", status);
}

VOID
kernelmode::Driver::ValidateKPRCBThreads()
{
        BOOLEAN                     status         = FALSE;
        DWORD                       bytes_returned = 0;
        HIDDEN_SYSTEM_THREAD_REPORT report         = {0};

        status = DeviceIoControl(this->driver_handle,
                                 IOCTL_VALIDATE_KPRCB_CURRENT_THREAD,
                                 NULL,
                                 NULL,
                                 &report,
                                 sizeof(report),
                                 &bytes_returned,
                                 NULL);

        if (status == NULL)
        {
                LOG_ERROR("failed to validate kpcrb threads with status %x", GetLastError());
                return;
        }
}

VOID
kernelmode::Driver::CheckForAttachedThreads()
{
        BOOLEAN status = FALSE;

        status = DeviceIoControl(
            this->driver_handle, IOCTL_DETECT_ATTACHED_THREADS, NULL, NULL, NULL, NULL, NULL, NULL);

        if (status == NULL)
                LOG_ERROR("failed to check for attached threads %x", GetLastError());
}

VOID
kernelmode::Driver::CheckForHiddenThreads()
{
        BOOLEAN status = FALSE;

        status = DeviceIoControl(this->driver_handle,
                                 IOCTL_VALIDATE_KPRCB_CURRENT_THREAD,
                                 NULL,
                                 NULL,
                                 NULL,
                                 NULL,
                                 NULL,
                                 NULL);

        if (status == NULL)
                LOG_ERROR("failed to check for hidden threads %x", GetLastError());
}

VOID
kernelmode::Driver::CheckForEptHooks()
{
        BOOLEAN status = FALSE;

        status = DeviceIoControl(
            this->driver_handle, IOCTL_CHECK_FOR_EPT_HOOK, NULL, NULL, NULL, NULL, NULL, NULL);

        if (status == NULL)
                LOG_ERROR("failed to check for ept hooks %x", GetLastError());
}

VOID
kernelmode::Driver::StackwalkThreadsViaDpc()
{
        BOOLEAN status = FALSE;

        status = DeviceIoControl(
            this->driver_handle, IOCTL_LAUNCH_DPC_STACKWALK, NULL, NULL, NULL, NULL, NULL, NULL);

        if (status == NULL)
                LOG_ERROR("failed to stackwalk threads via dpc %x", GetLastError());
}

VOID
kernelmode::Driver::ValidateSystemModules()
{
        BOOLEAN status = FALSE;

        status = DeviceIoControl(
            this->driver_handle, IOCTL_VALIDATE_SYSTEM_MODULES, NULL, NULL, NULL, NULL, NULL, NULL);

        if (status == NULL)
                LOG_ERROR("failed to validate system modules %x", GetLastError());
}

VOID
kernelmode::Driver::CheckDriverHeartbeat()
{
}

VOID
kernelmode::Driver::VerifyProcessLoadedModuleExecutableRegions()
{
        HANDLE                           process_modules_handle        = INVALID_HANDLE_VALUE;
        MODULEENTRY32                    module_entry                  = {0};
        BOOLEAN                          status                        = FALSE;
        PROCESS_MODULE_INFORMATION       module_information            = {0};
        PROCESS_MODULE_VALIDATION_RESULT validation_result             = {0};
        DWORD                            bytes_returned                = 0;
        RtlDosPathNameToNtPathName_U     pRtlDosPathNameToNtPathName_U = NULL;
        UNICODE_STRING                   nt_path_name                  = {0};

        pRtlDosPathNameToNtPathName_U = (RtlDosPathNameToNtPathName_U)GetProcAddress(
            GetModuleHandle(L"ntdll.dll"), "RtlDosPathNameToNtPathName_U");

        process_modules_handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                                          GetCurrentProcessId());

        if (process_modules_handle == INVALID_HANDLE_VALUE)
        {
                LOG_ERROR("CreateToolHelp32Snapshot with TH32CS_SNAPMODULE failed with status 0x%x",
                          GetLastError());
                return;
        }

        module_entry.dwSize = sizeof(MODULEENTRY32);

        if (!Module32First(process_modules_handle, &module_entry))
        {
                LOG_ERROR("Module32First failed with status 0x%x", GetLastError());
                return;
        }

        do
        {
                module_information.module_base = module_entry.modBaseAddr;
                module_information.module_size = module_entry.modBaseSize;

                status = (*pRtlDosPathNameToNtPathName_U)(module_entry.szExePath, &nt_path_name, NULL, NULL);

                if (!status)
                {
                        LOG_ERROR("RtlDosPathNameToNtPathName_U failed with no status.");
                        continue;
                }

                memcpy(module_information.module_path, nt_path_name.Buffer, MAX_MODULE_PATH);

                status = DeviceIoControl(this->driver_handle,
                                         IOCTL_VALIDATE_PROCESS_LOADED_MODULE,
                                         &module_information,
                                         sizeof(module_information),
                                         &validation_result,
                                         sizeof(validation_result),
                                         &bytes_returned,
                                         NULL);

                if (status == NULL || bytes_returned == NULL)
                {
                        LOG_ERROR("failed to validate process module with status %x",
                                  GetLastError());
                        continue;
                }

                if (validation_result.is_module_valid == FALSE)
                {
                        /*TODO: copy module aswell from an anomaly offset */
                        PROCESS_MODULES_INTEGRITY_CHECK_FAILURE report;
                        report.report_code         = REPORT_CODE_PROCESS_MODULE_VERIFICATION;
                        report.module_base_address = (UINT64)module_entry.modBaseAddr;
                        report.module_size         = module_entry.modBaseSize;
                        std::wstring wstr(module_entry.szModule);
                        std::string  module_name_string = std::string(wstr.begin(), wstr.end());
                        memcpy(
                            &report.module_name, &module_name_string, module_name_string.length());
                        this->report_interface->ReportViolation(&report);
                }
                else
                {
                        LOG_INFO("Module %S is valid", module_entry.szModule);
                }

        } while (Module32Next(process_modules_handle, &module_entry));

end:
        CloseHandle(process_modules_handle);
}

VOID
kernelmode::Driver::SendClientHardwareInformation()
{
        BOOLEAN                             status             = FALSE;
        global::headers::SYSTEM_INFORMATION system_information = {0};
        DWORD                               bytes_returned     = 0;

        status = DeviceIoControl(this->driver_handle,
                                 IOCTL_REQUEST_HARDWARE_INFORMATION,
                                 NULL,
                                 NULL,
                                 &system_information,
                                 sizeof(global::headers::SYSTEM_INFORMATION),
                                 &bytes_returned,
                                 NULL);

        if (status == NULL || bytes_returned == NULL)
        {
                LOG_ERROR("DeviceIoControl failed with status %x", GetLastError());
                return;
        }

        this->report_interface->ServerSend(&system_information,
                                           sizeof(global::headers::SYSTEM_INFORMATION),
                                           CLIENT_SEND_SYSTEM_INFORMATION);
}

BOOLEAN
kernelmode::Driver::InitiateApcOperation(INT OperationId)
{
        BOOLEAN                   status    = FALSE;
        APC_OPERATION_INFORMATION operation = {0};

        operation.operation_id = OperationId;

        status = DeviceIoControl(this->driver_handle,
                                 IOCTL_INITIATE_APC_OPERATION,
                                 &operation,
                                 sizeof(APC_OPERATION_INFORMATION),
                                 NULL,
                                 NULL,
                                 NULL,
                                 NULL);

        if (status == NULL)
        {
                LOG_ERROR("DeviceIoControl failed with status %x", GetLastError());
                return status;
        }
}

VOID
GetKernelStructureOffsets()
{
}
