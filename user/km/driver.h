#ifndef DRIVER_H
#define DRIVER_H

#include <Windows.h>

#include "../threadpool.h"
#include "../client.h"

#define IOCCTL_RUN_NMI_CALLBACKS \
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VALIDATE_DRIVER_OBJECTS \
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20002, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NOTIFY_DRIVER_ON_PROCESS_LAUNCH \
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20004, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HANDLE_REPORTS_IN_CALLBACK_QUEUE \
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20005, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PERFORM_VIRTUALIZATION_CHECK \
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20006, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUMERATE_HANDLE_TABLES \
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20007, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RETRIEVE_MODULE_EXECUTABLE_REGIONS \
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20008, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REQUEST_TOTAL_MODULE_SIZE \
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20009, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NOTIFY_DRIVER_ON_PROCESS_TERMINATION \
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20010, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SCAN_FOR_UNLINKED_PROCESS \
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20011, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PERFORM_INTEGRITY_CHECK \
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20013, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DETECT_ATTACHED_THREADS \
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20014, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VALIDATE_PROCESS_LOADED_MODULE \
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20015, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REQUEST_HARDWARE_INFORMATION \
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20016, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INITIATE_APC_OPERATION \
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20017, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CHECK_FOR_EPT_HOOK \
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20018, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_LAUNCH_DPC_STACKWALK \
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20019, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VALIDATE_SYSTEM_MODULES \
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20020, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MAX_REPORTS_PER_IRP 20

#define MAX_MODULE_PATH 256

namespace kernelmode {
enum APC_OPERATION_IDS
{
        operation_stackwalk = 0x1
};

class Driver
{
        HANDLE                          driver_handle;
        LPCWSTR                         driver_name;
        std::shared_ptr<global::Client> report_interface;

        ULONG RequestTotalModuleSize();
        VOID  NotifyDriverOnProcessLaunch();
        VOID  CheckDriverHeartbeat();
        VOID  NotifyDriverOnProcessTermination();
        // VOID GetKernelStructureOffsets();

        template <typename T>
        VOID ReportTypeFromReportQueue(CONST PVOID Buffer, PSIZE_T Offset, PVOID Report)
        {
                Report = (T*)((UINT64)Buffer +
                              sizeof(global::report_structures::REPORT_QUEUE_HEADER) + *Offset);

                this->report_interface->ReportViolation((T*)Report);

                *Offset += sizeof(T);
        }

    public:
        Driver(LPCWSTR DriverName, std::shared_ptr<global::Client> ReportInterface);
        ~Driver();

        VOID    RunNmiCallbacks();
        VOID    VerifySystemModuleDriverObjects();
        VOID    RunCallbackReportQueue();
        VOID    DetectSystemVirtualization();
        VOID    QueryReportQueue();
        VOID    CheckHandleTableEntries();
        VOID    RequestModuleExecutableRegions();
        VOID    ScanForUnlinkedProcess();
        VOID    PerformIntegrityCheck();
        VOID    CheckForAttachedThreads();
        VOID    VerifyProcessLoadedModuleExecutableRegions();
        VOID    SendClientHardwareInformation();
        VOID    CheckForEptHooks();
        VOID    StackwalkThreadsViaDpc();
        VOID    ValidateSystemModules();
        BOOLEAN InitiateApcOperation(INT OperationId);
};

struct DRIVER_INITIATION_INFORMATION
{
        ULONG protected_process_id;
};

struct HYPERVISOR_DETECTION_REPORT
{
        INT aperf_msr_timing_check;
        INT invd_emulation_check;
};

struct PROCESS_MODULE_INFORMATION
{
        PVOID  module_base;
        SIZE_T module_size;
        WCHAR  module_path[MAX_MODULE_PATH];
};

struct PROCESS_MODULE_VALIDATION_RESULT
{
        INT is_module_valid;
};

struct APC_OPERATION_INFORMATION
{
        int operation_id;
};
}

#endif
