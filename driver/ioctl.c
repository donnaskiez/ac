#include "ioctl.h"

#include "modules.h"
#include "driver.h"
#include "callbacks.h"
#include "pool.h"
#include "integrity.h"
#include "thread.h"
#include "queue.h"
#include "hv.h"

STATIC
NTSTATUS
DispatchApcOperation(_In_ PAPC_OPERATION_ID Operation);

#ifdef ALLOC_PRAGMA
#        pragma alloc_text(PAGE, DispatchApcOperation)
#        pragma alloc_text(PAGE, DeviceControl)
#        pragma alloc_text(PAGE, DeviceClose)
#        pragma alloc_text(PAGE, DeviceCreate)
#endif

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

#define APC_OPERATION_STACKWALK 0x1

STATIC
NTSTATUS
DispatchApcOperation(_In_ PAPC_OPERATION_ID Operation)
{
        PAGED_CODE();

        NTSTATUS status = STATUS_UNSUCCESSFUL;

        DEBUG_VERBOSE("Dispatching APC Operation...");

        switch (Operation->operation_id)
        {
        case APC_OPERATION_STACKWALK:

                DEBUG_INFO("Initiating APC stackwalk operation with operation id %i",
                           Operation->operation_id);

                status = ValidateThreadsViaKernelApc();

                if (!NT_SUCCESS(status))
                        DEBUG_ERROR("ValidateThreadsViaKernelApc failed with status %x", status);

                return status;

        default: DEBUG_WARNING("Invalid operation ID passed"); return STATUS_INVALID_PARAMETER;
        }

        return status;
}

/*
 * Obviously, its important we check that the input and output buffer sizes for each IRP is big
 * enough to hold the incoming and outgoing information.
 *
 * Another important thing to note is that the windows IO manager will only zero out the size
 * of the input buffer. Given that we use METHOD_BUFFERED for all communication, the input
 * and output buffer are the same, with the size used being that of the greatest buffer passed
 * to DeviceIoControl. The IO manager will then zero our the buffer to the size of the input
 * buffer, so if the output buffer is larger then the input buffer there will be uninitialised
 * memory in the buffer so we must zero out the buffer to the length of the output buffer.
 *
 * We then set the IoStatus.Information field to the size of the buffer we are passing back.
 * If we don't do this and we allocate an output buffer of size 0x1000, yet only use 0x100 bytes,
 * the user mode apps output buffer will receive 0x100 bytes + 0x900 bytes of uninitialised memory
 * which is an information leak.
 */
NTSTATUS
ValidateIrpOutputBuffer(_In_ PIRP Irp, _In_ ULONG RequiredSize)
{
        if (!Irp || !RequiredSize)
                return STATUS_INVALID_PARAMETER;

        PIO_STACK_LOCATION io = IoGetCurrentIrpStackLocation(Irp);

        if (!io)
                return STATUS_ABANDONED;

        if (io->Parameters.DeviceIoControl.OutputBufferLength < RequiredSize)
                return STATUS_BUFFER_TOO_SMALL;

        RtlSecureZeroMemory(Irp->AssociatedIrp.SystemBuffer, RequiredSize);

        Irp->IoStatus.Information = RequiredSize;

        return STATUS_SUCCESS;
}

/*
 * Here we just check that the input buffers size matches the expected size..
 * It isnt a very secure check but we can work on that later...
 */
NTSTATUS
ValidateIrpInputBuffer(_In_ PIRP Irp, _In_ ULONG RequiredSize)
{
        if (!Irp || !RequiredSize)
                return STATUS_INVALID_PARAMETER;

        PIO_STACK_LOCATION io = IoGetCurrentIrpStackLocation(Irp);

        if (!io)
                return STATUS_ABANDONED;

        if (io->Parameters.DeviceIoControl.InputBufferLength != RequiredSize)
                return STATUS_INVALID_BUFFER_SIZE;

        return STATUS_SUCCESS;
}

//_Dispatch_type_(IRP_MJ_SYSTEM_CONTROL)
NTSTATUS
DeviceControl(_In_ PDRIVER_OBJECT DriverObject, _Inout_ PIRP Irp)
{
        UNREFERENCED_PARAMETER(DriverObject);
        PAGED_CODE();

        NTSTATUS           status         = STATUS_SUCCESS;
        PIO_STACK_LOCATION stack_location = IoGetCurrentIrpStackLocation(Irp);
        HANDLE             handle         = NULL;
        PKTHREAD           thread         = NULL;
        BOOLEAN            security_flag  = FALSE;

        /*
         * LMAO
         */
        ReadProcessInitialisedConfigFlag(&security_flag);

        if (security_flag == FALSE && stack_location->Parameters.DeviceIoControl.IoControlCode !=
                                          IOCTL_NOTIFY_DRIVER_ON_PROCESS_LAUNCH)
        {
                status = STATUS_ACCESS_DENIED;
                goto end;
        }

        switch (stack_location->Parameters.DeviceIoControl.IoControlCode)
        {
        case IOCCTL_RUN_NMI_CALLBACKS:

                DEBUG_INFO("IOCTL_RUN_NMI_CALLBACKS Received.");

                status = HandleNmiIOCTL(Irp);

                if (!NT_SUCCESS(status))
                        DEBUG_ERROR("RunNmiCallbacks failed with status %lx", status);

                break;

        case IOCTL_VALIDATE_DRIVER_OBJECTS:

                DEBUG_INFO("IOCTL_VALIDATE_DRIVER_OBJECTS Received.");

                /*
                 * The reason this function is run in a new thread and not the thread
                 * issuing the IOCTL is because ZwOpenDirectoryObject issues a
                 * user mode handle if called on the user mode thread calling DeviceIoControl.
                 * This is a problem because when we pass said handle to ObReferenceObjectByHandle
                 * it will issue a bug check under windows driver verifier.
                 */

                status = PsCreateSystemThread(
                    &handle, PROCESS_ALL_ACCESS, NULL, NULL, NULL, HandleValidateDriversIOCTL, Irp);

                if (!NT_SUCCESS(status))
                {
                        DEBUG_ERROR("PsCreateSystemThread failed with status %x", status);
                        goto end;
                }

                /*
                 * Thread objects are a type of dispatcher object, meaning when they are freed
                 * its set to the signal state and any waiters will be signalled. This allows
                 * us to wait til our threads terminated and the IRP buffer has been either filled
                 * or left empty and then from there we can complete the IRP and return.
                 */
                status = ObReferenceObjectByHandle(
                    handle, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, &thread, NULL);

                if (!NT_SUCCESS(status))
                {
                        DEBUG_ERROR("ObReferenceObjectbyhandle failed with status %lx", status);
                        ZwClose(handle);
                        goto end;
                }

                KeWaitForSingleObject(thread, Executive, KernelMode, FALSE, NULL);

                ZwClose(handle);
                ObDereferenceObject(thread);

                break;

        case IOCTL_NOTIFY_DRIVER_ON_PROCESS_LAUNCH:;

                DEBUG_INFO("IOCTL_NOTIFY_DRIVER_ON_PROCESS_LAUNCH Received");

                status = ProcLoadInitialiseProcessConfig(Irp);

                if (!NT_SUCCESS(status))
                {
                        DEBUG_ERROR("InitialiseProcessConfig failed with status %x", status);
                        goto end;
                }

                status = ProcLoadEnableObCallbacks();

                if (!NT_SUCCESS(status))
                        DEBUG_ERROR("EnableObCallbacks failed with status %x", status);

                break;

        case IOCTL_HANDLE_REPORTS_IN_CALLBACK_QUEUE:

                DEBUG_INFO("IOCTL_HANDLE_REPORTS_IN_CALLBACK_QUEUE Received");

                status = QueryActiveApcContextsForCompletion();

                if (!NT_SUCCESS(status))
                        DEBUG_ERROR("QueryActiveApcContextsForCompletion failed with status %x",
                                    status);

                status = HandlePeriodicGlobalReportQueueQuery(Irp);

                if (!NT_SUCCESS(status))
                        DEBUG_ERROR("HandlePeriodicGlobalReportQueueQuery failed with status %x",
                                    status);

                break;

        case IOCTL_PERFORM_VIRTUALIZATION_CHECK:

                DEBUG_INFO("IOCTL_PERFORM_VIRTUALIZATION_CHECK Received");

                status = PerformVirtualizationDetection(Irp);

                if (!NT_SUCCESS(status))
                        DEBUG_ERROR("PerformVirtualizationDetection failed with status %x", status);

                break;

        case IOCTL_ENUMERATE_HANDLE_TABLES:

                DEBUG_INFO("IOCTL_ENUMERATE_HANDLE_TABLES Received");

                /* can maybe implement this better so we can extract a status value */
                EnumerateProcessListWithCallbackRoutine(EnumerateProcessHandles, NULL);

                break;

        case IOCTL_RETRIEVE_MODULE_EXECUTABLE_REGIONS:

                DEBUG_VERBOSE("IOCTL_RETRIEVE_MODULE_EXECUTABLE_REGIONS Received");

                status = PsCreateSystemThread(&handle,
                                              PROCESS_ALL_ACCESS,
                                              NULL,
                                              NULL,
                                              NULL,
                                              RetrieveInMemoryModuleExecutableSections,
                                              Irp);

                if (!NT_SUCCESS(status))
                {
                        DEBUG_ERROR("PsCreateSystemThread failed with status %x", status);
                        goto end;
                }

                status = ObReferenceObjectByHandle(
                    handle, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, &thread, NULL);

                if (!NT_SUCCESS(status))
                {
                        DEBUG_ERROR("ObReferenceObjectbyhandle failed with status %lx", status);
                        ZwClose(handle);
                        goto end;
                }

                KeWaitForSingleObject(thread, Executive, KernelMode, FALSE, NULL);

                ZwClose(handle);
                ObDereferenceObject(thread);

                break;

        case IOCTL_REQUEST_TOTAL_MODULE_SIZE:

                DEBUG_INFO("IOCTL_REQUEST_TOTAL_MODULE_SIZE Received");

                status = GetDriverImageSize(Irp);

                if (!NT_SUCCESS(status))
                        DEBUG_ERROR("GetDriverImageSize failed with status %x", status);

                break;

        case IOCTL_NOTIFY_DRIVER_ON_PROCESS_TERMINATION:

                DEBUG_INFO("IOCTL_NOTIFY_DRIVER_ON_PROCESS_TERMINATION Received");

                ProcCloseClearProcessConfiguration();
                ProcCloseDisableObCallbacks();

                break;

        case IOCTL_SCAN_FOR_UNLINKED_PROCESS:

                DEBUG_INFO("IOCTL_SCAN_FOR_UNLINKED_PROCESS Received");

                status = FindUnlinkedProcesses();

                if (!NT_SUCCESS(status))
                        DEBUG_ERROR("FindUnlinkedProcesses failed with status %x", status);

                break;

        case IOCTL_PERFORM_INTEGRITY_CHECK:

                DEBUG_INFO("IOCTL_PERFORM_INTEGRITY_CHECK Received");

                status = VerifyInMemoryImageVsDiskImage();

                if (!NT_SUCCESS(status))
                        DEBUG_ERROR("VerifyInMemoryImageVsDiskImage failed with status %x", status);

                break;

        case IOCTL_DETECT_ATTACHED_THREADS:

                DEBUG_INFO("IOCTL_DETECT_ATTACHED_THREADS Received");

                DetectThreadsAttachedToProtectedProcess();

                break;

        case IOCTL_VALIDATE_PROCESS_LOADED_MODULE:

                DEBUG_INFO("IOCTL_VALIDATE_PROCESS_LOADED_MODULE Received");

                status = ValidateProcessLoadedModule(Irp);

                if (!NT_SUCCESS(status))
                        DEBUG_ERROR("ValidateProcessLoadedModule failed with status %x", status);

                break;

        case IOCTL_REQUEST_HARDWARE_INFORMATION:;

                DEBUG_INFO("IOCTL_REQUEST_HARDWARE_INFORMATION Received");

                PSYSTEM_INFORMATION system_information = NULL;

                GetDriverConfigSystemInformation(&system_information);

                if (!system_information)
                {
                        DEBUG_ERROR("GetDriverConfigSystemInformation failed with no status.");
                        goto end;
                }

                status = ValidateIrpOutputBuffer(Irp, sizeof(SYSTEM_INFORMATION));

                if (!NT_SUCCESS(status))
                {
                        DEBUG_ERROR("ValidateIrpOutputBuffer failed with status %x", status);
                        goto end;
                }

                Irp->IoStatus.Information = sizeof(SYSTEM_INFORMATION);

                RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer,
                              system_information,
                              sizeof(SYSTEM_INFORMATION));

                break;

        case IOCTL_INITIATE_APC_OPERATION:;

                DEBUG_INFO("IOCTL_INITIATE_APC_OPERATION Received");

                PAPC_OPERATION_ID operation = (PAPC_OPERATION_ID)Irp->AssociatedIrp.SystemBuffer;

                status = DispatchApcOperation(operation);

                if (!NT_SUCCESS(status))
                        DEBUG_ERROR("DispatchApcOperation failed with status %x", status);

                break;

        case IOCTL_CHECK_FOR_EPT_HOOK:

                DEBUG_INFO("IOCTL_CHECK_FOR_EPT_HOOK Received");

                status = DetectEptHooksInKeyFunctions();

                if (!NT_SUCCESS(status))
                        DEBUG_ERROR("DetectEpthooksInKeyFunctions failed with status %x", status);

                break;

        case IOCTL_VALIDATE_SYSTEM_MODULES:

                DEBUG_INFO("IOCTL_VALIDATE_SYSTEM_MODULES Received");

                /*
                 * Currently the validation is buggy, once the validation is better will
                 * probably bugcheck the system.
                 */
                status = ValidateSystemModules();

                if (!NT_SUCCESS(status))
                        DEBUG_ERROR("ValidateSystemModules failed with status %x", status);

                break;

        case IOCTL_LAUNCH_DPC_STACKWALK:

                DEBUG_INFO("IOCTL_LAUNCH_DPC_STACKWALK Received");

                status = DispatchStackwalkToEachCpuViaDpc();

                if (!NT_SUCCESS(status))
                        DEBUG_ERROR("DispatchStackwalkToEachCpuViaDpc failed with status %x",
                                    status);

                break;


        default:
                DEBUG_WARNING("Invalid IOCTL passed to driver: %lx",
                            stack_location->Parameters.DeviceIoControl.IoControlCode);

                status = STATUS_INVALID_PARAMETER;
                break;
        }

end:
        DEBUG_VERBOSE("Completing IRP with status %x", status);
        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
}

_Dispatch_type_(IRP_MJ_CLOSE) NTSTATUS
    DeviceClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
        PAGED_CODE();

        UNREFERENCED_PARAMETER(DeviceObject);

        DEBUG_INFO("Handle to driver closed.");

        /*
         * For now its fine, but this will need to be moved to our process load callbacks
         * since right now anyone can open a handle to our driver and then close it lol
         */

        /* we also lose reports here, so sohuld pass em into the irp before freeing */
        FreeGlobalReportQueueObjects();
        ProcCloseClearProcessConfiguration();
        ProcCloseDisableObCallbacks();

        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return Irp->IoStatus.Status;
}

_Dispatch_type_(IRP_MJ_CREATE) NTSTATUS
    DeviceCreate(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
        PAGED_CODE();

        DEBUG_INFO("Handle to driver opened.");
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return Irp->IoStatus.Status;
}