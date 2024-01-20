#include "io.h"

#include "modules.h"
#include "driver.h"
#include "callbacks.h"
#include "pool.h"
#include "integrity.h"
#include "thread.h"
#include "queue.h"
#include "hv.h"
#include "imports.h"
#include "list.h"

STATIC
NTSTATUS
DispatchApcOperation(_In_ PAPC_OPERATION_ID Operation);

#ifdef ALLOC_PRAGMA
#        pragma alloc_text(PAGE, DispatchApcOperation)
#        pragma alloc_text(PAGE, DeviceControl)
#        pragma alloc_text(PAGE, DeviceClose)
#        pragma alloc_text(PAGE, DeviceCreate)
#endif

#define IOCTL_RUN_NMI_CALLBACKS \
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
#define IOCTL_INSERT_IRP_INTO_QUEUE \
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20021, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_QUERY_DEFERRED_REPORTS \
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20022, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define APC_OPERATION_STACKWALK 0x1

/*
 * Basic cancel-safe IRP queue implementation. Stores pending IRPs in a list, allowing us to dequeue
 * entries to send data back to user mode without being invoked by the user mode module via an io
 * completion port.
 *
 * user mode program will automatically queue another irp when an irp completes, ensuring queue has
 * a sufficient supply.
 */
VOID
IrpQueueAcquireLock(_In_ PIO_CSQ Csq, _Out_ PKIRQL Irql)
{
        KeAcquireGuardedMutex(&GetIrpQueueHead()->lock);
}

VOID
IrpQueueReleaseLock(_In_ PIO_CSQ Csq, _Out_ PKIRQL Irql)
{
        KeReleaseGuardedMutex(&GetIrpQueueHead()->lock);
}

PIRP
IrpQueuePeekNextEntry(_In_ PIO_CSQ Csq, _In_ PIRP Irp, _In_ PVOID Context)
{
        PIRP_QUEUE_HEAD queue = GetIrpQueueHead();

        DEBUG_VERBOSE("irp queue entry count: %lx", queue->count);

        if (queue->count == 0)
                return NULL;

        return CONTAINING_RECORD(queue->queue.Flink, IRP, Tail.Overlay.ListEntry);
}

VOID
IrpQueueRemove(_In_ PIO_CSQ Csq, _In_ PIRP Irp)
{
        UNREFERENCED_PARAMETER(Csq);
        GetIrpQueueHead()->count--;
        RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
}

BOOLEAN
IrpQueueIsThereDeferredReport(_In_ PIRP_QUEUE_HEAD Queue)
{
        return Queue->reports.count > 0 ? TRUE : FALSE;
}

PDEFERRED_REPORT
IrpQueueRemoveDeferredReport(_In_ PIRP_QUEUE_HEAD Queue)
{
        return RemoveHeadList(&Queue->reports.head);
}

NTSTATUS
IrpQueueCompleteDeferredReport(_In_ PDEFERRED_REPORT Report, _In_ PIRP Irp)
{
        NTSTATUS status = ValidateIrpOutputBuffer(Irp, Report->buffer_size);

        if (!NT_SUCCESS(status))
                return status;

        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, Report->buffer, Report->buffer_size);
        Irp->IoStatus.Status      = STATUS_SUCCESS;
        Irp->IoStatus.Information = Report->buffer_size;
        IofCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
}

NTSTATUS
IrpQueueQueryPendingReports(_In_ PIRP Irp)
{
        PIRP_QUEUE_HEAD  queue  = GetIrpQueueHead();
        PDEFERRED_REPORT report = NULL;
        NTSTATUS         status = STATUS_UNSUCCESSFUL;

        if (IrpQueueIsThereDeferredReport(queue))
        {
                KeAcquireGuardedMutex(&queue->reports.lock);
                report = IrpQueueRemoveDeferredReport(queue);

                status = IrpQueueCompleteDeferredReport(report, Irp);

                if (!NT_SUCCESS(status))
                        return status;

                queue->reports.count--;
                DEBUG_VERBOSE("Finishing deferred report. Deferred report count: %lx", queue->reports.count);
                KeReleaseGuardedMutex(&queue->reports.lock);
                return status;
        }
        return status;
}

VOID
IrpQueueInsert(_In_ PIO_CSQ Csq, _In_ PIRP Irp)
{
        DEBUG_VERBOSE("inserting IRP");
        PDEFERRED_REPORT report = NULL;
        PIRP_QUEUE_HEAD  queue  = GetIrpQueueHead();
        InsertTailList(&queue->queue, &Irp->Tail.Overlay.ListEntry);
        queue->count++;
}

VOID
IrpQueueCompleteCancelledIrp(_In_ PIO_CSQ Csq, _In_ PIRP Irp)
{
        UNREFERENCED_PARAMETER(Csq);
        Irp->IoStatus.Status = STATUS_CANCELLED;
        Irp->IoStatus.Status = 0;
        ImpIofCompleteRequest(Irp, IO_NO_INCREMENT);
}

PDEFERRED_REPORT
IrpQueueAllocateDeferredReport(_In_ PVOID Buffer, _In_ UINT32 BufferSize)
{
        PDEFERRED_REPORT report =
            ImpExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(DEFERRED_REPORT), REPORT_POOL_TAG);

        if (!report)
                return NULL;

        report->buffer      = Buffer;
        report->buffer_size = BufferSize;

        return report;
}

VOID
IrpQueueDeferReport(_In_ PIRP_QUEUE_HEAD Queue, _In_ PVOID Buffer, _In_ UINT32 BufferSize)
{
        PDEFERRED_REPORT report = IrpQueueAllocateDeferredReport(Buffer, BufferSize);

        if (!report)
                return;

        KeAcquireGuardedMutex(&Queue->reports.lock);
        InsertTailList(&Queue->reports.head, &report->list_entry);
        Queue->reports.count++;
        DEBUG_VERBOSE("Deferring report. Deferred report count: %lx", Queue->reports.count);
        KeReleaseGuardedMutex(&Queue->reports.lock);
}

/* takes ownership of the buffer and frees it regardless of status */
NTSTATUS
IrpQueueCompleteIrp(_In_ PVOID Buffer, _In_ ULONG BufferSize)
{
        NTSTATUS        status = STATUS_UNSUCCESSFUL;
        PIRP_QUEUE_HEAD queue  = GetIrpQueueHead();

        PIRP irp = IoCsqRemoveNextIrp(&queue->csq, NULL);

        /*
         * If no irps are available in our queue, lets store it in a deferred reports list which
         * should be checked each time we insert a new irp into the queue.
         */
        if (!irp)
        {
                IrpQueueDeferReport(queue, Buffer, BufferSize);
                return STATUS_SUCCESS;
        }

        status = ValidateIrpOutputBuffer(irp, BufferSize);

        if (!NT_SUCCESS(status))
        {
                ImpExFreePoolWithTag(Buffer, REPORT_POOL_TAG);
                return status;
        }

        irp->IoStatus.Status      = STATUS_SUCCESS;
        irp->IoStatus.Information = BufferSize;
        RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, Buffer, BufferSize);
        ImpExFreePoolWithTag(Buffer, REPORT_POOL_TAG);
        ImpIofCompleteRequest(irp, IO_NO_INCREMENT);
}

VOID
IrpQueueFreeDeferredReports()
{
        PIRP_QUEUE_HEAD  queue  = GetIrpQueueHead();
        PDEFERRED_REPORT report = NULL;

        while (IrpQueueIsThereDeferredReport(queue))
        {
                report = IrpQueueRemoveDeferredReport(queue);
                ExFreePoolWithTag(report, REPORT_POOL_TAG);
        }
}

NTSTATUS
IrpQueueInitialise()
{
        NTSTATUS        status = STATUS_UNSUCCESSFUL;
        PIRP_QUEUE_HEAD queue  = GetIrpQueueHead();

        KeInitializeGuardedMutex(&queue->lock);
        KeInitializeGuardedMutex(&queue->reports.lock);
        InitializeListHead(&queue->queue);
        InitializeListHead(&queue->reports.head);

        status = IoCsqInitialize(&queue->csq,
                                 IrpQueueInsert,
                                 IrpQueueRemove,
                                 IrpQueuePeekNextEntry,
                                 IrpQueueAcquireLock,
                                 IrpQueueReleaseLock,
                                 IrpQueueCompleteCancelledIrp);

        if (!NT_SUCCESS(status))
                DEBUG_ERROR("IoCsqInitialize failed with status %x", status);

        return status;
}

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
                return STATUS_UNSUCCESSFUL;

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
                return STATUS_UNSUCCESSFUL;

        if (io->Parameters.DeviceIoControl.InputBufferLength != RequiredSize)
                return STATUS_INVALID_BUFFER_SIZE;

        return STATUS_SUCCESS;
}

NTSTATUS
DeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
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
        case IOCTL_RUN_NMI_CALLBACKS:

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

                status = ImpPsCreateSystemThread(&handle,
                                                 PROCESS_ALL_ACCESS,
                                                 NULL,
                                                 NULL,
                                                 NULL,
                                                 HandleValidateDriversIOCTL,
                                                 NULL);

                if (!NT_SUCCESS(status))
                {
                        DEBUG_ERROR("PsCreateSystemThread failed with status %x", status);
                        goto end;
                }

                ImpZwClose(handle);
                break;

        case IOCTL_NOTIFY_DRIVER_ON_PROCESS_LAUNCH:;

                DEBUG_INFO("IOCTL_NOTIFY_DRIVER_ON_PROCESS_LAUNCH Received");

                status = ProcLoadInitialiseProcessConfig(Irp);

                if (!NT_SUCCESS(status))
                {
                        DEBUG_ERROR("InitialiseProcessConfig failed with status %x", status);
                        goto end;
                }

                status = RegisterProcessObCallbacks();

                if (!NT_SUCCESS(status))
                        DEBUG_ERROR("EnableObCallbacks failed with status %x", status);

                break;

        case IOCTL_HANDLE_REPORTS_IN_CALLBACK_QUEUE:

                DEBUG_INFO("IOCTL_HANDLE_REPORTS_IN_CALLBACK_QUEUE Received");

                status = QueryActiveApcContextsForCompletion();

                if (!NT_SUCCESS(status))
                        DEBUG_ERROR("QueryActiveApcContextsForCompletion failed with status %x",
                                    status);

                // status = HandlePeriodicGlobalReportQueueQuery(Irp);

                // if (!NT_SUCCESS(status))
                //         DEBUG_ERROR("HandlePeriodicGlobalReportQueueQuery failed with status %x",
                //                     status);

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

                status = ImpPsCreateSystemThread(&handle,
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

                status = ImpObReferenceObjectByHandle(
                    handle, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, &thread, NULL);

                if (!NT_SUCCESS(status))
                {
                        DEBUG_ERROR("ObReferenceObjectbyhandle failed with status %lx", status);
                        ImpZwClose(handle);
                        goto end;
                }

                ImpKeWaitForSingleObject(thread, Executive, KernelMode, FALSE, NULL);

                ImpZwClose(handle);
                ImpObDereferenceObject(thread);

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
                UnregisterProcessObCallbacks();

                break;

        case IOCTL_SCAN_FOR_UNLINKED_PROCESS:

                DEBUG_INFO("IOCTL_SCAN_FOR_UNLINKED_PROCESS Received");

                status = FindUnlinkedProcesses();

                if (!NT_SUCCESS(status))
                        DEBUG_ERROR("FindUnlinkedProcesses failed with status %x", status);

                break;

        case IOCTL_PERFORM_INTEGRITY_CHECK:

                DEBUG_INFO("IOCTL_PERFORM_INTEGRITY_CHECK Received");

                status = ValidateOurDriverImage();

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

                PSYSTEM_INFORMATION system_information =
                    GetDriverConfigSystemInformation(&system_information);

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

                status = SystemModuleVerificationDispatcher();

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

        case IOCTL_INSERT_IRP_INTO_QUEUE:

                DEBUG_INFO("IOCTL_INSERT_IRP_INTO_QUEUE Received");

                PIRP_QUEUE_HEAD queue = GetIrpQueueHead();

                /*
                 * Given the nature of the Windows IO subsystem and the cancel-safe queue
                 * implementation we use, we need to query for deferred reports before insert an irp
                 * into the queue. The reason for this is the cancel-safe queue will automically
                 * mark the irp as pending, so if we then use that irp to return a deferred report
                 * and return success here verifier has a lil cry.
                 */

                /* before we queue our IRP, check if we can complete a deferred report */
                status = IrpQueueQueryPendingReports(Irp);

                /* if we return success, weve completed the irp, we can return success */
                if (NT_SUCCESS(status))
                        return status;

                /* if there are no deferred reports, store the irp in the queue */
                IoCsqInsertIrp(&queue->csq, Irp, NULL);

                /* we dont want to complete the request */
                return STATUS_PENDING;

        case IOCTL_QUERY_DEFERRED_REPORTS:

                DEBUG_INFO("IOCTL_QUERY_DEFERRED_REPORTS Received");

                status = IrpQueueQueryPendingReports(Irp);

                if (NT_SUCCESS(status))
                        return status;

                status = STATUS_SUCCESS;
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

NTSTATUS
DeviceClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
        PAGED_CODE();
        UNREFERENCED_PARAMETER(DeviceObject);

        DEBUG_INFO("Handle to driver closed.");

        /* we also lose reports here, so sohuld pass em into the irp before freeing */
        ProcCloseClearProcessConfiguration();
        UnregisterProcessObCallbacks();

        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return Irp->IoStatus.Status;
}

NTSTATUS
DeviceCreate(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
        PAGED_CODE();
        DEBUG_INFO("Handle to driver opened.");
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return Irp->IoStatus.Status;
}