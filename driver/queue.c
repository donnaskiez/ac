#include "queue.h"

#include "callbacks.h"

#include "driver.h"

#include "queue.h"
#include "pool.h"
#include "thread.h"
#include "io.h"
#include "common.h"
#include "imports.h"

VOID
InitialiseGlobalReportQueue()
{
        PREPORT_QUEUE_HEAD queue = GetDriverReportQueue();

        queue->head.start          = NULL;
        queue->head.end            = NULL;
        queue->head.entries        = 0;
        queue->is_driver_unloading = FALSE;

        ImpKeInitializeGuardedMutex(&queue->head.lock);
        ImpKeInitializeGuardedMutex(&queue->lock);
}

VOID
QueuePush(_Inout_ PQUEUE_HEAD Head, _In_ PVOID Data)
{
        ImpKeAcquireGuardedMutex(&Head->lock);

        PQUEUE_NODE temp = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(QUEUE_NODE), QUEUE_POOL_TAG);

        if (!temp)
                goto end;

        Head->entries += 1;

        temp->data = Data;

        if (Head->end != NULL)
                Head->end->next = temp;

        Head->end = temp;

        if (Head->start == NULL)
                Head->start = temp;

end:
        ImpKeReleaseGuardedMutex(&Head->lock);
}

PVOID
QueuePop(_Inout_ PQUEUE_HEAD Head)
{
        ImpKeAcquireGuardedMutex(&Head->lock);

        PVOID       data = NULL;
        PQUEUE_NODE temp = Head->start;

        if (temp == NULL)
                goto end;

        Head->entries = Head->entries - 1;

        data        = temp->data;
        Head->start = temp->next;

        if (Head->end == temp)
                Head->end = NULL;

        ImpExFreePoolWithTag(temp, QUEUE_POOL_TAG);

end:
        ImpKeReleaseGuardedMutex(&Head->lock);
        return data;
}

VOID
InsertReportToQueue(_In_ PVOID Report)
{
        PREPORT_QUEUE_HEAD queue = GetDriverReportQueue();

        if (InterlockedExchange(&queue->is_driver_unloading, queue->is_driver_unloading))
                return;

        ImpKeAcquireGuardedMutex(&queue->lock);
        QueuePush(&queue->head, Report);
        ImpKeReleaseGuardedMutex(&queue->lock);
}

VOID
FreeGlobalReportQueueObjects()
{
        PREPORT_QUEUE_HEAD queue = GetDriverReportQueue();

        InterlockedExchange(&queue->is_driver_unloading, TRUE);
        ImpKeAcquireGuardedMutex(&queue->lock);

        PVOID report = QueuePop(&queue->head);

        while (report)
        {
                ImpExFreePoolWithTag(report, REPORT_POOL_TAG);
                report = QueuePop(&queue->head);
        }

end:
        ImpKeReleaseGuardedMutex(&queue->lock);
}

/*
 * This function handles sending all the pending reports in the global report
 * queue to the usermode application. This function is called periodically by the
 * usermode application. The reason I have implemented this is because as this application
 * expanded, it became apparent that some of the driver functions will generate multiple
 * reports as a result of a single usermode request and hence it makes dealing with
 * reports generated from ObRegisterCallbacks for example much easier.
 */
NTSTATUS
HandlePeriodicGlobalReportQueueQuery(_Out_ PIRP Irp)
{
        INT                        count              = 0;
        NTSTATUS                   status             = STATUS_UNSUCCESSFUL;
        PVOID                      report             = NULL;
        SIZE_T                     total_size         = 0;
        PVOID                      report_buffer      = NULL;
        ULONG                      report_buffer_size = 0;
        PREPORT_HEADER             report_header      = NULL;
        GLOBAL_REPORT_QUEUE_HEADER header             = {0};
        PREPORT_QUEUE_HEAD         queue              = GetDriverReportQueue();

        ImpKeAcquireGuardedMutex(&queue->lock);

        report_buffer_size = sizeof(INVALID_PROCESS_ALLOCATION_REPORT) * MAX_REPORTS_PER_IRP +
                             sizeof(GLOBAL_REPORT_QUEUE_HEADER);

        status = ValidateIrpOutputBuffer(Irp, report_buffer_size);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ValidateIrpOutputBuffer failed with status %x", status);
                ImpKeReleaseGuardedMutex(&queue->lock);
                return status;
        }

        report_buffer = ImpExAllocatePool2(
            POOL_FLAG_NON_PAGED, report_buffer_size, REPORT_QUEUE_TEMP_BUFFER_TAG);

        if (!report_buffer)
        {
                ImpKeReleaseGuardedMutex(&queue->lock);
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        report = QueuePop(&queue->head);

        if (report == NULL)
        {
                DEBUG_VERBOSE("Callback report queue is empty. No reports to be sent to usermode.");
                goto end;
        }

        while (report != NULL)
        {
                if (count >= MAX_REPORTS_PER_IRP)
                        goto end;

                report_header = (PREPORT_HEADER)report;

                switch (report_header->report_id)
                {
                case REPORT_ILLEGAL_HANDLE_OPERATION:

                        RtlCopyMemory((UINT64)report_buffer + sizeof(GLOBAL_REPORT_QUEUE_HEADER) +
                                          total_size,
                                      report,
                                      sizeof(OPEN_HANDLE_FAILURE_REPORT));

                        total_size += sizeof(OPEN_HANDLE_FAILURE_REPORT);
                        break;

                case REPORT_ILLEGAL_ATTACH_PROCESS:

                        RtlCopyMemory((UINT64)report_buffer + sizeof(GLOBAL_REPORT_QUEUE_HEADER) +
                                          total_size,
                                      report,
                                      sizeof(ATTACH_PROCESS_REPORT));

                        total_size += sizeof(ATTACH_PROCESS_REPORT);
                        break;

                case REPORT_INVALID_PROCESS_ALLOCATION:

                        RtlCopyMemory((UINT64)report_buffer + sizeof(GLOBAL_REPORT_QUEUE_HEADER) +
                                          total_size,
                                      report,
                                      sizeof(INVALID_PROCESS_ALLOCATION_REPORT));

                        total_size += sizeof(INVALID_PROCESS_ALLOCATION_REPORT);
                        break;

                case REPORT_APC_STACKWALK:

                        RtlCopyMemory((UINT64)report_buffer + sizeof(GLOBAL_REPORT_QUEUE_HEADER) +
                                          total_size,
                                      report,
                                      sizeof(APC_STACKWALK_REPORT));

                        total_size += sizeof(APC_STACKWALK_REPORT);
                        break;

                case REPORT_HIDDEN_SYSTEM_THREAD:

                        RtlCopyMemory((UINT64)report_buffer + sizeof(GLOBAL_REPORT_QUEUE_HEADER) +
                                          total_size,
                                      report,
                                      sizeof(HIDDEN_SYSTEM_THREAD_REPORT));

                        total_size += sizeof(HIDDEN_SYSTEM_THREAD_REPORT);
                        break;

                case REPORT_DPC_STACKWALK:

                        RtlCopyMemory((UINT64)report_buffer + sizeof(GLOBAL_REPORT_QUEUE_HEADER) +
                                          total_size,
                                      report,
                                      sizeof(DPC_STACKWALK_REPORT));

                        total_size += sizeof(DPC_STACKWALK_REPORT);
                        break;

                case REPORT_DATA_TABLE_ROUTINE:

                        RtlCopyMemory((UINT64)report_buffer + sizeof(GLOBAL_REPORT_QUEUE_HEADER) +
                                          total_size,
                                      report,
                                      sizeof(DATA_TABLE_ROUTINE_REPORT));

                        total_size += sizeof(DATA_TABLE_ROUTINE_REPORT);
                        break;
                }

                /* QueuePop frees the node, but we still need to free the returned data */
                ImpExFreePoolWithTag(report, REPORT_POOL_TAG);

                report = QueuePop(&queue->head);
                count += 1;
        }

end:

        ImpKeReleaseGuardedMutex(&queue->lock);

        Irp->IoStatus.Information = sizeof(GLOBAL_REPORT_QUEUE_HEADER) + total_size;
        header.count              = count;

        RtlCopyMemory(report_buffer, &header, sizeof(GLOBAL_REPORT_QUEUE_HEADER));
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer,
                      report_buffer,
                      sizeof(GLOBAL_REPORT_QUEUE_HEADER) + total_size);

        if (report_buffer)
                ImpExFreePoolWithTag(report_buffer, REPORT_QUEUE_TEMP_BUFFER_TAG);

        DEBUG_VERBOSE("All reports moved into the IRP, sending to usermode.");
        return STATUS_SUCCESS;
}