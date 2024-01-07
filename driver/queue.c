#include "queue.h"

#include "callbacks.h"

#include "driver.h"

#include "queue.h"
#include "pool.h"
#include "thread.h"
#include "ioctl.h"
#include "common.h"
#include "imports.h"

/*
 * This mutex is to prevent a new item being pushed to the queue
 * while the HandlePeriodicCallbackReportQueue is iterating through
 * the objects. This can be an issue because the spinlock is released
 * after each report is placed in the IRP buffer which means a new report
 * can be pushed into the queue before the next iteration can take ownership
 * of the spinlock.
 */
typedef struct _REPORT_QUEUE_CONFIGURATION
{
        QUEUE_HEAD       head;
        volatile BOOLEAN is_driver_unloading;
        KGUARDED_MUTEX   lock;

} REPORT_QUEUE_CONFIGURATION, *PREPORT_QUEUE_CONFIGURATION;

REPORT_QUEUE_CONFIGURATION report_queue_config = {0};

VOID
InitialiseGlobalReportQueue(_Out_ PBOOLEAN Status)
{
        report_queue_config.head.start          = NULL;
        report_queue_config.head.end            = NULL;
        report_queue_config.head.entries        = 0;
        report_queue_config.is_driver_unloading = FALSE;

        ImpKeInitializeGuardedMutex(&report_queue_config.head.lock);
        ImpKeInitializeGuardedMutex(&report_queue_config.lock);

        *Status = TRUE;
}

// PQUEUE_HEAD QueueCreate()
//{
//	PQUEUE_HEAD head = ExAllocatePool2( POOL_FLAG_NON_PAGED, sizeof( QUEUE_HEAD ),
// QUEUE_POOL_TAG );
//
//	if ( !head )
//		return NULL;
//
//	head->end = NULL;
//	head->start = NULL;
//	head->entries = 0;
//
//	KeInitializeSpinLock( &head->lock );
//
//	return head;
// }

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
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

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
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

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
VOID
InsertReportToQueue(_In_ PVOID Report)
{
        if (InterlockedExchange(&report_queue_config.is_driver_unloading,
                                report_queue_config.is_driver_unloading))
                return;

        ImpKeAcquireGuardedMutex(&report_queue_config.lock);
        QueuePush(&report_queue_config.head, Report);
        ImpKeReleaseGuardedMutex(&report_queue_config.lock);
}

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
VOID
FreeGlobalReportQueueObjects()
{
        InterlockedExchange(&report_queue_config.is_driver_unloading, TRUE);
        ImpKeAcquireGuardedMutex(&report_queue_config.lock);

        PVOID report = QueuePop(&report_queue_config.head);

        while (report != NULL)
        {
                ImpExFreePoolWithTag(report, REPORT_POOL_TAG);
                report = QueuePop(&report_queue_config.head);
                DEBUG_VERBOSE("Unloading report queue. Entries remaining: %i",
                              report_queue_config.head.entries);
        }

end:
        ImpKeReleaseGuardedMutex(&report_queue_config.lock);
}

/*
 * This function handles sending all the pending reports in the global report
 * queue to the usermode application. This function is called periodically by the
 * usermode application. The reason I have implemented this is because as this application
 * expanded, it became apparent that some of the driver functions will generate multiple
 * reports as a result of a single usermode request and hence it makes dealing with
 * reports generated from ObRegisterCallbacks for example much easier.
 */
_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
NTSTATUS
HandlePeriodicGlobalReportQueueQuery(_Inout_ PIRP Irp)
{
        INT                        count              = 0;
        NTSTATUS                   status             = STATUS_UNSUCCESSFUL;
        PVOID                      report             = NULL;
        SIZE_T                     total_size         = 0;
        PVOID                      report_buffer      = NULL;
        ULONG                      report_buffer_size = 0;
        PREPORT_HEADER             report_header      = NULL;
        GLOBAL_REPORT_QUEUE_HEADER header             = {0};

        ImpKeAcquireGuardedMutex(&report_queue_config.lock);

        report_buffer_size = sizeof(INVALID_PROCESS_ALLOCATION_REPORT) * MAX_REPORTS_PER_IRP +
                             sizeof(GLOBAL_REPORT_QUEUE_HEADER);

        status = ValidateIrpOutputBuffer(Irp, report_buffer_size);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ValidateIrpOutputBuffer failed with status %x", status);
                ImpKeReleaseGuardedMutex(&report_queue_config.lock);
                return status;
        }

        report_buffer = ImpExAllocatePool2(
            POOL_FLAG_NON_PAGED, report_buffer_size, REPORT_QUEUE_TEMP_BUFFER_TAG);

        if (!report_buffer)
        {
                ImpKeReleaseGuardedMutex(&report_queue_config.lock);
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        report = QueuePop(&report_queue_config.head);

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

                report = QueuePop(&report_queue_config.head);
                count += 1;
        }

end:

        ImpKeReleaseGuardedMutex(&report_queue_config.lock);

        Irp->IoStatus.Information = sizeof(GLOBAL_REPORT_QUEUE_HEADER) + total_size;

        header.count = count;

        RtlCopyMemory(report_buffer, &header, sizeof(GLOBAL_REPORT_QUEUE_HEADER));

        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer,
                      report_buffer,
                      sizeof(GLOBAL_REPORT_QUEUE_HEADER) + total_size);

        if (report_buffer)
                ImpExFreePoolWithTag(report_buffer, REPORT_QUEUE_TEMP_BUFFER_TAG);

        DEBUG_VERBOSE("All reports moved into the IRP, sending to usermode.");
        return STATUS_SUCCESS;
}

/*
 * Simple thread safe linked list implementation. All structures should begin
 * with a SINGLE_LIST_ENTRY structure provided by the windows API. for example:
 *
 *	typedef struct _LIST_ENTRY_STRUCTURE
 *	{
 *		SINGLE_LIST_ENTRY list;
 *		PVOID address;
 *		UINT32 data;
 *		...
 *	};
 *
 * This common structure layout allows us to pass in a callback routine when freeing
 * allowing immense flexibility to ensure we can free and/or deference any objects
 * that are referenced in said object.
 *
 * I've opted to use a mutex rather then a spinlock since there are many times we
 * enumerate the list for extended periods aswell as queue up many insertions at
 * once.
 */
VOID
ListInit(_Inout_ PSINGLE_LIST_ENTRY Head, _Inout_ PKGUARDED_MUTEX Lock)
{
        ImpKeInitializeGuardedMutex(Lock);
        Head->Next = NULL;
}

_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
VOID
ListInsert(_Inout_ PSINGLE_LIST_ENTRY Head,
           _Inout_ PSINGLE_LIST_ENTRY NewEntry,
           _In_ PKGUARDED_MUTEX       Lock)
{
        ImpKeAcquireGuardedMutex(Lock);

        PSINGLE_LIST_ENTRY old_entry = Head->Next;

        Head->Next     = NewEntry;
        NewEntry->Next = old_entry;

        ImpKeReleaseGuardedMutex(Lock);
}

/*
 * Assuming the SINGLE_LIST_ENTRY is the first item in the structure, we
 * can pass a callback routine to be called before the free occurs. This
 * allows us to dereference/free structure specific items whilst still allowing
 * the list to remain flexible.
 */
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
BOOLEAN
ListFreeFirstEntry(_Inout_ PSINGLE_LIST_ENTRY Head,
                   _In_ PKGUARDED_MUTEX       Lock,
                   _In_opt_ PVOID             CallbackRoutine)
{
        BOOLEAN result = FALSE;
        ImpKeAcquireGuardedMutex(Lock);

        if (Head->Next)
        {
                PSINGLE_LIST_ENTRY entry = Head->Next;

                if (CallbackRoutine)
                {
                        VOID (*callback_function_ptr)(PVOID) = CallbackRoutine;
                        (*callback_function_ptr)(entry);
                }

                Head->Next = Head->Next->Next;
                ImpExFreePoolWithTag(entry, POOL_TAG_THREAD_LIST);
                result = TRUE;
        }

        ImpKeReleaseGuardedMutex(Lock);
        return result;
}

/*
 * If we are removing a specific entry, its assumed we have freed and/or dereferenced
 * any fields in the structure.
 */
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
VOID
ListRemoveEntry(_Inout_ PSINGLE_LIST_ENTRY Head,
                _Inout_ PSINGLE_LIST_ENTRY Entry,
                _In_ PKGUARDED_MUTEX       Lock)
{
        ImpKeAcquireGuardedMutex(Lock);

        PSINGLE_LIST_ENTRY entry = Head->Next;

        if (!entry)
                goto unlock;

        if (entry == Entry)
        {
                Head->Next = entry->Next;
                ImpExFreePoolWithTag(Entry, POOL_TAG_THREAD_LIST);
                goto unlock;
        }

        while (entry->Next)
        {
                if (entry->Next == Entry)
                {
                        entry->Next = Entry->Next;
                        ImpExFreePoolWithTag(Entry, POOL_TAG_THREAD_LIST);
                        goto unlock;
                }

                entry = entry->Next;
        }

unlock:
        ImpKeReleaseGuardedMutex(Lock);
}
