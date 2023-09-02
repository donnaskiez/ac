#include "queue.h"

#include "callbacks.h"

#include "driver.h"

#include "queue.h"
#include "pool.h"
#include "thread.h"
#include "common.h"

typedef struct _REPORT_HEADER
{
	INT report_id;

}REPORT_HEADER, * PREPORT_HEADER;

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
	QUEUE_HEAD head;
	KGUARDED_MUTEX lock;

}REPORT_QUEUE_CONFIGURATION, *PREPORT_QUEUE_CONFIGURATION;

REPORT_QUEUE_CONFIGURATION report_queue_config = { 0 };

VOID InitialiseGlobalReportQueue(
	_In_ PBOOLEAN Status
)
{
	report_queue_config.head.start = NULL;
	report_queue_config.head.end = NULL;
	report_queue_config.head.entries = 0;

	KeInitializeSpinLock( &report_queue_config.head.lock );
	KeInitializeGuardedMutex( &report_queue_config.lock );

	*Status = TRUE;
}

//PQUEUE_HEAD QueueCreate()
//{
//	PQUEUE_HEAD head = ExAllocatePool2( POOL_FLAG_NON_PAGED, sizeof( QUEUE_HEAD ), QUEUE_POOL_TAG );
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
//}

VOID QueuePush( 
	_In_ PQUEUE_HEAD Head,
	_In_ PVOID Data
)
{
	KIRQL irql = KeGetCurrentIrql();
	KeAcquireSpinLock( &Head->lock, &irql );

	PQUEUE_NODE temp = ExAllocatePool2( POOL_FLAG_NON_PAGED, sizeof( QUEUE_NODE ), QUEUE_POOL_TAG );

	if ( !temp )
		goto end;

	Head->entries += 1;

	temp->data = Data;

	if ( Head->end != NULL )
		Head->end->next = temp;

	Head->end = temp;

	if ( Head->start == NULL )
		Head->start = temp;

end:
	KeReleaseSpinLock( &Head->lock, irql );
}

PVOID QueuePop(
	_In_ PQUEUE_HEAD Head
)
{
	KIRQL irql = KeGetCurrentIrql();
	KeAcquireSpinLock( &Head->lock, &irql );

	PVOID data = NULL;
	PQUEUE_NODE temp = Head->start;

	if ( temp == NULL )
		goto end;

	Head->entries = Head->entries - 1;

	data = temp->data;
	Head->start = temp->next;

	if ( Head->end == temp )
		Head->end = NULL;

	ExFreePoolWithTag( temp, QUEUE_POOL_TAG );

end:
	KeReleaseSpinLock( &Head->lock, irql );
	return data;
}

VOID InsertReportToQueue(
	_In_ PVOID Report
)
{
	KeAcquireGuardedMutex( &report_queue_config.lock );
	QueuePush( &report_queue_config.head, Report );
	KeReleaseGuardedMutex( &report_queue_config.lock );
}

VOID FreeGlobalReportQueueObjects()
{
	KeAcquireGuardedMutex( &report_queue_config.lock );

	PVOID report = QueuePop( &report_queue_config.head );

	while ( report != NULL )
	{
		ExFreePoolWithTag( report, REPORT_POOL_TAG );
		report = QueuePop( &report_queue_config.head );
	}

end:
	KeReleaseGuardedMutex( &report_queue_config.lock );
}

/*
* This function handles sending all the pending reports in the global report
* queue to the usermode application. This function is called periodically by the
* usermode application. The reason I have implemented this is because as this application
* expanded, it became apparent that some of the driver functions will generate multiple
* reports as a result of a single usermode request and hence it makes dealing with
* reports generated from ObRegisterCallbacks for example much easier.
*/
NTSTATUS HandlePeriodicGlobalReportQueueQuery(
	_In_ PIRP Irp
)
{
	PVOID report = NULL;
	INT count = 0;
	GLOBAL_REPORT_QUEUE_HEADER header;
	PVOID report_buffer = NULL;
	PREPORT_HEADER report_header;
	SIZE_T total_size = NULL;

	KeAcquireGuardedMutex( &report_queue_config.lock );
	report = QueuePop( &report_queue_config.head );

	report_buffer = ExAllocatePool2( POOL_FLAG_NON_PAGED, 1024 * 2, REPORT_QUEUE_TEMP_BUFFER_TAG );

	if ( !report_buffer )
	{
		DEBUG_LOG( "Failed to allocate report buffer" );
		KeReleaseGuardedMutex( &report_queue_config.lock );
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	if ( report == NULL )
	{
		DEBUG_LOG( "callback report queue is empty, returning" );
		goto end;
	}

	while ( report != NULL )
	{
		if ( count >= MAX_REPORTS_PER_IRP )
			goto end;

		report_header = ( PREPORT_HEADER )report;

		switch ( report_header->report_id )
		{
		case REPORT_ILLEGAL_HANDLE_OPERATION:

			RtlCopyMemory(
				( UINT64 )report_buffer + sizeof( GLOBAL_REPORT_QUEUE_HEADER ) + total_size,
				report,
				sizeof( OPEN_HANDLE_FAILURE_REPORT )
			);

			total_size += sizeof( OPEN_HANDLE_FAILURE_REPORT );

			break;

		case REPORT_ILLEGAL_ATTACH_PROCESS:

			RtlCopyMemory(
				( UINT64 )report_buffer + sizeof( GLOBAL_REPORT_QUEUE_HEADER ) + total_size,
				report,
				sizeof( ATTACH_PROCESS_REPORT )
			);

			total_size += sizeof( ATTACH_PROCESS_REPORT );

			break;
		}

		/* QueuePop frees the node, but we still need to free the returned data */
		ExFreePoolWithTag( report, REPORT_POOL_TAG );

		report = QueuePop( &report_queue_config.head );
		count += 1;
	}

end:

	Irp->IoStatus.Information = sizeof( GLOBAL_REPORT_QUEUE_HEADER ) + total_size;

	header.count = count;

	RtlCopyMemory(
		report_buffer,
		&header,
		sizeof( GLOBAL_REPORT_QUEUE_HEADER ) );

	RtlCopyMemory(
		Irp->AssociatedIrp.SystemBuffer,
		report_buffer,
		sizeof( GLOBAL_REPORT_QUEUE_HEADER ) + total_size
	);

	KeReleaseGuardedMutex( &report_queue_config.lock );

	if ( report_buffer )
		ExFreePoolWithTag( report_buffer, REPORT_QUEUE_TEMP_BUFFER_TAG );

	DEBUG_LOG( "Moved all reports into the IRP, sending !" );
	return STATUS_SUCCESS;
}
