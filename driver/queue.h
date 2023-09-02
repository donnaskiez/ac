#ifndef QUEUE_H
#define QUEUE_H

#include <ntifs.h>

#define QUEUE_POOL_TAG 'qqqq'
#define REPORT_QUEUE_TEMP_BUFFER_TAG 'temp'

#define REPORT_POOL_TAG 'repo'

#define MAX_REPORTS_PER_IRP 20

typedef struct _QUEUE_NODE
{
	struct _QUEUE_NODE* next;
	PVOID data;

}QUEUE_NODE, *PQUEUE_NODE;

typedef struct QUEUE_HEAD
{
	struct _QUEUE_NODE* start;
	struct _QUEUE_NODE* end;
	KSPIN_LOCK lock;
	INT entries;

}QUEUE_HEAD, *PQUEUE_HEAD;

typedef struct _GLOBAL_REPORT_QUEUE_HEADER
{
	INT count;

}GLOBAL_REPORT_QUEUE_HEADER, * PGLOBAL_REPORT_QUEUE_HEADER;

VOID QueuePush(
	_In_ PQUEUE_HEAD Head,
	_In_ PVOID Data
);

PVOID QueuePop( 
	_In_ PQUEUE_HEAD Head
);

VOID InitialiseGlobalReportQueue(
	_In_ PBOOLEAN Status
);

VOID InsertReportToQueue(
	_In_ PVOID Report
);

NTSTATUS HandlePeriodicGlobalReportQueueQuery(
	_In_ PIRP Irp
);

VOID FreeGlobalReportQueueObjects();

#endif