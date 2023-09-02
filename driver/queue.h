#ifndef QUEUE_H
#define QUEUE_H

#include <ntifs.h>
#include "common.h"

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

typedef struct _REPORT_HEADER
{
	INT report_id;

}REPORT_HEADER, * PREPORT_HEADER;

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