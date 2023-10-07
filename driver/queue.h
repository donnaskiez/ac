#ifndef QUEUE_H
#define QUEUE_H

#include <ntifs.h>
#include "common.h"

#define MAX_REPORTS_PER_IRP 20

typedef struct _QUEUE_NODE
{
	struct _QUEUE_NODE* next;
	PVOID data;

}QUEUE_NODE, * PQUEUE_NODE;

typedef struct QUEUE_HEAD
{
	struct _QUEUE_NODE* start;
	struct _QUEUE_NODE* end;
	KSPIN_LOCK lock;
	INT entries;

}QUEUE_HEAD, * PQUEUE_HEAD;

typedef struct _GLOBAL_REPORT_QUEUE_HEADER
{
	INT count;

}GLOBAL_REPORT_QUEUE_HEADER, * PGLOBAL_REPORT_QUEUE_HEADER;

typedef struct _REPORT_HEADER
{
	INT report_id;

}REPORT_HEADER, * PREPORT_HEADER;

typedef struct _LIST_ITEM
{
	struct _LIST_ITEM* next;

}LIST_ITEM, * PLIST_ITEM;

typedef struct _LIST_HEAD
{
	PLIST_ITEM start;
	KSPIN_LOCK lock;

}LIST_HEAD, * PLIST_HEAD;

#define LIST_POOL_TAG 'list'

VOID
QueuePush(
	_Inout_ PQUEUE_HEAD Head,
	_In_ PVOID Data
);

PVOID
QueuePop(
	_Inout_ PQUEUE_HEAD Head
);

VOID
InitialiseGlobalReportQueue(
	_Out_ PBOOLEAN Status
);

VOID
InsertReportToQueue(
	_In_ PVOID Report
);

NTSTATUS
HandlePeriodicGlobalReportQueueQuery(
	_Inout_ PIRP Irp
);

VOID
FreeGlobalReportQueueObjects();

VOID
ListInit(
	_Inout_ PLIST_HEAD ListHead
);

PLIST_ITEM
ListInsert(
	_Inout_ PLIST_HEAD ListHead,
	_Inout_ PLIST_ITEM Data
);

PVOID
ListRemoveFirst(
	_Inout_ PLIST_HEAD ListHead
);

PVOID
ListRemoveItem(
	_Inout_ PLIST_HEAD ListHead,
	_Inout_ PLIST_ITEM ListItem
);

#endif