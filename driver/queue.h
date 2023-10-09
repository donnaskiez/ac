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

#define LIST_POOL_TAG 'list'

_IRQL_raises_(DISPATCH_LEVEL)
_IRQL_requires_max_(DISPATCH_LEVEL)
_Acquires_lock_(Head->lock)
_Releases_lock_(Head->lock)
VOID
QueuePush(
	_Inout_ PQUEUE_HEAD Head,
	_In_ PVOID Data
);

_IRQL_raises_(DISPATCH_LEVEL)
_IRQL_requires_max_(DISPATCH_LEVEL)
_Acquires_lock_(Head->lock)
_Releases_lock_(Head->lock)
PVOID
QueuePop(
	_Inout_ PQUEUE_HEAD Head
);

VOID
InitialiseGlobalReportQueue(
	_Out_ PBOOLEAN Status
);

_IRQL_raises_(APC_LEVEL)
_Acquires_lock_(&report_queue_config.lock)
_Releases_lock_(&report_queue_config.lock)
_IRQL_restores_global_(irql, GuardedMutex)
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
	_Inout_ PSINGLE_LIST_ENTRY Head,
	_Inout_ PKSPIN_LOCK Lock
);

_IRQL_raises_(DISPATCH_LEVEL)
_Acquires_lock_(Lock)
_Releases_lock_(Lock)
_IRQL_restores_global_(SpinLock, irql)
VOID
ListInsert(
	_Inout_ PSINGLE_LIST_ENTRY Head,
	_Inout_ PSINGLE_LIST_ENTRY NewEntry,
	_In_ PKSPIN_LOCK Lock
);

_IRQL_raises_(DISPATCH_LEVEL)
_Acquires_lock_(Lock)
_Releases_lock_(Lock)
_IRQL_restores_global_(SpinLock, irql)
BOOLEAN
ListFreeFirstEntry(
	_Inout_ PSINGLE_LIST_ENTRY Head,
	_In_ PKSPIN_LOCK Lock
);

_IRQL_raises_(DISPATCH_LEVEL)
_Acquires_lock_(Lock)
_Releases_lock_(Lock)
_IRQL_restores_global_(SpinLock, irql)
VOID
ListRemoveEntry(
	_Inout_ PSINGLE_LIST_ENTRY Head,
	_Inout_ PSINGLE_LIST_ENTRY Entry,
	_In_ PKSPIN_LOCK Lock
);

#endif