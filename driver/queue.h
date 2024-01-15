#ifndef QUEUE_H
#define QUEUE_H

#include <ntifs.h>
#include "common.h"

#define MAX_REPORTS_PER_IRP 20

typedef struct QUEUE_HEAD
{
        struct _QUEUE_NODE* start;
        struct _QUEUE_NODE* end;
        KGUARDED_MUTEX      lock;
        INT                 entries;

} QUEUE_HEAD, *PQUEUE_HEAD;

/*
 * This mutex is to prevent a new item being pushed to the queue
 * while the HandlePeriodicCallbackReportQueue is iterating through
 * the objects. This can be an issue because the spinlock is released
 * after each report is placed in the IRP buffer which means a new report
 * can be pushed into the queue before the next iteration can take ownership
 * of the spinlock.
 */
typedef struct _REPORT_QUEUE_HEAD
{
        QUEUE_HEAD       head;
        volatile BOOLEAN is_driver_unloading;
        KGUARDED_MUTEX   lock;

} REPORT_QUEUE_HEAD, *PREPORT_QUEUE_HEAD;

typedef struct _QUEUE_NODE
{
        struct _QUEUE_NODE* next;
        PVOID               data;

} QUEUE_NODE, *PQUEUE_NODE;

typedef struct _GLOBAL_REPORT_QUEUE_HEADER
{
        INT count;

} GLOBAL_REPORT_QUEUE_HEADER, *PGLOBAL_REPORT_QUEUE_HEADER;

typedef struct _REPORT_HEADER
{
        INT report_id;

} REPORT_HEADER, *PREPORT_HEADER;

VOID
QueuePush(_Inout_ PQUEUE_HEAD Head, _In_ PVOID Data);

PVOID
QueuePop(_Inout_ PQUEUE_HEAD Head);

VOID
InitialiseGlobalReportQueue();

VOID
InsertReportToQueue(_In_ PVOID Report);

NTSTATUS
HandlePeriodicGlobalReportQueueQuery(_Out_ PIRP Irp);

NTSTATUS
HandlePeriodicGlobalReportQueueQuery(_Out_ PIRP Irp);

VOID
FreeGlobalReportQueueObjects();

#endif