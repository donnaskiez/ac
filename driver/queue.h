#ifndef QUEUE_H
#define QUEUE_H

#include <ntifs.h>

#define QUEUE_POOL_TAG 'qqqq'

typedef struct _QUEUE_NODE
{
	struct _QUEUE_NODE* next;
	PKSPIN_LOCK lock;
	PVOID data;

}QUEUE_NODE, *PQUEUE_NODE;

typedef struct QUEUE_HEAD
{
	struct _QUEUE_NODE* start;
	struct _QUEUE_NODE* end;
	PKSPIN_LOCK lock;

}QUEUE_HEAD, *PQUEUE_HEAD;

PQUEUE_NODE QueueCreate();

VOID QueuePush(
	_In_ PQUEUE_HEAD Head,
	_In_ PVOID Data
);

PVOID QueuePop( 
	_In_ PQUEUE_HEAD Head
);



#endif