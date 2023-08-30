#include "queue.h"

#include "common.h"

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
