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
QueuePush(_Inout_ PQUEUE_HEAD Head, _In_ PVOID Data)
{
        ImpKeAcquireGuardedMutex(&Head->lock);

        PQUEUE_NODE temp = ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(QUEUE_NODE), QUEUE_POOL_TAG);

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