#include "apc.h"

#include "driver.h"
#include "imports.h"

VOID
GetApcContextByIndex(_Out_ PVOID* Context, _In_ INT Index)
{
    AcquireDriverConfigLock();
    *Context = GetApcContextArray()[Index];
    ReleaseDriverConfigLock();
}

VOID
GetApcContext(_Out_ PVOID* Context, _In_ LONG ContextIdentifier)
{
    AcquireDriverConfigLock();

    for (INT index = 0; index < MAXIMUM_APC_CONTEXTS; index++) {
        PAPC_CONTEXT_HEADER header = GetApcContextArray()[index];

        if (!header)
            continue;

        if (header->context_id != ContextIdentifier)
            continue;

        *Context = header;
        goto unlock;
    }
unlock:
    ReleaseDriverConfigLock();
}

/*
 * No need to hold the lock here as the thread freeing the APCs will
 * already hold the configuration lock. We also dont want to release and
 * reclaim the lock before calling this function since we need to ensure
 * we hold the lock during the entire decrement and free process.
 */
BOOLEAN
FreeApcContextStructure(_Out_ PAPC_CONTEXT_HEADER Context)
{
    DEBUG_VERBOSE("All APCs executed, freeing context structure");

    for (INT index = 0; index < MAXIMUM_APC_CONTEXTS; index++) {
        PUINT64 entry = GetApcContextArray();

        if (entry[index] != Context)
            continue;

        if (Context->count > 0)
            return FALSE;

        ImpExFreePoolWithTag(Context, POOL_TAG_APC);
        entry[index] = NULL;
        return TRUE;
    }

    return FALSE;
}

VOID
IncrementApcCount(_In_ LONG ContextId)
{
    PAPC_CONTEXT_HEADER header = NULL;
    GetApcContext(&header, ContextId);

    if (!header)
        return;

    /* i actually dont think we need this lock here */
    AcquireDriverConfigLock();
    header->count += 1;
    ReleaseDriverConfigLock();
}

VOID
FreeApcAndDecrementApcCount(_Inout_ PRKAPC Apc, _In_ LONG ContextId)
{
    PAPC_CONTEXT_HEADER context = NULL;

    ImpExFreePoolWithTag(Apc, POOL_TAG_APC);
    GetApcContext(&context, ContextId);

    if (!context)
        return;

    AcquireDriverConfigLock();
    context->count -= 1;
    ReleaseDriverConfigLock();
}

/*
 * The reason we use a query model rather then checking the count of queued APCs
 * after each APC free and decrement is that the lock will be recursively
 * acquired by freeing threads (i.e executing APCs) rather then APC allocation
 * threads. The reason for this being that freeing threads are executing at a
 * higher IRQL then the APC allocation thread, hence they are granted higher
 * priority by the scheduler when determining which thread will accquire the
 * lock next:
 *
 * [+] Freeing thread -> ApcKernelRoutine IRQL: 1 (APC_LEVEL)
 * [+] Allocation thread -> ValidateThreadViaKernelApcCallback IRQL: 0
 * (PASSIVE_LEVEL)
 *
 * As a result, once an APC is executed and reaches the freeing stage, it will
 * acquire the lock and decrement it. Then, if atleast 1 APC execution thread is
 * waiting on the lock, it will be prioritised due to its higher IRQL and the
 * cycle will continue. Eventually, the count will reach 0 due to recursive
 * acquisition by the executing APC threads and then the function will free the
 * APC context structure. This will then cause a bug check the next time a
 * thread accesses the context structure and hence not good :c.
 *
 * So to combat this, we add in a flag specifying whether or not an allocation
 * of APCs is in progress, and even if the count is 0 we will not free the
 * context structure until the count is 0 and allocation_in_progress is 0. We
 * can then call this function alongside other query callbacks via IOCTL to
 * constantly monitor the status of open APC contexts.
 */
NTSTATUS
QueryActiveApcContextsForCompletion()
{
  AcquireDriverConfigLock();

    for (INT index = 0; index < MAXIMUM_APC_CONTEXTS; index++) {
        PAPC_CONTEXT_HEADER entry = NULL;
        GetApcContextByIndex(&entry, index);

        if (!entry)
          continue;

        if (entry->count > 0 || entry->allocation_in_progress == TRUE)
          continue;

        switch (entry->context_id) {
        case APC_CONTEXT_ID_STACKWALK:
            FreeApcStackwalkApcContextInformation(entry);
            FreeApcContextStructure(entry);
            break;
        }
    }

    ReleaseDriverConfigLock();
    return STATUS_SUCCESS;
}

VOID
InsertApcContext(_In_ PVOID Context)
{
    if (IsDriverUnloading())
        return STATUS_UNSUCCESSFUL;

    AcquireDriverConfigLock();
    PAPC_CONTEXT_HEADER header = Context;

    for (INT index = 0; index < MAXIMUM_APC_CONTEXTS; index++) {
        PUINT64 entry = GetApcContextArray();

        if (entry[index] == NULL) {
            entry[index] = Context;
            goto end;
        }
    }
end:
    ReleaseDriverConfigLock();
}

/*
 * The driver config structure holds an array of pointers to APC context
 * structures. These APC context structures are unique to each APC operation
 * that this driver will perform. For example, a single context will manage all
 * APCs that are used to stackwalk, whilst another context will be used to
 * manage all APCs used to query a threads memory for example.
 *
 * Due to the nature of APCs, its important to keep a total or count of the
 * number of APCs we have allocated and queued to threads. This information is
 * stored in the APC_CONTEXT_HEADER which all APC context structures will
 * contain as the first entry in their structure. It holds the ContextId which
 * is a unique identifier for the type of APC operation it is managing aswell as
 * the number of currently queued APCs.
 *
 * When an APC is allocated a queued, we increment this count. When an APC is
 * completed and freed, we decrement this counter and free the APC itself. If
 * all APCs have been freed and the counter is 0,the following objects will be
 * freed:
 *
 * 1. Any additional allocations used by the APC stored in the context structure
 * 2. The APC context structure for the given APC operation
 * 3. The APC context entry in g_DriverConfig->>apc_contexts will be zero'd.
 *
 * It's important to remember that the driver can unload when pending APC's have
 * not been freed due to the limitations windows places on APCs, however I am in
 * the process of finding a solution for this.
 */
BOOLEAN
DrvUnloadFreeAllApcContextStructures()
{
    AcquireDriverConfigLock();

    for (INT index = 0; index < MAXIMUM_APC_CONTEXTS; index++) {
        PUINT64 entry = GetApcContextArray();

        if (entry[index] == NULL)
            continue;

        PAPC_CONTEXT_HEADER context = entry[index];

        if (context->count > 0) {
            ReleaseDriverConfigLock();
            return FALSE;
        }

        ImpExFreePoolWithTag(context, POOL_TAG_APC);
    }
unlock:
    ReleaseDriverConfigLock();
    return TRUE;
}