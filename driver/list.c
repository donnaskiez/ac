#include "list.h"

#include "imports.h"
#include "driver.h"

/*
 * Simple thread safe linked list implementation. All structures should begin
 * with a SINGLE_LIST_ENTRY structure provided by the windows API. for example:
 *
 *	typedef struct _LIST_ENTRY_STRUCTURE
 *	{
 *		SINGLE_LIST_ENTRY list;
 *		PVOID address;
 *		UINT32 data;
 *		...
 *	};
 *
 * This common structure layout allows us to pass in a callback routine when
 *freeing allowing immense flexibility to ensure we can free and/or deference
 *any objects that are referenced in said object.
 *
 * I've opted to use a mutex rather then a spinlock since there are many times
 *we enumerate the list for extended periods aswell as queue up many insertions
 *at once.
 */

#define LIST_POOL_TAG 'list'

VOID
ListInit(_Inout_ PSINGLE_LIST_ENTRY Head, _Inout_ PKGUARDED_MUTEX Lock)
{
    ImpKeInitializeGuardedMutex(Lock);
    Head->Next = NULL;
}

VOID
ListInsert(_Inout_ PSINGLE_LIST_ENTRY Head,
           _Inout_ PSINGLE_LIST_ENTRY NewEntry,
           _In_ PKGUARDED_MUTEX       Lock)
{
    ImpKeAcquireGuardedMutex(Lock);

    PSINGLE_LIST_ENTRY old_entry = Head->Next;

    Head->Next     = NewEntry;
    NewEntry->Next = old_entry;

    ImpKeReleaseGuardedMutex(Lock);
}

/*
 * Assuming the SINGLE_LIST_ENTRY is the first item in the structure, we
 * can pass a callback routine to be called before the free occurs. This
 * allows us to dereference/free structure specific items whilst still allowing
 * the list to remain flexible.
 */
BOOLEAN
ListFreeFirstEntry(_Inout_ PSINGLE_LIST_ENTRY       Head,
                   _In_ PKGUARDED_MUTEX             Lock,
                   _In_opt_ FREE_LIST_ITEM_CALLBACK CallbackRoutine)
{
    BOOLEAN result = FALSE;
    ImpKeAcquireGuardedMutex(Lock);

    if (Head->Next) {
        PSINGLE_LIST_ENTRY entry = Head->Next;

        if (CallbackRoutine)
            CallbackRoutine(entry);

        Head->Next = Head->Next->Next;
        ImpExFreePoolWithTag(entry, POOL_TAG_THREAD_LIST);
        result = TRUE;
    }

    ImpKeReleaseGuardedMutex(Lock);
    return result;
}

/*
 * If we are removing a specific entry, its assumed we have freed and/or
 * dereferenced any fields in the structure.
 */
VOID
ListRemoveEntry(_Inout_ PSINGLE_LIST_ENTRY Head,
                _Inout_ PSINGLE_LIST_ENTRY Entry,
                _In_ PKGUARDED_MUTEX       Lock)
{
    ImpKeAcquireGuardedMutex(Lock);

    PSINGLE_LIST_ENTRY entry = Head->Next;

    if (!entry)
        goto unlock;

    if (entry == Entry) {
        Head->Next = entry->Next;
        ImpExFreePoolWithTag(Entry, POOL_TAG_THREAD_LIST);
        goto unlock;
    }

    while (entry->Next) {
        if (entry->Next == Entry) {
            entry->Next = Entry->Next;
            ImpExFreePoolWithTag(Entry, POOL_TAG_THREAD_LIST);
            goto unlock;
        }

        entry = entry->Next;
    }

unlock:
    ImpKeReleaseGuardedMutex(Lock);
}

VOID
LookasideListRemoveEntry(_Inout_ PSINGLE_LIST_ENTRY Head,
                         _Inout_ PSINGLE_LIST_ENTRY Entry,
                         _In_ PKGUARDED_MUTEX       Lock)
{
    ImpKeAcquireGuardedMutex(Lock);

    PTHREAD_LIST_HEAD  head  = GetThreadList();
    PSINGLE_LIST_ENTRY entry = Head->Next;

    if (!entry)
        goto unlock;

    if (entry == Entry) {
        Head->Next = entry->Next;
        ExFreeToLookasideListEx(&head->lookaside_list, Entry);
        goto unlock;
    }

    while (entry->Next) {
        if (entry->Next == Entry) {
            entry->Next = Entry->Next;
            ExFreeToLookasideListEx(&head->lookaside_list, Entry);
            goto unlock;
        }

        entry = entry->Next;
    }

unlock:
    ImpKeReleaseGuardedMutex(Lock);
}

BOOLEAN
LookasideListFreeFirstEntry(_Inout_ PSINGLE_LIST_ENTRY       Head,
                            _In_ PKGUARDED_MUTEX             Lock,
                            _In_opt_ FREE_LIST_ITEM_CALLBACK CallbackRoutine)
{
    ImpKeAcquireGuardedMutex(Lock);

    PTHREAD_LIST_HEAD head   = GetThreadList();
    BOOLEAN           result = FALSE;

    if (Head->Next) {
        PSINGLE_LIST_ENTRY entry = Head->Next;

        if (CallbackRoutine)
            CallbackRoutine(entry);

        Head->Next = Head->Next->Next;
        ExFreeToLookasideListEx(&head->lookaside_list, entry);
        result = TRUE;
    }

    ImpKeReleaseGuardedMutex(Lock);
    return result;
}