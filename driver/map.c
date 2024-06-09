#include "map.h"

NTSTATUS
RtlCreateHashmap(_In_ UINT32           BucketCount,
                 _In_ UINT32           EntryObjectSize,
                 _In_ HASH_FUNCTION    HashFunction,
                 _In_ COMPARE_FUNCTION CompareFunction,
                 _In_ PVOID            Context,
                 _Out_ PRTL_HASHMAP    Hashmap)
{
    NTSTATUS           status     = STATUS_UNSUCCESSFUL;
    UINT32             entry_size = sizeof(RTL_HASHMAP_ENTRY) + EntryObjectSize;
    PRTL_HASHMAP_ENTRY entry      = NULL;

    Hashmap->buckets = ExAllocatePool2(
        POOL_FLAG_NON_PAGED, BucketCount * entry_size, POOL_TAG_HASHMAP);

    if (!Hashmap->buckets)
        return STATUS_INSUFFICIENT_RESOURCES;

    for (UINT32 index = 0; index < BucketCount; index++) {
        entry         = &Hashmap->buckets[index];
        entry->in_use = FALSE;
        InitializeListHead(&entry->entry);
    }

    KeInitializeGuardedMutex(&Hashmap->lock);

    Hashmap->bucket_count     = BucketCount;
    Hashmap->hash_function    = HashFunction;
    Hashmap->compare_function = CompareFunction;
    Hashmap->object_size      = EntryObjectSize;
    Hashmap->active           = TRUE;
    Hashmap->context          = Context;

    return STATUS_SUCCESS;
}

FORCEINLINE
STATIC
PRTL_HASHMAP_ENTRY
RtlFindUnusedHashmapEntry(_In_ PRTL_HASHMAP_ENTRY Head)
{
    PRTL_HASHMAP_ENTRY entry = Head;

    while (entry) {
        if (entry->in_use == FALSE)
            return entry;

        entry = CONTAINING_RECORD(entry->entry.Flink, RTL_HASHMAP_ENTRY, entry);
    }

    return NULL;
}

FORCEINLINE
STATIC
PRTL_HASHMAP_ENTRY
RtlAllocateBucketListEntry(_In_ PRTL_HASHMAP Hashmap)
{
    PRTL_HASHMAP_ENTRY entry =
        ExAllocatePool2(POOL_FLAG_NON_PAGED,
                        Hashmap->object_size + sizeof(RTL_HASHMAP_ENTRY),
                        POOL_TAG_HASHMAP);

    if (!entry)
        return NULL;

    entry->in_use = TRUE;
    return entry;
}

FORCEINLINE
STATIC
BOOLEAN
RtlIsIndexInHashmapRange(_In_ PRTL_HASHMAP Hashmap, _In_ UINT32 Index)
{
    return Index < Hashmap->bucket_count ? TRUE : FALSE;
}

/* assumes map lock is held */
PVOID
RtlInsertEntryHashmap(_In_ PRTL_HASHMAP Hashmap, _In_ UINT64 Key)
{
    UINT32             index      = 0;
    PLIST_ENTRY        list_head  = NULL;
    PLIST_ENTRY        list_entry = NULL;
    PRTL_HASHMAP_ENTRY entry      = NULL;
    PRTL_HASHMAP_ENTRY new_entry  = NULL;

    index = Hashmap->hash_function(Key);

    if (!RtlIsIndexInHashmapRange(Hashmap, index)) {
        DEBUG_ERROR("Key is not in range of buckets");
        return NULL;
    }

    list_head  = &(&Hashmap->buckets[index])->entry;
    list_entry = list_head->Flink;

    while (list_entry != list_head) {
        entry = CONTAINING_RECORD(list_entry, RTL_HASHMAP_ENTRY, entry);

        if (entry->in_use == FALSE) {
            entry->in_use = TRUE;
            return entry->object;
        }

        list_entry = list_entry->Flink;
    }

    new_entry = RtlAllocateBucketListEntry(Hashmap);

    if (!new_entry) {
        DEBUG_ERROR("Failed to allocate new entry");
        return NULL;
    }

    InsertHeadList(list_head, &new_entry->entry);
    return new_entry->object;
}

/* Returns a pointer to the start of the entries caller defined data. i.e
 * &PRTL_HASHMAP_ENTRY->Object
 *
 * Also assumes lock is held.
 */
PVOID
RtlLookupEntryHashmap(_In_ PRTL_HASHMAP Hashmap,
                      _In_ UINT64       Key,
                      _In_ PVOID        Compare)
{
    UINT32             index = 0;
    PRTL_HASHMAP_ENTRY entry = NULL;

    index = Hashmap->hash_function(Key);

    if (!RtlIsIndexInHashmapRange(Hashmap, index)) {
        DEBUG_ERROR("Key is not in range of buckets");
        return NULL;
    }

    entry = &Hashmap->buckets[index];

    while (entry) {
        if (entry->in_use == FALSE)
            goto increment;

        if (Hashmap->compare_function(entry->object, Compare))
            return entry->object;

    increment:
        entry = CONTAINING_RECORD(entry->entry.Flink, RTL_HASHMAP_ENTRY, entry);
    }

    DEBUG_ERROR("Unable to find entry in hashmap.");
    return NULL;
}

/* Assumes lock is held */
BOOLEAN
RtlDeleteEntryHashmap(_In_ PRTL_HASHMAP Hashmap,
                      _In_ UINT64       Key,
                      _In_ PVOID        Compare)
{
    UINT32             index = 0;
    PRTL_HASHMAP_ENTRY entry = NULL;
    PRTL_HASHMAP_ENTRY next  = NULL;

    index = Hashmap->hash_function(Key);

    if (!RtlIsIndexInHashmapRange(Hashmap, index)) {
        DEBUG_ERROR("Key is not in range of buckets");
        return FALSE;
    }

    entry = &Hashmap->buckets[index];

    while (entry) {
        if (entry->in_use == FALSE) {
            next =
                CONTAINING_RECORD(entry->entry.Flink, RTL_HASHMAP_ENTRY, entry);

            if (next == &Hashmap->buckets[index])
                break;

            entry = next;
            continue;
        }

        if (Hashmap->compare_function(entry->object, Compare)) {
            if (entry == &Hashmap->buckets[index]) {
                entry->in_use = FALSE;
            }
            else {
                RemoveEntryList(&entry->entry);
                ExFreePoolWithTag(entry, POOL_TAG_HASHMAP);
            }

            return TRUE;
        }

        next = CONTAINING_RECORD(entry->entry.Flink, RTL_HASHMAP_ENTRY, entry);

        if (next == &Hashmap->buckets[index])
            break;

        entry = next;
    }

    return FALSE;
}

VOID
RtlEnumerateHashmap(_In_ PRTL_HASHMAP      Hashmap,
                    _In_ ENUMERATE_HASHMAP EnumerationCallback,
                    _In_opt_ PVOID         Context)
{
    PRTL_HASHMAP_ENTRY entry = NULL;

    for (UINT32 index = 0; index < Hashmap->bucket_count; index++) {
        PLIST_ENTRY list_head  = &Hashmap->buckets[index];
        PLIST_ENTRY list_entry = list_head->Flink;

        while (list_entry != list_head) {
            entry = CONTAINING_RECORD(list_entry, RTL_HASHMAP_ENTRY, entry);

            if (entry->in_use == TRUE) {
                EnumerationCallback(entry->object, Context);
            }

            list_entry = list_entry->Flink;
        }
    }
}

VOID
RtlDeleteHashmap(_In_ PRTL_HASHMAP Hashmap)
{
    ExFreePoolWithTag(Hashmap->buckets, POOL_TAG_HASHMAP);
}