#include "map.h"

#include "../lib/stdlib.h"

VOID
RtlHashmapDelete(_In_ PRTL_HASHMAP Hashmap)
{
    ExFreePoolWithTag(Hashmap->buckets, POOL_TAG_HASHMAP);
    ExFreePoolWithTag(Hashmap->locks, POOL_TAG_HASHMAP);
    ExDeleteLookasideListEx(&Hashmap->pool);
}

VOID
RtlHashmapSetInactive(_Inout_ PRTL_HASHMAP Hashmap)
{
    Hashmap->active = FALSE;
}

NTSTATUS
RtlHashmapCreate(
    _In_ UINT32 BucketCount,
    _In_ UINT32 EntryObjectSize,
    _In_ HASH_FUNCTION HashFunction,
    _In_ COMPARE_FUNCTION CompareFunction,
    _In_opt_ PVOID Context,
    _Out_ PRTL_HASHMAP Hashmap)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UINT32 entry_size = sizeof(RTL_HASHMAP_ENTRY) + EntryObjectSize;
    PRTL_HASHMAP_ENTRY entry = NULL;

    if (!CompareFunction || !HashFunction)
        return STATUS_INVALID_PARAMETER;

    Hashmap->buckets = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        BucketCount * entry_size,
        POOL_TAG_HASHMAP);

    if (!Hashmap->buckets)
        return STATUS_INSUFFICIENT_RESOURCES;

    Hashmap->locks = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(KGUARDED_MUTEX) * BucketCount,
        POOL_TAG_HASHMAP);

    if (!Hashmap->locks) {
        ExFreePoolWithTag(Hashmap->buckets, POOL_TAG_HASHMAP);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (UINT32 index = 0; index < BucketCount; index++) {
        entry = &Hashmap->buckets[index];
        entry->in_use = FALSE;
        InitializeListHead(&entry->entry);
        KeInitializeGuardedMutex(&Hashmap->locks[index]);
    }

    status = ExInitializeLookasideListEx(
        &Hashmap->pool,
        NULL,
        NULL,
        NonPagedPoolNx,
        0,
        entry_size,
        POOL_TAG_HASHMAP,
        0);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ExInitializeLookasideListEx: %x", status);
        ExFreePoolWithTag(Hashmap->buckets, POOL_TAG_HASHMAP);
        ExFreePoolWithTag(Hashmap->locks, POOL_TAG_HASHMAP);
        return status;
    }

    Hashmap->bucket_count = BucketCount;
    Hashmap->hash_function = HashFunction;
    Hashmap->compare_function = CompareFunction;
    Hashmap->object_size = EntryObjectSize;
    Hashmap->active = TRUE;
    Hashmap->context = Context;

    return STATUS_SUCCESS;
}

FORCEINLINE
STATIC
PRTL_HASHMAP_ENTRY
RtlpHashmapFindUnusedEntry(_In_ PLIST_ENTRY Head)
{
    PRTL_HASHMAP_ENTRY entry = NULL;
    PLIST_ENTRY list_entry = Head->Flink;

    while (list_entry != Head) {
        entry = CONTAINING_RECORD(list_entry, RTL_HASHMAP_ENTRY, entry);

        if (entry->in_use == FALSE) {
            entry->in_use = TRUE;
            return entry;
        }

        list_entry = list_entry->Flink;
    }

    return NULL;
}

FORCEINLINE
STATIC
PRTL_HASHMAP_ENTRY
RtlpHashmapAllocateBucketEntry(_In_ PRTL_HASHMAP Hashmap)
{
    PRTL_HASHMAP_ENTRY entry = ExAllocateFromLookasideListEx(&Hashmap->pool);

    if (!entry)
        return NULL;

    entry->in_use = TRUE;
    return entry;
}

FORCEINLINE
STATIC
BOOLEAN
RtlpHashmapIsIndexInRange(_In_ PRTL_HASHMAP Hashmap, _In_ UINT32 Index)
{
    return Index < Hashmap->bucket_count ? TRUE : FALSE;
}

INT32
RtlHashmapHashKeyAndAcquireBucket(_Inout_ PRTL_HASHMAP Hashmap, _In_ UINT64 Key)
{
    UINT32 index = Hashmap->hash_function(Key);

    if (!RtlpHashmapIsIndexInRange(Hashmap, index))
        return -1;

    KeAcquireGuardedMutex(&Hashmap->locks[index]);
    return index;
}

VOID
RtlHashmapReleaseBucket(_Inout_ PRTL_HASHMAP Hashmap, _In_ UINT32 Index)
{
    /* No index check here, assuming we exit the caller early if we fail on
     * acquisition */
    KeReleaseGuardedMutex(&Hashmap->locks[Index]);
}

/* assumes map lock is held */
PVOID
RtlHashmapEntryInsert(_In_ PRTL_HASHMAP Hashmap, _In_ UINT32 Index)
{
    UINT32 index = 0;
    PLIST_ENTRY list_head = NULL;
    PRTL_HASHMAP_ENTRY entry = NULL;
    PRTL_HASHMAP_ENTRY new_entry = NULL;

    if (!Hashmap->active)
        return NULL;

    list_head = &(&Hashmap->buckets[index])->entry;
    entry = RtlpHashmapFindUnusedEntry(list_head);

    if (entry)
        return entry;

    new_entry = RtlpHashmapAllocateBucketEntry(Hashmap);

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
RtlHashmapEntryLookup(
    _In_ PRTL_HASHMAP Hashmap, _In_ UINT32 Index, _In_ PVOID Compare)
{
    UINT32 index = 0;
    PRTL_HASHMAP_ENTRY entry = NULL;

    if (!Hashmap->active)
        return NULL;

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
RtlHashmapEntryDelete(
    _Inout_ PRTL_HASHMAP Hashmap, _In_ UINT32 Index, _In_ PVOID Compare)
{
    UINT32 index = 0;
    PLIST_ENTRY list_head = NULL;
    PLIST_ENTRY list_entry = NULL;
    PRTL_HASHMAP_ENTRY entry = NULL;

    if (!Hashmap->active)
        return FALSE;

    list_head = &(&Hashmap->buckets[index])->entry;
    list_entry = list_head->Flink;

    while (list_entry != list_head) {
        entry = CONTAINING_RECORD(list_entry, RTL_HASHMAP_ENTRY, entry);

        if (entry->in_use &&
            Hashmap->compare_function(entry->object, Compare)) {
            if (entry == list_head) {
                entry->in_use = FALSE;
            }
            else {
                RemoveEntryList(&entry->entry);
                ExFreeToLookasideListEx(&Hashmap->pool, entry);
            }

            return TRUE;
        }

        list_entry = list_entry->Flink;
    }

    return FALSE;
}

/* assumes lock is held */
VOID
RtlHashmapEnumerate(
    _In_ PRTL_HASHMAP Hashmap,
    _In_ ENUMERATE_HASHMAP EnumerationCallback,
    _In_opt_ PVOID Context)
{
    PLIST_ENTRY list_head = NULL;
    PLIST_ENTRY list_entry = NULL;
    PRTL_HASHMAP_ENTRY entry = NULL;

    for (UINT32 index = 0; index < Hashmap->bucket_count; index++) {
        KeAcquireGuardedMutex(&Hashmap->locks[index]);

        list_head = &Hashmap->buckets[index];
        list_entry = list_head->Flink;

        while (list_entry != list_head) {
            entry = CONTAINING_RECORD(list_entry, RTL_HASHMAP_ENTRY, entry);

            if (entry->in_use == TRUE)
                EnumerationCallback(entry->object, Context);

            list_entry = list_entry->Flink;
        }

        KeReleaseGuardedMutex(&Hashmap->locks[index]);
    }
}