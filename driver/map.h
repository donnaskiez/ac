#ifndef MAP_H
#define MAP_H

#include "common.h"

typedef UINT32 (*HASH_FUNCTION)(_In_ UINT64 Key);

/* Struct1 being the node being compared to the value in Struct 2*/
typedef BOOLEAN (*COMPARE_FUNCTION)(_In_ PVOID Struct1, _In_ PVOID Struct2);

/* To improve efficiency, each entry contains a common header
 * RTL_HASHMAP_ENTRY*, reducing the need to store a seperate pointer to the
 * entrys data. */
typedef struct _RTL_HASHMAP_ENTRY {
    LIST_ENTRY entry;
    UINT32     in_use;
    CHAR       object[];
} RTL_HASHMAP_ENTRY, *PRTL_HASHMAP_ENTRY;

typedef VOID (*ENUMERATE_HASHMAP)(_In_ PRTL_HASHMAP_ENTRY Entry,
                                  _In_opt_ PVOID          Context);

typedef struct _RTL_HASHMAP {
    /* Array of RTL_HASHMAP_ENTRIES with length = bucket_count */
    PRTL_HASHMAP_ENTRY buckets;

    /* Number of buckets, ideally a prime number */
    UINT32 bucket_count;

    /* Size of each custom object existing after the RTL_HASHMAP_ENTRY */
    UINT32 object_size;

    /* Pointer to caller-designated callback routines */
    HASH_FUNCTION    hash_function;
    COMPARE_FUNCTION compare_function;

    KGUARDED_MUTEX    lock;

    /* in the future bucket entries will use this */
    LOOKASIDE_LIST_EX pool;

    /* user allocated context */
    PVOID context;
    volatile UINT32   active;

} RTL_HASHMAP, *PRTL_HASHMAP;

/* Hashmap is caller allocated */
NTSTATUS
RtlCreateHashmap(_In_ UINT32           BucketCount,
                 _In_ UINT32           EntryObjectSize,
                 _In_ HASH_FUNCTION    HashFunction,
                 _In_ COMPARE_FUNCTION CompareFunction,
                 _In_ PVOID            Context,
                 _Out_ PRTL_HASHMAP    Hashmap);

PVOID
RtlInsertEntryHashmap(_In_ PRTL_HASHMAP Hashmap, _In_ UINT64 Key);

PVOID
RtlLookupEntryHashmap(_In_ PRTL_HASHMAP Hashmap,
                      _In_ UINT64       Key,
                      _In_ PVOID        Compare);

BOOLEAN
RtlDeleteEntryHashmap(_In_ PRTL_HASHMAP Hashmap,
                      _In_ UINT64       Key,
                      _In_ PVOID        Compare);

VOID
RtlEnumerateHashmap(_In_ PRTL_HASHMAP      Hashmap,
                    _In_ ENUMERATE_HASHMAP EnumerationCallback,
                    _In_opt_ PVOID         Context);

VOID
RtlDeleteHashmap(_In_ PRTL_HASHMAP Hashmap);

#endif