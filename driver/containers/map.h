#ifndef MAP_H
#define MAP_H

#include "../common.h"

/* To improve efficiency, each entry contains a common header
 * RTL_HASHMAP_ENTRY*, reducing the need to store a seperate pointer to the
 * entrys data. */
typedef struct _RTL_HASHMAP_ENTRY {
    LIST_ENTRY entry;
    UINT32     in_use;
    CHAR       object[];
} RTL_HASHMAP_ENTRY, *PRTL_HASHMAP_ENTRY;

typedef UINT32 (*HASH_FUNCTION)(_In_ UINT64 Key);

/* Struct1 being the node being compared to the value in Struct 2*/
typedef BOOLEAN (*COMPARE_FUNCTION)(_In_ PVOID Struct1, _In_ PVOID Struct2);

typedef struct _RTL_HASHMAP {
    /* Array of RTL_HASHMAP_ENTRIES with length = bucket_count */
    PRTL_HASHMAP_ENTRY buckets;

    /* per bucket locks */
    PKGUARDED_MUTEX locks;

    /* Number of buckets, ideally a prime number */
    UINT32 bucket_count;

    /* Size of each custom object existing after the RTL_HASHMAP_ENTRY */
    UINT32 object_size;

    /* Pointer to caller-designated callback routines */
    HASH_FUNCTION    hash_function;
    COMPARE_FUNCTION compare_function;

    /* in the future bucket entries will use this */
    LOOKASIDE_LIST_EX pool;

    /* user allocated context */
    PVOID           context;
    volatile UINT32 active;

} RTL_HASHMAP, *PRTL_HASHMAP;

typedef VOID (*ENUMERATE_HASHMAP)(_In_ PRTL_HASHMAP_ENTRY Entry,
                                  _In_opt_ PVOID          Context);

#define STATUS_INVALID_HASHMAP_INDEX -1

/* Hashmap is caller allocated */
NTSTATUS
RtlHashmapCreate(_In_ UINT32           BucketCount,
                 _In_ UINT32           EntryObjectSize,
                 _In_ HASH_FUNCTION    HashFunction,
                 _In_ COMPARE_FUNCTION CompareFunction,
                 _In_opt_ PVOID        Context,
                 _Out_ PRTL_HASHMAP    Hashmap);

PVOID
RtlHashmapEntryInsert(_In_ PRTL_HASHMAP Hashmap, _In_ UINT32 Index);

PVOID
RtlHashmapEntryLookup(_In_ PRTL_HASHMAP Hashmap,
                      _In_ UINT32       Index,
                      _In_ PVOID        Compare);

BOOLEAN
RtlHashmapEntryDelete(_Inout_ PRTL_HASHMAP Hashmap,
                      _In_ UINT32          Index,
                      _In_ PVOID           Compare);

VOID
RtlHashmapEnumerate(_In_ PRTL_HASHMAP      Hashmap,
                    _In_ ENUMERATE_HASHMAP EnumerationCallback,
                    _In_opt_ PVOID         Context);

VOID
RtlHashmapDelete(_In_ PRTL_HASHMAP Hashmap);

INT32
RtlHashmapHashKeyAndAcquireBucket(_Inout_ PRTL_HASHMAP Hashmap,
                                  _In_ UINT64          Key);

VOID
RtlHashmapReleaseBucket(_Inout_ PRTL_HASHMAP Hashmap, _In_ UINT32 Index);

VOID
RtlHashmapSetInactive(_Inout_ PRTL_HASHMAP Hashmap);

#endif