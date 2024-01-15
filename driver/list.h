#ifndef LIST_H
#define LIST_H

#include "common.h"

typedef void (*FREE_LIST_ITEM_CALLBACK)(_In_ PVOID Entry);

VOID
LookasideListRemoveEntry(_Inout_ PSINGLE_LIST_ENTRY Head,
                         _Inout_ PSINGLE_LIST_ENTRY Entry,
                         _In_ PKGUARDED_MUTEX       Lock);

BOOLEAN
LookasideListFreeFirstEntry(_Inout_ PSINGLE_LIST_ENTRY       Head,
                            _In_ PKGUARDED_MUTEX             Lock,
                            _In_opt_ FREE_LIST_ITEM_CALLBACK CallbackRoutine);

VOID
ListInit(_Inout_ PSINGLE_LIST_ENTRY Head, _Inout_ PKGUARDED_MUTEX Lock);

VOID
ListInsert(_Inout_ PSINGLE_LIST_ENTRY Head,
           _Inout_ PSINGLE_LIST_ENTRY NewEntry,
           _In_ PKGUARDED_MUTEX       Lock);

BOOLEAN
ListFreeFirstEntry(_Inout_ PSINGLE_LIST_ENTRY       Head,
                   _In_ PKGUARDED_MUTEX             Lock,
                   _In_opt_ FREE_LIST_ITEM_CALLBACK CallbackRoutine);

VOID
ListRemoveEntry(_Inout_ PSINGLE_LIST_ENTRY Head,
                _Inout_ PSINGLE_LIST_ENTRY Entry,
                _In_ PKGUARDED_MUTEX       Lock);

#endif