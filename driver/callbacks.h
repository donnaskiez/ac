#ifndef CALLBACKS_H
#define CALLBACKS_H

#include "driver.h"
#include "common.h"

#include <wdf.h>

typedef void (*THREADLIST_CALLBACK_ROUTINE)(_In_ PTHREAD_LIST_ENTRY ThreadListEntry,
                                            _In_opt_ PVOID          Context);

typedef void (*PROCESSLIST_CALLBACK_ROUTINE)(_In_ PPROCESS_LIST_ENTRY ProcessListEntry,
                                             _In_opt_ PVOID           Context);

#define DRIVER_PATH_LENGTH  0x100
#define SHA_256_HASH_LENGTH 32

typedef struct _DRIVER_LIST_ENTRY
{
        SINGLE_LIST_ENTRY list;
        PVOID             ImageBase;
        ULONG             ImageSize;
        BOOLEAN           hashed;
        CHAR              path[DRIVER_PATH_LENGTH];
        CHAR              text_hash[SHA_256_HASH_LENGTH];

} DRIVER_LIST_ENTRY, *PDRIVER_LIST_ENTRY;

NTSTATUS
InitialiseDriverList();

VOID NTAPI
ExUnlockHandleTableEntry(IN PHANDLE_TABLE HandleTable, IN PHANDLE_TABLE_ENTRY HandleTableEntry);

VOID
ObPostOpCallbackRoutine(_In_ PVOID                          RegistrationContext,
                        _In_ POB_POST_OPERATION_INFORMATION OperationInformation);

OB_PREOP_CALLBACK_STATUS
ObPreOpCallbackRoutine(_In_ PVOID                         RegistrationContext,
                       _In_ POB_PRE_OPERATION_INFORMATION OperationInformation);

NTSTATUS
EnumerateProcessHandles(_In_ PPROCESS_LIST_ENTRY ProcessListEntry, _In_opt_ PVOID Context);

NTSTATUS
InitialiseThreadList();

NTSTATUS
InitialiseProcessList();

VOID
ThreadCreateNotifyRoutine(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create);

VOID
ProcessCreateNotifyRoutine(_In_ HANDLE ParentId, _In_ HANDLE ProcessId, _In_ BOOLEAN Create);

VOID
CleanupThreadListOnDriverUnload();

VOID
FindThreadListEntryByThreadAddress(_In_ PKTHREAD Thread, _Inout_ PTHREAD_LIST_ENTRY* Entry);

VOID
FindProcessListEntryByProcess(_In_ PKPROCESS Process, _Inout_ PPROCESS_LIST_ENTRY* Entry);

VOID
EnumerateThreadListWithCallbackRoutine(_In_ THREADLIST_CALLBACK_ROUTINE CallbackRoutine,
                                       _In_opt_ PVOID                   Context);

VOID
EnumerateProcessListWithCallbackRoutine(_In_ PROCESSLIST_CALLBACK_ROUTINE CallbackRoutine,
                                        _In_opt_ PVOID                   Context);

VOID
FindDriverEntryByBaseAddress(_In_ PVOID ImageBase, _Out_ PDRIVER_LIST_ENTRY* Entry);

VOID
CleanupProcessListOnDriverUnload();

VOID
CleanupDriverListOnDriverUnload();

VOID
ImageLoadNotifyRoutineCallback(_In_opt_ PUNICODE_STRING FullImageName,
                               _In_ HANDLE              ProcessId,
                               _In_ PIMAGE_INFO         ImageInfo);

NTSTATUS
InitialiseTimerObject(_Out_ PTIMER_OBJECT Timer);

VOID
CleanupDriverTimerObjects(_Out_ PTIMER_OBJECT Timer);

VOID
UnregisterProcessCreateNotifyRoutine();

VOID
UnregisterImageLoadNotifyRoutine();

VOID
UnregisterThreadCreateNotifyRoutine();

VOID
UnregisterProcessObCallbacks();

NTSTATUS
RegisterProcessObCallbacks();

VOID
InitialiseObCallbacksConfiguration(_Out_ PPROCESS_CONFIG ProcessConfig);

#endif
