#ifndef CALLBACKS_H
#define CALLBACKS_H

#include "driver.h"
#include "common.h"

#include <wdf.h>

typedef void (*THREADLIST_CALLBACK_ROUTINE)(
    _In_ PTHREAD_LIST_ENTRY ThreadListEntry, _In_opt_ PVOID Context);

#define DRIVER_PATH_LENGTH  0x100
#define SHA_256_HASH_LENGTH 32

typedef struct _DRIVER_LIST_ENTRY {
    LIST_ENTRY list_entry;
    PVOID      ImageBase;
    ULONG      ImageSize;
    BOOLEAN    hashed;
    BOOLEAN    x86;
    CHAR       path[DRIVER_PATH_LENGTH];
    CHAR       text_hash[SHA_256_HASH_LENGTH];

    /*
     * This LIST_ENTRY is to be used for modules where the hashing needs to
     * be deferred. For example, when x86 modules can't be hashed on driver
     * load.
     */
    LIST_ENTRY deferred_entry;

} DRIVER_LIST_ENTRY, *PDRIVER_LIST_ENTRY;

typedef void (*DRIVERLIST_CALLBACK_ROUTINE)(
    _In_ PDRIVER_LIST_ENTRY DriverListEntry, _In_opt_ PVOID Context);

typedef BOOLEAN (*PROCESS_MODULE_CALLBACK)(_In_ PPROCESS_MAP_MODULE_ENTRY Entry,
                                           _In_opt_ PVOID Context);

NTSTATUS
InitialiseDriverList();

VOID NTAPI
ExUnlockHandleTableEntry(IN PHANDLE_TABLE       HandleTable,
                         IN PHANDLE_TABLE_ENTRY HandleTableEntry);

VOID
ObPostOpCallbackRoutine(_In_ PVOID RegistrationContext,
                        _In_ POB_POST_OPERATION_INFORMATION
                            OperationInformation);

OB_PREOP_CALLBACK_STATUS
ObPreOpCallbackRoutine(_In_ PVOID                         RegistrationContext,
                       _In_ POB_PRE_OPERATION_INFORMATION OperationInformation);

NTSTATUS
InitialiseThreadList();

VOID
ThreadCreateNotifyRoutine(_In_ HANDLE  ProcessId,
                          _In_ HANDLE  ThreadId,
                          _In_ BOOLEAN Create);

VOID
ProcessCreateNotifyRoutine(_In_ HANDLE  ParentId,
                           _In_ HANDLE  ProcessId,
                           _In_ BOOLEAN Create);

VOID
CleanupThreadListOnDriverUnload();

VOID
FindThreadListEntryByThreadAddress(_In_ HANDLE               ThreadId,
                                   _Out_ PTHREAD_LIST_ENTRY* Entry);

VOID
FindDriverEntryByBaseAddress(_In_ PVOID                ImageBase,
                             _Out_ PDRIVER_LIST_ENTRY* Entry);

VOID
CleanupDriverListOnDriverUnload();

VOID
ImageLoadNotifyRoutineCallback(_In_opt_ PUNICODE_STRING FullImageName,
                               _In_ HANDLE              ProcessId,
                               _In_ PIMAGE_INFO         ImageInfo);

NTSTATUS
InitialiseTimerObject(_Out_ PTIMER_OBJECT Timer);

VOID
CleanupDriverTimerObjects(_Inout_ PTIMER_OBJECT Timer);

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
InitialiseObCallbacksConfiguration(_Out_ PACTIVE_SESSION ProcessConfig);

VOID
EnumerateDriverListWithCallbackRoutine(
    _In_ DRIVERLIST_CALLBACK_ROUTINE CallbackRoutine, _In_opt_ PVOID Context);

VOID
DriverListEntryToExtendedModuleInfo(_In_ PDRIVER_LIST_ENTRY         Entry,
                                    _Out_ PRTL_MODULE_EXTENDED_INFO Extended);

NTSTATUS
InitialiseProcessHashmap();

NTSTATUS
EnumerateProcessHandles(_In_ PPROCESS_LIST_ENTRY Entry, _In_opt_ PVOID Context);

VOID
EnumerateAndPrintProcessHashmap();

VOID
CleanupProcessHashmap();

VOID
EnumerateProcessModuleList(_In_ HANDLE                  ProcessId,
                           _In_ PROCESS_MODULE_CALLBACK Callback,
                           _In_opt_ PVOID               Context);

VOID
FindOurUserModeModuleEntry(_In_ PROCESS_MODULE_CALLBACK Callback,
                           _In_opt_ PVOID               Context);

#endif
