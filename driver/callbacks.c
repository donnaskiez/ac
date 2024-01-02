#include "callbacks.h"

#include "driver.h"

#include "queue.h"
#include "pool.h"
#include "thread.h"

/*
 * Interlocked intrinsics are only atomic with respect to other InterlockedXxx functions,
 * so all reads and writes to the THREAD_LIST->active flag must be with Interlocked instrinsics
 * to ensure atomicity.
 */
typedef struct _THREAD_LIST
{
        SINGLE_LIST_ENTRY start;
        volatile BOOLEAN  active;
        KGUARDED_MUTEX    lock;

} THREAD_LIST, *PTHREAD_LIST;

/* todo: maybe put this in the global config? hmm.. I kinda like how its encapsulated here tho hm..
 */
PTHREAD_LIST thread_list = NULL;

typedef struct _PROCESS_LIST
{
        SINGLE_LIST_ENTRY start;
        volatile BOOLEAN  active;
        KGUARDED_MUTEX    lock;

} PROCESS_LIST, *PPROCESS_LIST;

PPROCESS_LIST process_list = NULL;

STATIC
BOOLEAN
EnumHandleCallback(_In_ PHANDLE_TABLE       HandleTable,
                   _In_ PHANDLE_TABLE_ENTRY Entry,
                   _In_ HANDLE              Handle,
                   _In_ PVOID               Context);

#ifdef ALLOC_PRAGMA
#        pragma alloc_text(PAGE, ObPostOpCallbackRoutine)
#        pragma alloc_text(PAGE, ObPreOpCallbackRoutine)
#        pragma alloc_text(PAGE, EnumHandleCallback)
#        pragma alloc_text(PAGE, EnumerateProcessHandles)
#        pragma alloc_text(PAGE, InitialiseThreadList)
#        pragma alloc_text(PAGE, ExUnlockHandleTableEntry)
#endif

/*
 * Its important on unload we dereference any objects to ensure the kernels reference
 * count remains correct.
 */
VOID
CleanupProcessListFreeCallback(_In_ PPROCESS_LIST_ENTRY ProcessListEntry)
{
        ObDereferenceObject(ProcessListEntry->parent);
        ObDereferenceObject(ProcessListEntry->process);
}

VOID
CleanupThreadListFreeCallback(_In_ PTHREAD_LIST_ENTRY ThreadListEntry)
{
        ObDereferenceObject(ThreadListEntry->thread);
        ObDereferenceObject(ThreadListEntry->owning_process);
}

VOID
CleanupProcessListOnDriverUnload()
{
        InterlockedExchange(&process_list->active, FALSE);
        PsSetCreateProcessNotifyRoutine(ProcessCreateNotifyRoutine, TRUE);

        for (;;)
        {
                if (!ListFreeFirstEntry(
                        &process_list->start, &process_list->lock, CleanupProcessListFreeCallback))
                {
                        ExFreePoolWithTag(process_list, POOL_TAG_THREAD_LIST);
                        return;
                }
        }
}

VOID
CleanupThreadListOnDriverUnload()
{
        InterlockedExchange(&thread_list->active, FALSE);
        PsRemoveCreateThreadNotifyRoutine(ThreadCreateNotifyRoutine);

        for (;;)
        {
                if (!ListFreeFirstEntry(
                        &thread_list->start, &thread_list->lock, CleanupThreadListFreeCallback))
                {
                        ExFreePoolWithTag(thread_list, POOL_TAG_THREAD_LIST);
                        return;
                }
        }
}

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
VOID
EnumerateThreadListWithCallbackRoutine(_In_ PVOID CallbackRoutine, _In_opt_ PVOID Context)
{
        KeAcquireGuardedMutex(&thread_list->lock);

        if (!CallbackRoutine)
                goto unlock;

        PTHREAD_LIST_ENTRY entry = thread_list->start.Next;

        while (entry)
        {
                VOID (*callback_function_ptr)(PTHREAD_LIST_ENTRY, PVOID) = CallbackRoutine;
                (*callback_function_ptr)(entry, Context);
                entry = entry->list.Next;
        }

unlock:
        KeReleaseGuardedMutex(&thread_list->lock);
}

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
VOID
EnumerateProcessListWithCallbackRoutine(_In_ PVOID CallbackRoutine, _In_opt_ PVOID Context)
{
        KeAcquireGuardedMutex(&process_list->lock);

        if (!CallbackRoutine)
                goto unlock;

        PPROCESS_LIST_ENTRY entry = process_list->start.Next;

        while (entry)
        {
                VOID (*callback_function_ptr)(PPROCESS_LIST_ENTRY, PVOID) = CallbackRoutine;
                (*callback_function_ptr)(entry, Context);
                entry = entry->list.Next;
        }

unlock:
        KeReleaseGuardedMutex(&process_list->lock);
}

NTSTATUS
InitialiseProcessList()
{
        PAGED_CODE();

        process_list =
            ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PROCESS_LIST), POOL_TAG_THREAD_LIST);

        if (!process_list)
                return STATUS_MEMORY_NOT_ALLOCATED;

        InterlockedExchange(&process_list->active, TRUE);
        ListInit(&process_list->start, &process_list->lock);

        return STATUS_SUCCESS;
}

NTSTATUS
InitialiseThreadList()
{
        PAGED_CODE();

        thread_list =
            ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(THREAD_LIST), POOL_TAG_THREAD_LIST);

        if (!thread_list)
                return STATUS_MEMORY_NOT_ALLOCATED;

        InterlockedExchange(&thread_list->active, TRUE);
        ListInit(&thread_list->start, &thread_list->lock);

        return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
VOID
FindProcessListEntryByProcess(_In_ PKPROCESS Process, _Inout_ PPROCESS_LIST_ENTRY* Entry)
{
        *Entry = NULL;
        KeAcquireGuardedMutex(&process_list->lock);

        PPROCESS_LIST_ENTRY entry = (PPROCESS_LIST_ENTRY)process_list->start.Next;

        while (entry)
        {
                if (entry->process == Process)
                {
                        *Entry = entry;
                        goto unlock;
                }

                entry = entry->list.Next;
        }
unlock:
        KeReleaseGuardedMutex(&process_list->lock);
}

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
VOID
FindThreadListEntryByThreadAddress(_In_ PKTHREAD Thread, _Inout_ PTHREAD_LIST_ENTRY* Entry)
{
        *Entry = NULL;
        KeAcquireGuardedMutex(&thread_list->lock);

        PTHREAD_LIST_ENTRY entry = (PTHREAD_LIST_ENTRY)thread_list->start.Next;

        while (entry)
        {
                if (entry->thread == Thread)
                {
                        *Entry = entry;
                        goto unlock;
                }

                entry = entry->list.Next;
        }
unlock:
        KeReleaseGuardedMutex(&thread_list->lock);
}

VOID
ProcessCreateNotifyRoutine(_In_ HANDLE ParentId, _In_ HANDLE ProcessId, _In_ BOOLEAN Create)
{
        PPROCESS_LIST_ENTRY entry   = NULL;
        PKPROCESS           parent  = NULL;
        PKPROCESS           process = NULL;

        if (InterlockedExchange(&process_list->active, process_list->active) == FALSE)
                return;

        PsLookupProcessByProcessId(ParentId, &parent);
        PsLookupProcessByProcessId(ProcessId, &process);

        if (!parent || !process)
                return;

        if (Create)
        {
                entry = ExAllocatePool2(
                    POOL_FLAG_NON_PAGED, sizeof(PROCESS_LIST_ENTRY), POOL_TAG_THREAD_LIST);

                if (!entry)
                        return;

                ObReferenceObject(parent);
                ObReferenceObject(process);

                entry->parent  = parent;
                entry->process = process;

                ListInsert(&process_list->start, entry, &process_list->lock);
        }
        else
        {
                FindProcessListEntryByProcess(process, &entry);

                if (!entry)
                        return;

                ObDereferenceObject(entry->parent);
                ObDereferenceObject(entry->process);

                ListRemoveEntry(&process_list->start, entry, &process_list->lock);
        }
}

VOID
ThreadCreateNotifyRoutine(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create)
{
        PTHREAD_LIST_ENTRY entry   = NULL;
        PKTHREAD           thread  = NULL;
        PKPROCESS          process = NULL;

        /* ensure we don't insert new entries if we are unloading */
        if (InterlockedExchange(&thread_list->active, thread_list->active) == FALSE)
                return;

        PsLookupThreadByThreadId(ThreadId, &thread);
        PsLookupProcessByProcessId(ProcessId, &process);

        if (!thread || !process)
                return;

        if (Create)
        {
                entry = ExAllocatePool2(
                    POOL_FLAG_NON_PAGED, sizeof(THREAD_LIST_ENTRY), POOL_TAG_THREAD_LIST);

                if (!entry)
                        return;

                ObReferenceObject(thread);
                ObReferenceObject(process);

                entry->thread         = thread;
                entry->owning_process = process;
                entry->apc            = NULL;
                entry->apc_queued     = FALSE;

                ListInsert(&thread_list->start, &entry->list, &thread_list->lock);
        }
        else
        {
                FindThreadListEntryByThreadAddress(thread, &entry);

                if (!entry)
                        return;

                ObDereferenceObject(entry->thread);
                ObDereferenceObject(entry->owning_process);

                ListRemoveEntry(&thread_list->start, entry, &thread_list->lock);
        }
}

VOID
ObPostOpCallbackRoutine(_In_ PVOID                          RegistrationContext,
                        _In_ POB_POST_OPERATION_INFORMATION OperationInformation)
{
        PAGED_CODE();

        UNREFERENCED_PARAMETER(RegistrationContext);
        UNREFERENCED_PARAMETER(OperationInformation);
}

_IRQL_requires_max_(APC_LEVEL)
_Acquires_lock_(_Lock_kind_mutex_)
_Releases_lock_(_Lock_kind_mutex_)
OB_PREOP_CALLBACK_STATUS
ObPreOpCallbackRoutine(_In_ PVOID                         RegistrationContext,
                       _In_ POB_PRE_OPERATION_INFORMATION OperationInformation)
{
        PAGED_CODE();

        UNREFERENCED_PARAMETER(RegistrationContext);

        /* access mask to completely strip permissions */
        ACCESS_MASK deny_access = SYNCHRONIZE | PROCESS_TERMINATE;

        /*
         * This callback routine is executed in the context of the thread that
         * is requesting to open said handle
         */
        PEPROCESS            process_creator        = PsGetCurrentProcess();
        PEPROCESS            protected_process      = NULL;
        PEPROCESS            target_process         = (PEPROCESS)OperationInformation->Object;
        HANDLE               process_creator_id     = PsGetProcessId(process_creator);
        LONG                 protected_process_id   = 0;
        LPCSTR               process_creator_name   = NULL;
        LPCSTR               target_process_name    = NULL;
        LPCSTR               protected_process_name = NULL;
        POB_CALLBACKS_CONFIG configuration          = NULL;

        /*
         * This is to prevent the condition where the thread executing this function is scheduled
         * whilst we are cleaning up the callbacks on driver unload. We must hold the driver config
         * lock to ensure the pool containing the callback configuration lock is not freed
         */
        GetCallbackConfigStructure(&configuration);

        if (!configuration)
                return OB_PREOP_SUCCESS;

        KeAcquireGuardedMutex(&configuration->lock);
        GetProtectedProcessId(&protected_process_id);
        GetProtectedProcessEProcess(&protected_process);

        if (!protected_process_id || !protected_process)
                goto end;

        process_creator_name   = PsGetProcessImageFileName(process_creator);
        target_process_name    = PsGetProcessImageFileName(target_process);
        protected_process_name = PsGetProcessImageFileName(protected_process);

        if (!protected_process_name || !target_process_name)
                goto end;

        if (!strcmp(protected_process_name, target_process_name))
        {
                /*
                 * WerFault is some windows 11 application that cries when it cant get a handle,
                 * so well allow it for now... todo; learn more about it
                 */
                if (!strcmp(process_creator_name, "lsass.exe") ||
                    !strcmp(process_creator_name, "csrss.exe") ||
                    !strcmp(process_creator_name, "WerFault.exe"))
                {
                        /* We will downgrade these handles later */
                        // DEBUG_LOG("Handles created by CSRSS, LSASS and WerFault are allowed for
                        // now...");
                }
                else if (target_process == process_creator)
                {
                        // DEBUG_LOG("handles made by NOTEPAD r okay :)");
                        /* handles created by the game (notepad) are okay */
                }
                else
                {
                        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess =
                            deny_access;
                        OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess =
                            deny_access;

                        /*
                         * These processes will constantly open handles to any open process for
                         * various reasons, so we will still strip them but we won't report them..
                         * for now atleast.
                         */

                        if (!strcmp(process_creator_name, "Discord.exe") ||
                            !strcmp(process_creator_name, "svchost.exe") ||
                            !strcmp(process_creator_name, "explorer.exe"))
                                goto end;

                        // DEBUG_LOG("handle stripped from: %s", process_creator_name);

                        POPEN_HANDLE_FAILURE_REPORT report =
                            ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                            sizeof(OPEN_HANDLE_FAILURE_REPORT),
                                            REPORT_POOL_TAG);

                        if (!report)
                                goto end;

                        report->report_code      = REPORT_ILLEGAL_HANDLE_OPERATION;
                        report->is_kernel_handle = OperationInformation->KernelHandle;
                        report->process_id       = process_creator_id;
                        report->thread_id        = PsGetCurrentThreadId();
                        report->access =
                            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;

                        RtlCopyMemory(report->process_name,
                                      process_creator_name,
                                      HANDLE_REPORT_PROCESS_NAME_MAX_LENGTH);

                        InsertReportToQueue(report);
                }
        }

end:

        KeReleaseGuardedMutex(&configuration->lock);
        return OB_PREOP_SUCCESS;
}

/* stolen from ReactOS xD */
VOID NTAPI
ExUnlockHandleTableEntry(IN PHANDLE_TABLE HandleTable, IN PHANDLE_TABLE_ENTRY HandleTableEntry)
{
        INT64 old_value;
        PAGED_CODE();

        /* Set the lock bit and make sure it wasn't earlier */
        old_value = InterlockedOr((PLONG)&HandleTableEntry->VolatileLowValue, 1);

        /* Unblock any waiters */
        ExfUnblockPushLock(&HandleTable->HandleContentionEvent, NULL);
}

STATIC
BOOLEAN
EnumHandleCallback(_In_ PHANDLE_TABLE       HandleTable,
                   _In_ PHANDLE_TABLE_ENTRY Entry,
                   _In_ HANDLE              Handle,
                   _In_ PVOID               Context)
{
        PAGED_CODE();

        PVOID        object                 = NULL;
        PVOID        object_header          = NULL;
        POBJECT_TYPE object_type            = NULL;
        PEPROCESS    process                = NULL;
        PEPROCESS    protected_process      = NULL;
        LPCSTR       process_name           = NULL;
        LPCSTR       protected_process_name = NULL;
        ACCESS_MASK  handle_access_mask     = 0;

        object_header = GET_OBJECT_HEADER_FROM_HANDLE(Entry->ObjectPointerBits);

        /* Object header is the first 30 bytes of the object */
        object = (uintptr_t)object_header + OBJECT_HEADER_SIZE;

        object_type = ObGetObjectType(object);

        /* TODO: check for threads aswell */
        if (!RtlCompareUnicodeString(&object_type->Name, &OBJECT_TYPE_PROCESS, TRUE))
        {
                process      = (PEPROCESS)object;
                process_name = PsGetProcessImageFileName(process);

                GetProtectedProcessEProcess(&protected_process);

                protected_process_name = PsGetProcessImageFileName(protected_process);

                if (strcmp(process_name, protected_process_name))
                        goto end;

                DEBUG_VERBOSE("Handle references our protected process with access mask: %lx",
                              (ACCESS_MASK)Entry->GrantedAccessBits);

                handle_access_mask = (ACCESS_MASK)Entry->GrantedAccessBits;

                /* These permissions can be stripped from every process including CSRSS and LSASS */
                if (handle_access_mask & PROCESS_CREATE_PROCESS)
                {
                        Entry->GrantedAccessBits &= ~PROCESS_CREATE_PROCESS;
                        DEBUG_VERBOSE("Stripped PROCESS_CREATE_PROCESS");
                }

                if (handle_access_mask & PROCESS_CREATE_THREAD)
                {
                        Entry->GrantedAccessBits &= ~PROCESS_CREATE_THREAD;
                        DEBUG_VERBOSE("Stripped PROCESS_CREATE_THREAD");
                }

                if (handle_access_mask & PROCESS_DUP_HANDLE)
                {
                        Entry->GrantedAccessBits &= ~PROCESS_DUP_HANDLE;
                        DEBUG_VERBOSE("Stripped PROCESS_DUP_HANDLE");
                }

                if (handle_access_mask & PROCESS_QUERY_INFORMATION)
                {
                        Entry->GrantedAccessBits &= ~PROCESS_QUERY_INFORMATION;
                        DEBUG_VERBOSE("Stripped PROCESS_QUERY_INFORMATION");
                }

                if (handle_access_mask & PROCESS_QUERY_LIMITED_INFORMATION)
                {
                        Entry->GrantedAccessBits &= ~PROCESS_QUERY_LIMITED_INFORMATION;
                        DEBUG_VERBOSE("Stripped PROCESS_QUERY_LIMITED_INFORMATION");
                }

                if (handle_access_mask & PROCESS_VM_READ)
                {
                        Entry->GrantedAccessBits &= ~PROCESS_VM_READ;
                        DEBUG_VERBOSE("Stripped PROCESS_VM_READ");
                }

                if (!strcmp(process_name, "csrss.exe") || !strcmp(process_name, "lsass.exe"))
                {
                        DEBUG_VERBOSE(
                            "Required system process allowed, only stripping some permissions");
                        goto end;
                }

                /* Permissions beyond here can only be stripped from non critical processes */
                if (handle_access_mask & PROCESS_SET_INFORMATION)
                {
                        Entry->GrantedAccessBits &= ~PROCESS_SET_INFORMATION;
                        DEBUG_VERBOSE("Stripped PROCESS_SET_INFORMATION");
                }

                if (handle_access_mask & PROCESS_SET_QUOTA)
                {
                        Entry->GrantedAccessBits &= ~PROCESS_SET_QUOTA;
                        DEBUG_VERBOSE("Stripped PROCESS_SET_QUOTA");
                }

                if (handle_access_mask & PROCESS_SUSPEND_RESUME)
                {
                        Entry->GrantedAccessBits &= ~PROCESS_SUSPEND_RESUME;
                        DEBUG_VERBOSE("Stripped PROCESS_SUSPEND_RESUME ");
                }

                if (handle_access_mask & PROCESS_TERMINATE)
                {
                        Entry->GrantedAccessBits &= ~PROCESS_TERMINATE;
                        DEBUG_VERBOSE("Stripped PROCESS_TERMINATE");
                }

                if (handle_access_mask & PROCESS_VM_OPERATION)
                {
                        Entry->GrantedAccessBits &= ~PROCESS_VM_OPERATION;
                        DEBUG_VERBOSE("Stripped PROCESS_VM_OPERATION");
                }

                if (handle_access_mask & PROCESS_VM_WRITE)
                {
                        Entry->GrantedAccessBits &= ~PROCESS_VM_WRITE;
                        DEBUG_VERBOSE("Stripped PROCESS_VM_WRITE");
                }

                POPEN_HANDLE_FAILURE_REPORT report = ExAllocatePool2(
                    POOL_FLAG_NON_PAGED, sizeof(OPEN_HANDLE_FAILURE_REPORT), REPORT_POOL_TAG);

                if (!report)
                        goto end;

                /*
                 * Using the same report structure as the ObRegisterCallbacks report
                 * since both of these reports are closely related by the fact they are
                 * triggered by a process either opening a handle to our protected process
                 * or have a valid open handle to it. I also don't think its worth creating
                 * another queue specifically for open handle reports since they will be
                 * rare.
                 */
                report->report_code      = REPORT_ILLEGAL_HANDLE_OPERATION;
                report->is_kernel_handle = 0;
                report->process_id       = PsGetProcessId(process);
                report->thread_id        = 0;
                report->access           = handle_access_mask;

                RtlCopyMemory(
                    &report->process_name, process_name, HANDLE_REPORT_PROCESS_NAME_MAX_LENGTH);

                InsertReportToQueue(report);
        }

end:
        ExUnlockHandleTableEntry(HandleTable, Entry);
        return FALSE;
}

NTSTATUS
EnumerateProcessHandles(_In_ PPROCESS_LIST_ENTRY ProcessListEntry, _In_opt_ PVOID Context)
{
        /* Handles are stored in paged memory */
        PAGED_CODE();

        UNREFERENCED_PARAMETER(Context);

        if (!ProcessListEntry)
                return STATUS_INVALID_PARAMETER;

        if (ProcessListEntry->process == PsInitialSystemProcess)
                return STATUS_SUCCESS;

        PHANDLE_TABLE handle_table =
            *(PHANDLE_TABLE*)((uintptr_t)ProcessListEntry->process + EPROCESS_HANDLE_TABLE_OFFSET);

        if (!handle_table)
                return STATUS_INVALID_ADDRESS;

        if (!MmIsAddressValid(handle_table))
                return STATUS_INVALID_ADDRESS;

#pragma warning(push)
#pragma warning(suppress : 6387)

        BOOLEAN result = ExEnumHandleTable(handle_table, EnumHandleCallback, NULL, NULL);

#pragma warning(pop)

        return STATUS_SUCCESS;
}