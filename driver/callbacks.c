#include "callbacks.h"

#include "driver.h"

#include "queue.h"
#include "pool.h"
#include "thread.h"
#include "modules.h"
#include "imports.h"
#include "list.h"
#include "session.h"

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
        ImpObDereferenceObject(ProcessListEntry->parent);
        ImpObDereferenceObject(ProcessListEntry->process);
}

VOID
CleanupThreadListFreeCallback(_In_ PTHREAD_LIST_ENTRY ThreadListEntry)
{
        ImpObDereferenceObject(ThreadListEntry->thread);
        ImpObDereferenceObject(ThreadListEntry->owning_process);
}

VOID
UnregisterProcessCreateNotifyRoutine()
{
        PPROCESS_LIST_HEAD list = GetProcessList();
        InterlockedExchange(&list->active, FALSE);
        ImpPsSetCreateProcessNotifyRoutine(ProcessCreateNotifyRoutine, TRUE);
}

VOID
UnregisterImageLoadNotifyRoutine()
{
        PDRIVER_LIST_HEAD list = GetDriverList();
        InterlockedExchange(&list->active, FALSE);
        PsRemoveLoadImageNotifyRoutine(ImageLoadNotifyRoutineCallback);
}

VOID
UnregisterThreadCreateNotifyRoutine()
{
        PTHREAD_LIST_HEAD list = GetThreadList();
        InterlockedExchange(&list->active, FALSE);
        ImpPsRemoveCreateThreadNotifyRoutine(ThreadCreateNotifyRoutine);
}

/*
 * While ExDeleteLookasideListEx already frees each item, we wanna allow ourselves to reduce the
 * reference count to any objects we are referencing.
 */
VOID
CleanupProcessListOnDriverUnload()
{
        PPROCESS_LIST_HEAD list = GetProcessList();
        DEBUG_VERBOSE("Freeing process list");
        for (;;)
        {
                if (!LookasideListFreeFirstEntry(
                        &list->start, &list->lock, CleanupProcessListFreeCallback))
                {
                        ExDeleteLookasideListEx(&list->lookaside_list);
                        return;
                }
        }
}

VOID
CleanupThreadListOnDriverUnload()
{
        PTHREAD_LIST_HEAD list = GetThreadList();
        DEBUG_VERBOSE("Freeing thread list!");
        for (;;)
        {
                if (!LookasideListFreeFirstEntry(
                        &list->start, &list->lock, CleanupThreadListFreeCallback))
                {
                        ExDeleteLookasideListEx(&list->lookaside_list);
                        return;
                }
        }
}

VOID
CleanupDriverListOnDriverUnload()
{
        PDRIVER_LIST_HEAD list = GetDriverList();
        for (;;)
        {
                if (!ListFreeFirstEntry(&list->start, &list->lock, NULL))
                        return;
        }
}

VOID
EnumerateThreadListWithCallbackRoutine(_In_ THREADLIST_CALLBACK_ROUTINE CallbackRoutine,
                                       _In_opt_ PVOID                   Context)
{
        PTHREAD_LIST_HEAD list = GetThreadList();
        ImpKeAcquireGuardedMutex(&list->lock);

        if (!CallbackRoutine)
                goto unlock;

        PTHREAD_LIST_ENTRY entry = list->start.Next;

        while (entry)
        {
                CallbackRoutine(entry, Context);
                entry = entry->list.Next;
        }

unlock:
        ImpKeReleaseGuardedMutex(&list->lock);
}

VOID
EnumerateProcessListWithCallbackRoutine(_In_ PROCESSLIST_CALLBACK_ROUTINE CallbackRoutine,
                                        _In_opt_ PVOID                    Context)
{
        PPROCESS_LIST_HEAD list = GetProcessList();
        ImpKeAcquireGuardedMutex(&list->lock);

        if (!CallbackRoutine)
                goto unlock;

        PPROCESS_LIST_ENTRY entry = list->start.Next;

        while (entry)
        {
                CallbackRoutine(entry, Context);
                entry = entry->list.Next;
        }

unlock:
        ImpKeReleaseGuardedMutex(&list->lock);
}

VOID
EnumerateDriverListWithCallbackRoutine(_In_ DRIVERLIST_CALLBACK_ROUTINE CallbackRoutine,
                                       _In_opt_ PVOID                   Context)
{
        PDRIVER_LIST_HEAD list = GetDriverList();
        ImpKeAcquireGuardedMutex(&list->lock);

        if (!CallbackRoutine)
                goto unlock;

        PDRIVER_LIST_ENTRY entry = list->start.Next;

        while (entry)
        {
                CallbackRoutine(entry, Context);
                entry = entry->list.Next;
        }

unlock:
        ImpKeReleaseGuardedMutex(&list->lock);
}

VOID
DriverListEntryToExtendedModuleInfo(_In_ PDRIVER_LIST_ENTRY         Entry,
                                    _Out_ PRTL_MODULE_EXTENDED_INFO Extended)
{
        Extended->ImageBase = Entry->ImageBase;
        Extended->ImageSize = Entry->ImageSize;
        RtlCopyMemory(Extended->FullPathName, Entry->path, sizeof(Extended->FullPathName));
}

NTSTATUS
InitialiseDriverList()
{
        PAGED_CODE();

        NTSTATUS                  status       = STATUS_UNSUCCESSFUL;
        SYSTEM_MODULES            modules      = {0};
        PDRIVER_LIST_ENTRY        entry        = NULL;
        PRTL_MODULE_EXTENDED_INFO module_entry = NULL;
        PDRIVER_LIST_HEAD         list         = GetDriverList();

        InterlockedExchange(&list->active, TRUE);
        ListInit(&list->start, &list->lock);
        InitializeListHead(&list->deferred_list);

        list->can_hash_x86       = FALSE;
        list->deferred_work_item = IoAllocateWorkItem(GetDriverDeviceObject());

        if (!list->deferred_work_item)
                return STATUS_INSUFFICIENT_RESOURCES;

        status = GetSystemModuleInformation(&modules);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("GetSystemModuleInformation failed with status %x", status);
                return status;
        }

        /* skip hal.dll and ntoskrnl.exe */
        for (INT index = 2; index < modules.module_count; index++)
        {
                entry = ImpExAllocatePool2(
                    POOL_FLAG_NON_PAGED, sizeof(DRIVER_LIST_ENTRY), POOL_TAG_DRIVER_LIST);

                if (!entry)
                        continue;

                module_entry = &((PRTL_MODULE_EXTENDED_INFO)modules.address)[index];

                entry->hashed    = TRUE;
                entry->ImageBase = module_entry->ImageBase;
                entry->ImageSize = module_entry->ImageSize;

                RtlCopyMemory(
                    entry->path, module_entry->FullPathName, sizeof(module_entry->FullPathName));

                status = HashModule(module_entry, entry->text_hash);

                if (status == STATUS_INVALID_IMAGE_WIN_32)
                {
                        DEBUG_ERROR("32 bit module not hashed, will hash later. %x", status);
                        entry->hashed = FALSE;
                        entry->x86    = TRUE;
                        InsertHeadList(&list->deferred_list, &entry->deferred_entry);
                }
                else if (!NT_SUCCESS(status))
                {
                        DEBUG_ERROR("HashModule failed with status %x", status);
                        entry->hashed = FALSE;
                }

                ListInsert(&list->start, entry, &list->lock);
        }

        list->active = TRUE;

end:
        if (modules.address)
                ImpExFreePoolWithTag(modules.address, SYSTEM_MODULES_POOL);

        return STATUS_SUCCESS;
}

/*
 * I actually think a spinlock here for the driver list is what we want rather then a mutex, but
 * implementing a spinlock has its challenges... todo: have a think!
 */
VOID
FindDriverEntryByBaseAddress(_In_ PVOID ImageBase, _Out_ PDRIVER_LIST_ENTRY* Entry)
{
        PDRIVER_LIST_HEAD list = GetDriverList();
        ImpKeAcquireGuardedMutex(&list->lock);
        *Entry = NULL;

        PDRIVER_LIST_ENTRY entry = (PDRIVER_LIST_ENTRY)list->start.Next;

        while (entry)
        {
                if (entry->ImageBase == ImageBase)
                {
                        *Entry = entry;
                        goto unlock;
                }

                entry = entry->list.Next;
        }
unlock:
        ImpKeReleaseGuardedMutex(&list->lock);
}

VOID
ImageLoadNotifyRoutineCallback(_In_opt_ PUNICODE_STRING FullImageName,
                               _In_ HANDLE              ProcessId,
                               _In_ PIMAGE_INFO         ImageInfo)
{
        NTSTATUS                 status             = STATUS_UNSUCCESSFUL;
        PDRIVER_LIST_ENTRY       entry              = NULL;
        RTL_MODULE_EXTENDED_INFO module             = {0};
        PDRIVER_LIST_HEAD        list               = GetDriverList();
        ANSI_STRING              ansi_path          = {0};
        UINT32                   ansi_string_length = 0;

        if (InterlockedExchange(&list->active, list->active) == FALSE)
                return;

        if (ImageInfo->SystemModeImage == FALSE)
                return;

        FindDriverEntryByBaseAddress(ImageInfo->ImageBase, &entry);

        if (entry)
                return;

        entry =
            ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(DRIVER_LIST_ENTRY), POOL_TAG_DRIVER_LIST);

        if (!entry)
                return;

        entry->hashed    = TRUE;
        entry->x86       = FALSE;
        entry->ImageBase = ImageInfo->ImageBase;
        entry->ImageSize = ImageInfo->ImageSize;

        module.ImageBase = ImageInfo->ImageBase;
        module.ImageSize = ImageInfo->ImageSize;

        if (FullImageName)
        {
                status = RtlUnicodeStringToAnsiString(&ansi_path, FullImageName, TRUE);

                if (!NT_SUCCESS(status))
                {
                        DEBUG_ERROR("RtlUnicodeStringToAnsiString failed with status %x", status);
                        goto hash;
                }

                if (ansi_path.Length > sizeof(module.FullPathName))
                {
                        RtlFreeAnsiString(&ansi_path);
                        goto hash;
                }

                RtlCopyMemory(module.FullPathName, ansi_path.Buffer, ansi_path.Length);
                RtlCopyMemory(entry->path, ansi_path.Buffer, ansi_path.Length);

                RtlFreeAnsiString(&ansi_path);
        }

        DEBUG_VERBOSE("New system image ansi: %s", entry->path);

hash:
        status = HashModule(&module, &entry->text_hash);

        if (status == STATUS_INVALID_IMAGE_WIN_32)
        {
                DEBUG_ERROR("32 bit module not hashed, will hash later. %x", status);
                entry->x86    = TRUE;
                entry->hashed = FALSE;
        }
        else if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("HashModule failed with status %x", status);
                entry->hashed = FALSE;
        }

        ListInsert(&list->start, entry, &list->lock);
}

NTSTATUS
InitialiseProcessList()
{
        NTSTATUS           status = STATUS_UNSUCCESSFUL;
        PPROCESS_LIST_HEAD list   = GetProcessList();

        status = ExInitializeLookasideListEx(&list->lookaside_list,
                                             NULL,
                                             NULL,
                                             POOL_NX_ALLOCATION,
                                             0,
                                             sizeof(PROCESS_LIST_ENTRY),
                                             POOL_TAG_PROCESS_LIST,
                                             0);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ExInitializeLookasideListEx failed with status %x", status);
                return status;
        }

        InterlockedExchange(&list->active, TRUE);
        ListInit(&list->start, &list->lock);
        return status;
}

NTSTATUS
InitialiseThreadList()
{
        NTSTATUS          status = STATUS_UNSUCCESSFUL;
        PTHREAD_LIST_HEAD list   = GetThreadList();

        status = ExInitializeLookasideListEx(&list->lookaside_list,
                                             NULL,
                                             NULL,
                                             POOL_NX_ALLOCATION,
                                             0,
                                             sizeof(THREAD_LIST_ENTRY),
                                             POOL_TAG_PROCESS_LIST,
                                             0);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ExInitializeLookasideListEx failed with status %x", status);
                return status;
        }

        InterlockedExchange(&list->active, TRUE);
        ListInit(&list->start, &list->lock);
        return status;
}

VOID
FindProcessListEntryByProcess(_In_ PKPROCESS Process, _Out_ PPROCESS_LIST_ENTRY* Entry)
{
        PPROCESS_LIST_HEAD list = GetProcessList();
        ImpKeAcquireGuardedMutex(&list->lock);
        *Entry = NULL;

        PPROCESS_LIST_ENTRY entry = (PPROCESS_LIST_ENTRY)list->start.Next;

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
        ImpKeReleaseGuardedMutex(&list->lock);
}

VOID
FindThreadListEntryByThreadAddress(_In_ PKTHREAD Thread, _Out_ PTHREAD_LIST_ENTRY* Entry)
{
        PTHREAD_LIST_HEAD list = GetThreadList();
        ImpKeAcquireGuardedMutex(&list->lock);
        *Entry = NULL;

        PTHREAD_LIST_ENTRY entry = (PTHREAD_LIST_ENTRY)list->start.Next;

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
        ImpKeReleaseGuardedMutex(&list->lock);
}

VOID
ProcessCreateNotifyRoutine(_In_ HANDLE ParentId, _In_ HANDLE ProcessId, _In_ BOOLEAN Create)
{
        PPROCESS_LIST_ENTRY entry        = NULL;
        PKPROCESS           parent       = NULL;
        PKPROCESS           process      = NULL;
        PPROCESS_LIST_HEAD  list         = GetProcessList();
        PDRIVER_LIST_HEAD   driver_list  = GetDriverList();
        LPCSTR              process_name = NULL;

        if (!list->active)
                return;

        ImpPsLookupProcessByProcessId(ParentId, &parent);
        ImpPsLookupProcessByProcessId(ProcessId, &process);

        if (!parent || !process)
                return;

        process_name = ImpPsGetProcessImageFileName(process);

        if (Create)
        {
                entry = ExAllocateFromLookasideListEx(&list->lookaside_list);

                if (!entry)
                        return;

                ImpObfReferenceObject(parent);
                ImpObfReferenceObject(process);

                entry->parent  = parent;
                entry->process = process;

                ListInsert(&list->start, entry, &list->lock);

                /*
                 * Notify to our driver that we can hash x86 modules, and hash any x86 modules that
                 * werent hashed.
                 */
                if (!strcmp(process_name, "winlogon.exe"))
                {
                        DEBUG_VERBOSE("Winlogon process has started");
                        driver_list->can_hash_x86 = TRUE;
                        IoQueueWorkItem(driver_list->deferred_work_item,
                                        DeferredModuleHashingCallback,
                                        NormalWorkQueue,
                                        NULL);
                }
        }
        else
        {
                FindProcessListEntryByProcess(process, &entry);

                if (!entry)
                        return;

                ImpObDereferenceObject(entry->parent);
                ImpObDereferenceObject(entry->process);

                LookasideListRemoveEntry(&list->start, entry, &list->lock);
        }
}

VOID
ThreadCreateNotifyRoutine(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create)
{
        PTHREAD_LIST_ENTRY entry   = NULL;
        PKTHREAD           thread  = NULL;
        PKPROCESS          process = NULL;
        PTHREAD_LIST_HEAD  list    = GetThreadList();

        /* ensure we don't insert new entries if we are unloading */
        if (!list->active)
                return;

        ImpPsLookupThreadByThreadId(ThreadId, &thread);
        ImpPsLookupProcessByProcessId(ProcessId, &process);

        if (!thread || !process)
                return;

        if (Create)
        {
                entry = ExAllocateFromLookasideListEx(&list->lookaside_list);

                if (!entry)
                        return;

                ImpObfReferenceObject(thread);
                ImpObfReferenceObject(process);

                entry->thread         = thread;
                entry->owning_process = process;
                entry->apc            = NULL;
                entry->apc_queued     = FALSE;

                ListInsert(&list->start, &entry->list, &list->lock);
        }
        else
        {
                FindThreadListEntryByThreadAddress(thread, &entry);

                if (!entry)
                        return;

                ImpObDereferenceObject(entry->thread);
                ImpObDereferenceObject(entry->owning_process);

                LookasideListRemoveEntry(&list->start, entry, &list->lock);
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

// https://www.sysnative.com/forums/threads/object-headers-handles-and-types.34987/
#define GET_OBJECT_HEADER_FROM_HANDLE(x) ((x << 4) | 0xffff000000000000);

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
        HANDLE               process_creator_id     = ImpPsGetProcessId(process_creator);
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
        SessionGetCallbackConfiguration(&configuration);

        if (!configuration)
                return OB_PREOP_SUCCESS;

        ImpKeAcquireGuardedMutex(&configuration->lock);
        SessionGetProcessId(&protected_process_id);
        SessionGetProcess(&protected_process);

        if (!protected_process_id || !protected_process)
                goto end;

        process_creator_name   = ImpPsGetProcessImageFileName(process_creator);
        target_process_name    = ImpPsGetProcessImageFileName(target_process);
        protected_process_name = ImpPsGetProcessImageFileName(protected_process);

        if (!protected_process_name || !target_process_name)
                goto end;

        if (!strcmp(protected_process_name, target_process_name))
        {
                /*
                 * WerFault is some windows 11 application that cries when it cant get a handle,
                 * so well allow it for now... todo; learn more about it
                 *
                 * todo: perform stricter checks rather then the image name. perhapds check some
                 * certificate or something.
                 */
                if (!strcmp(process_creator_name, "lsass.exe") ||
                    !strcmp(process_creator_name, "csrss.exe") ||
                    !strcmp(process_creator_name, "WerFault.exe") ||
                    !strcmp(process_creator_name, "MsMpEng.exe") ||
                    !strcmp(process_creator_name, target_process_name))
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

                        // POPEN_HANDLE_FAILURE_REPORT report =
                        //     ImpExAllocatePool2(POOL_FLAG_NON_PAGED,
                        //                        sizeof(OPEN_HANDLE_FAILURE_REPORT),
                        //                        REPORT_POOL_TAG);

                        // if (!report)
                        //         goto end;

                        // report->report_code      = REPORT_ILLEGAL_HANDLE_OPERATION;
                        // report->is_kernel_handle = OperationInformation->KernelHandle;
                        // report->process_id       = process_creator_id;
                        // report->thread_id        = ImpPsGetCurrentThreadId();
                        // report->access =
                        //     OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;

                        // RtlCopyMemory(report->process_name,
                        //               process_creator_name,
                        //               HANDLE_REPORT_PROCESS_NAME_MAX_LENGTH);

                        // if (!NT_SUCCESS(
                        //         IrpQueueCompleteIrp(report, sizeof(OPEN_HANDLE_FAILURE_REPORT))))
                        //{
                        //         DEBUG_ERROR("IrpQueueCompleteIrp failed with no status.");
                        //         goto end;
                        // }
                }
        }

end:

        ImpKeReleaseGuardedMutex(&configuration->lock);
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
        ImpExfUnblockPushLock(&HandleTable->HandleContentionEvent, NULL);
}

static UNICODE_STRING OBJECT_TYPE_PROCESS = RTL_CONSTANT_STRING(L"Process");
static UNICODE_STRING OBJECT_TYPE_THREAD  = RTL_CONSTANT_STRING(L"Thread");

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

        object_type = ImpObGetObjectType(object);

        /* TODO: check for threads aswell */
        if (!ImpRtlCompareUnicodeString(&object_type->Name, &OBJECT_TYPE_PROCESS, TRUE))
        {
                process      = (PEPROCESS)object;
                process_name = ImpPsGetProcessImageFileName(process);

                SessionGetProcess(&protected_process);

                protected_process_name = ImpPsGetProcessImageFileName(protected_process);

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

                POPEN_HANDLE_FAILURE_REPORT report = ImpExAllocatePool2(
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
                report->process_id       = ImpPsGetProcessId(process);
                report->thread_id        = 0;
                report->access           = handle_access_mask;

                RtlCopyMemory(
                    &report->process_name, process_name, HANDLE_REPORT_PROCESS_NAME_MAX_LENGTH);

                if (!NT_SUCCESS(IrpQueueCompleteIrp(report, sizeof(OPEN_HANDLE_FAILURE_REPORT))))
                {
                        DEBUG_ERROR("IrpQueueCompleteIrp failed with no status.");
                        goto end;
                }
        }

end:
        ExUnlockHandleTableEntry(HandleTable, Entry);
        return FALSE;
}

NTSTATUS
EnumerateProcessHandles(_In_ PPROCESS_LIST_ENTRY ProcessListEntry, _In_opt_ PVOID Context)
{
        /* Handles are stored in pageable memory */
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

        if (!ImpMmIsAddressValid(handle_table))
                return STATUS_INVALID_ADDRESS;

#pragma warning(push)
#pragma warning(suppress : 6387)

        BOOLEAN result = ImpExEnumHandleTable(handle_table, EnumHandleCallback, NULL, NULL);

#pragma warning(pop)

        return STATUS_SUCCESS;
}

#define REPEAT_TIME_10_SEC 10000

ULONG value = 10;

VOID
TimerObjectWorkItemRoutine(_In_ PDEVICE_OBJECT DeviceObject, _In_opt_ PVOID Context)
{
        NTSTATUS          status = STATUS_UNSUCCESSFUL;
        PTIMER_OBJECT     timer  = (PTIMER_OBJECT)Context;
        PDRIVER_LIST_HEAD list   = GetDriverList();

        if (!list->active)
                goto end;

        DEBUG_VERBOSE("Integrity check timer callback invoked.");

        if (!ValidateOurDriversDispatchRoutines())
        {
                DEBUG_VERBOSE("l");
        }

        status = ValidateOurDriverImage();

        if (!NT_SUCCESS(status))
                DEBUG_ERROR("ValidateOurDriverImage failed with status %x", status);

end:
        InterlockedExchange(&timer->state, FALSE);
}

/*
 * This routine is executed every x seconds, and is run at IRQL = DISPATCH_LEVEL
 */
VOID
TimerObjectCallbackRoutine(_In_ PKDPC     Dpc,
                           _In_opt_ PVOID DeferredContext,
                           _In_opt_ PVOID SystemArgument1,
                           _In_opt_ PVOID SystemArgument2)
{
        PTIMER_OBJECT timer = (PTIMER_OBJECT)DeferredContext;

        if (!HasDriverLoaded())
                return;

        /* we dont want to queue our work item if it hasnt executed */
        if (timer->state)
                return;

        /* we queue a work item because DPCs run at IRQL = DISPATCH_LEVEL and we need certain
         * routines which cannot be run at an IRQL this high.*/
        InterlockedExchange(&timer->state, TRUE);
        IoQueueWorkItem(timer->work_item, TimerObjectWorkItemRoutine, BackgroundWorkQueue, timer);
}

NTSTATUS
InitialiseTimerObject(_Out_ PTIMER_OBJECT Timer)
{
        LARGE_INTEGER due_time = {0};
        LONG          period   = 0;

        due_time.QuadPart = ABSOLUTE(SECONDS(5));

        Timer->work_item = IoAllocateWorkItem(GetDriverDeviceObject());

        if (!Timer->work_item)
                return STATUS_MEMORY_NOT_ALLOCATED;

        KeInitializeDpc(&Timer->dpc, TimerObjectCallbackRoutine, Timer);
        KeInitializeTimer(&Timer->timer);
        KeSetTimerEx(&Timer->timer, due_time, REPEAT_TIME_10_SEC, &Timer->dpc);

        DEBUG_VERBOSE("Successfully initialised global timer callback.");
        return STATUS_SUCCESS;
}

VOID
CleanupDriverTimerObjects(_Out_ PTIMER_OBJECT Timer)
{
        /* this routine blocks until all queued DPCs on all processors have executed. */
        KeFlushQueuedDpcs();

        /* wait for our work item to complete */
        while (Timer->state)
                YieldProcessor();

        /* now its safe to free and cancel our timers, pools etc. */
        KeCancelTimer(&Timer->timer);
        IoFreeWorkItem(Timer->work_item);

        DEBUG_VERBOSE("Freed timer objects.");
}

VOID
UnregisterProcessObCallbacks()
{
        PAGED_CODE();
        PACTIVE_SESSION config = GetActiveSession();
        AcquireDriverConfigLock();

        if (config->callback_configuration.registration_handle)
        {
                ImpObUnRegisterCallbacks(config->callback_configuration.registration_handle);
                config->callback_configuration.registration_handle = NULL;
        }

        ReleaseDriverConfigLock();
}

NTSTATUS
RegisterProcessObCallbacks()
{
        PAGED_CODE();

        NTSTATUS        status = STATUS_UNSUCCESSFUL;
        PACTIVE_SESSION config = GetActiveSession();

        DEBUG_VERBOSE("Enabling ObRegisterCallbacks.");
        AcquireDriverConfigLock();

        OB_CALLBACK_REGISTRATION          callback_registration  = {0};
        OB_OPERATION_REGISTRATION         operation_registration = {0};
        PCREATE_PROCESS_NOTIFY_ROUTINE_EX notify_routine         = {0};

        operation_registration.ObjectType = PsProcessType;
        operation_registration.Operations |= OB_OPERATION_HANDLE_CREATE;
        operation_registration.Operations |= OB_OPERATION_HANDLE_DUPLICATE;
        operation_registration.PreOperation  = ObPreOpCallbackRoutine;
        operation_registration.PostOperation = ObPostOpCallbackRoutine;

        callback_registration.Version                    = OB_FLT_REGISTRATION_VERSION;
        callback_registration.OperationRegistration      = &operation_registration;
        callback_registration.OperationRegistrationCount = 1;
        callback_registration.RegistrationContext        = NULL;

        status = ImpObRegisterCallbacks(&callback_registration,
                                        &config->callback_configuration.registration_handle);

        if (!NT_SUCCESS(status))
                DEBUG_ERROR("ObRegisterCallbacks failed with status %x", status);

        ReleaseDriverConfigLock();
        return status;
}

VOID
InitialiseObCallbacksConfiguration(_Out_ PACTIVE_SESSION ProcessConfig)
{
        ImpKeInitializeGuardedMutex(&ProcessConfig->callback_configuration.lock);
}