#include "callbacks.h"

#include "driver.h"

#include "queue.h"
#include "pool.h"
#include "thread.h"
#include "modules.h"
#include "imports.h"
#include "list.h"
#include "session.h"
#include "crypt.h"

STATIC
BOOLEAN
EnumHandleCallback(_In_ PHANDLE_TABLE       HandleTable,
                   _In_ PHANDLE_TABLE_ENTRY Entry,
                   _In_ HANDLE              Handle,
                   _In_ PVOID               Context);

#ifdef ALLOC_PRAGMA
#    pragma alloc_text(PAGE, ObPostOpCallbackRoutine)
#    pragma alloc_text(PAGE, ObPreOpCallbackRoutine)
#    pragma alloc_text(PAGE, EnumHandleCallback)
#    pragma alloc_text(PAGE, EnumerateProcessHandles)
#    pragma alloc_text(PAGE, InitialiseThreadList)
#    pragma alloc_text(PAGE, ExUnlockHandleTableEntry)
#endif

VOID
CleanupThreadListFreeCallback(_In_ PTHREAD_LIST_ENTRY ThreadListEntry)
{
    ImpObDereferenceObject(ThreadListEntry->thread);
    ImpObDereferenceObject(ThreadListEntry->owning_process);
}

VOID
UnregisterProcessCreateNotifyRoutine()
{
    PPROCESS_TREE_HEAD tree = GetProcessTreeHead();
    InterlockedExchange(&tree->active, FALSE);
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

VOID
CleanupThreadListOnDriverUnload()
{
    PTHREAD_LIST_HEAD list = GetThreadList();
    DEBUG_VERBOSE("Freeing thread list!");
    for (;;) {
        if (!LookasideListFreeFirstEntry(
                &list->start, &list->lock, CleanupThreadListFreeCallback)) {
            ExDeleteLookasideListEx(&list->lookaside_list);
            return;
        }
    }
}

VOID
CleanupDriverListOnDriverUnload()
{
    PDRIVER_LIST_HEAD list = GetDriverList();
    for (;;) {
        if (!ListFreeFirstEntry(&list->start, &list->lock, NULL))
            return;
    }
}

VOID
EnumerateThreadListWithCallbackRoutine(
    _In_ THREADLIST_CALLBACK_ROUTINE CallbackRoutine, _In_opt_ PVOID Context)
{
    PTHREAD_LIST_HEAD list = GetThreadList();
    ImpKeAcquireGuardedMutex(&list->lock);

    if (!CallbackRoutine)
        goto unlock;

    PTHREAD_LIST_ENTRY entry = list->start.Next;

    while (entry) {
        CallbackRoutine(entry, Context);
        entry = (PTHREAD_LIST_ENTRY)entry->list.Next;
    }

unlock:
    ImpKeReleaseGuardedMutex(&list->lock);
}

VOID
EnumerateDriverListWithCallbackRoutine(
    _In_ DRIVERLIST_CALLBACK_ROUTINE CallbackRoutine, _In_opt_ PVOID Context)
{
    PDRIVER_LIST_HEAD list = GetDriverList();
    ImpKeAcquireGuardedMutex(&list->lock);

    if (!CallbackRoutine)
        goto unlock;

    PDRIVER_LIST_ENTRY entry = list->start.Next;

    while (entry) {
        CallbackRoutine(entry, Context);
        entry = (PDRIVER_LIST_ENTRY)entry->list.Next;
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
    RtlCopyMemory(
        Extended->FullPathName, Entry->path, sizeof(Extended->FullPathName));
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

    list->can_hash_x86 = FALSE;
    list->work_item    = IoAllocateWorkItem(GetDriverDeviceObject());

    if (!list->work_item)
        return STATUS_INSUFFICIENT_RESOURCES;

    status = GetSystemModuleInformation(&modules);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("GetSystemModuleInformation failed with status %x", status);
        return status;
    }

    /* skip hal.dll and ntoskrnl.exe */
    for (INT index = 2; index < modules.module_count; index++) {
        entry = ImpExAllocatePool2(POOL_FLAG_NON_PAGED,
                                   sizeof(DRIVER_LIST_ENTRY),
                                   POOL_TAG_DRIVER_LIST);

        if (!entry)
            continue;

        module_entry = &((PRTL_MODULE_EXTENDED_INFO)modules.address)[index];

        entry->hashed    = TRUE;
        entry->ImageBase = module_entry->ImageBase;
        entry->ImageSize = module_entry->ImageSize;

        RtlCopyMemory(entry->path,
                      module_entry->FullPathName,
                      sizeof(module_entry->FullPathName));

        status = HashModule(module_entry, entry->text_hash);

        if (status == STATUS_INVALID_IMAGE_WIN_32) {
            DEBUG_ERROR("32 bit module not hashed, will hash later. %x",
                        status);
            entry->hashed = FALSE;
            entry->x86    = TRUE;
            InsertHeadList(&list->deferred_list, &entry->deferred_entry);
        }
        else if (!NT_SUCCESS(status)) {
            DEBUG_ERROR("HashModule failed with status %x", status);
            entry->hashed = FALSE;
        }

        ListInsert(&list->start, entry, &list->lock);
    }

    list->active = TRUE;

    if (modules.address)
        ImpExFreePoolWithTag(modules.address, SYSTEM_MODULES_POOL);

    return STATUS_SUCCESS;
}

/*
 * I actually think a spinlock here for the driver list is what we want rather
 * then a mutex, but implementing a spinlock has its challenges... todo: have a
 * think!
 */
VOID
FindDriverEntryByBaseAddress(_In_ PVOID                ImageBase,
                             _Out_ PDRIVER_LIST_ENTRY* Entry)
{
    PDRIVER_LIST_HEAD list = GetDriverList();
    ImpKeAcquireGuardedMutex(&list->lock);
    *Entry = NULL;

    PDRIVER_LIST_ENTRY entry = (PDRIVER_LIST_ENTRY)list->start.Next;

    while (entry) {
        if (entry->ImageBase == ImageBase) {
            *Entry = entry;
            goto unlock;
        }

        entry = entry->list.Next;
    }
unlock:
    ImpKeReleaseGuardedMutex(&list->lock);
}

STATIC
RTL_GENERIC_COMPARE_RESULTS
ProcessTreeCompareNode(_In_ RTL_GENERIC_TABLE  Table,
                       _In_ PPROCESS_TREE_NODE Struct1,
                       _In_ PPROCESS_TREE_NODE Struct2)
{
    if ((UINT64)Struct1->process < (UINT64)Struct2->process)
        return GenericLessThan;
    else if ((UINT64)Struct1->process > (UINT64)Struct2->process)
        return GenericGreaterThan;
    else
        return GenericEqual;
}

STATIC
PVOID
ProcessTreeAllocateNode(_In_ RTL_GENERIC_TABLE Table, _In_ CLONG ByteSize)
{
    /* We initialize the members once allocated. */
    return ImpExAllocatePool2(
        POOL_FLAG_NON_PAGED, ByteSize, POOL_TAG_MODULE_TREE);
}

STATIC
VOID
ProcessTreeFreeNode(_In_ RTL_GENERIC_TABLE Table, _In_ PVOID Buffer)
{
    ImpExFreePoolWithTag(Buffer, POOL_TAG_MODULE_TREE);
}

STATIC
VOID
ImageLoadInsertNonSystemImageIntoProcessTree(_In_ PIMAGE_INFO ImageInfo,
                                             _In_ HANDLE      ProcessId)
{
    NTSTATUS                        status  = STATUS_UNSUCCESSFUL;
    PEPROCESS                       process = NULL;
    PPROCESS_TREE_NODE              node    = NULL;
    PPROCESS_TREE_HEAD              tree    = GetProcessTreeHead();
    PPROCESS_TREE_MODULE_LIST_ENTRY entry   = NULL;

    status = PsLookupProcessByProcessId(ProcessId, &process);

    if (!NT_SUCCESS(status))
        return;

    KeAcquireGuardedMutex(&tree->lock);

    /* the PEPROCESS is the first element and is the only thing compared, hence
     * we can simply pass it in the context parameter.*/
    node = RtlLookupElementGenericTable(&tree->table, &process);

    /* critical error has occured */
    if (!node) {
        DEBUG_ERROR("RtlLookupElementGenericTable failed.");
        goto end;
    }

    entry = ExAllocateFromLookasideListEx(&tree->module_list_entry_lookaside);

    if (!entry)
        goto end;

    /* for now lets just do base and size */
    entry->base = ImageInfo->ImageBase;
    entry->size = ImageInfo->ImageSize;

    InsertHeadList(&node->module_list, &entry->entry);
    node->list_count++;

end:
    KeReleaseGuardedMutex(&tree->lock);
}

VOID
ImageLoadNotifyRoutineCallback(_In_opt_ PUNICODE_STRING FullImageName,
                               _In_ HANDLE              ProcessId,
                               _In_ PIMAGE_INFO         ImageInfo)
{
    UNREFERENCED_PARAMETER(ProcessId);

    NTSTATUS                 status    = STATUS_UNSUCCESSFUL;
    PDRIVER_LIST_ENTRY       entry     = NULL;
    RTL_MODULE_EXTENDED_INFO module    = {0};
    PDRIVER_LIST_HEAD        list      = GetDriverList();
    ANSI_STRING              ansi_path = {0};

    if (InterlockedExchange(&list->active, list->active) == FALSE)
        return;

    if (ImageInfo->SystemModeImage == FALSE) {
        ImageLoadInsertNonSystemImageIntoProcessTree(ImageInfo, ProcessId);
        return;
    }

    FindDriverEntryByBaseAddress(ImageInfo->ImageBase, &entry);

    if (entry)
        return;

    entry = ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(DRIVER_LIST_ENTRY), POOL_TAG_DRIVER_LIST);

    if (!entry)
        return;

    entry->hashed    = TRUE;
    entry->x86       = FALSE;
    entry->ImageBase = ImageInfo->ImageBase;
    entry->ImageSize = ImageInfo->ImageSize;

    module.ImageBase = ImageInfo->ImageBase;
    module.ImageSize = ImageInfo->ImageSize;

    if (FullImageName) {
        status = RtlUnicodeStringToAnsiString(&ansi_path, FullImageName, TRUE);

        if (!NT_SUCCESS(status)) {
            DEBUG_ERROR("RtlUnicodeStringToAnsiString failed with status %x",
                        status);
            goto hash;
        }

        if (ansi_path.Length > sizeof(module.FullPathName)) {
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

    if (status == STATUS_INVALID_IMAGE_WIN_32) {
        DEBUG_ERROR("32 bit module not hashed, will hash later. %x", status);
        entry->x86    = TRUE;
        entry->hashed = FALSE;
    }
    else if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("HashModule failed with status %x", status);
        entry->hashed = FALSE;
    }

    ListInsert(&list->start, entry, &list->lock);
}

/*
 * I have chosen to refactor this to use a Splay tree (RTL_GENERIC_TABLE) for
 * the storage of both processes and associated modules. The reasons for this is
 * as follows:
 *
 * 1. Splay trees are self-balancing in the regard that recently used nodes will
 * be closer to the root. Due to the fact we are wanting to store modules, once
 * a process is launched and subsequent modules are loaded, the process
 * associated with these processes will live near the root - allowing for faster
 * access.
 *
 * 2. The initial implementation was a simple linked list of processes, but the
 * need to safely access loaded modules for that process became a need. So an
 * unoredered linked-list full of modules would incur way too much overhead in
 * lookups and deletions.
 * 
 * So the end implementation is a splay tree.
 */
NTSTATUS
InitialiseProcessTree()
{
    PAGED_CODE();

    NTSTATUS           status = STATUS_UNSUCCESSFUL;
    PPROCESS_TREE_HEAD tree   = GetProcessTreeHead();

    DEBUG_VERBOSE("Initialising process tree");

    RtlInitializeGenericTable(&tree->table,
                              ProcessTreeCompareNode,
                              ProcessTreeAllocateNode,
                              ProcessTreeFreeNode,
                              NULL);

    KeInitializeGuardedMutex(&tree->lock);

    status = ExInitializeLookasideListEx(&tree->module_list_entry_lookaside,
                                         NULL,
                                         NULL,
                                         POOL_NX_ALLOCATION,
                                         0,
                                         sizeof(PROCESS_TREE_MODULE_LIST_ENTRY),
                                         POOL_TAG_USER_MODULE_LIST,
                                         0);

    if (!NT_SUCCESS(status))
        return status;

    tree->active = TRUE;
    DEBUG_VERBOSE("Process tree is successfully active!");

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

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ExInitializeLookasideListEx failed with status %x",
                    status);
        return status;
    }

    InterlockedExchange(&list->active, TRUE);
    ListInit(&list->start, &list->lock);
    return status;
}

VOID
FindThreadListEntryByThreadAddress(_In_ PKTHREAD             Thread,
                                   _Out_ PTHREAD_LIST_ENTRY* Entry)
{
    PTHREAD_LIST_HEAD list = GetThreadList();
    ImpKeAcquireGuardedMutex(&list->lock);
    *Entry = NULL;

    PTHREAD_LIST_ENTRY entry = (PTHREAD_LIST_ENTRY)list->start.Next;

    while (entry) {
        if (entry->thread == Thread) {
            *Entry = entry;
            goto unlock;
        }

        entry = entry->list.Next;
    }
unlock:
    ImpKeReleaseGuardedMutex(&list->lock);
}

FORCEINLINE
STATIC
BOOLEAN
CanInitiateDeferredHashing(_In_ LPCSTR ProcessName, _In_ PDRIVER_LIST_HEAD Head)
{
    return !strcmp(ProcessName, "winlogon.exe") && Head->work_item ? TRUE
                                                                   : FALSE;
}

FORCEINLINE
STATIC
VOID
InitialiseProcessNodeEntry(_In_ PPROCESS_TREE_NODE Node,
                           _In_ PEPROCESS          Process,
                           _In_ PEPROCESS          Parent)
{
    ImpObfReferenceObject(Parent);
    ImpObfReferenceObject(Process);

    Node->parent  = Parent;
    Node->process = Process;

    InitializeListHead(&Node->module_list);
    Node->list_count = 0;
}

FORCEINLINE
STATIC
VOID
FreeProcessNodeModuleList(_In_ PPROCESS_TREE_NODE Node)
{
    PPROCESS_TREE_HEAD              tree  = GetProcessTreeHead();
    PLIST_ENTRY                     list  = NULL;
    PPROCESS_TREE_MODULE_LIST_ENTRY entry = NULL;

    while (!IsListEmpty(&Node->module_list)) {
        list  = RemoveHeadList(&Node->module_list);
        entry = CONTAINING_RECORD(list, PROCESS_TREE_MODULE_LIST_ENTRY, entry);

        ExFreeToLookasideListEx(&tree->module_list_entry_lookaside, entry);
    }
}

VOID
EnumerateProcessTreeWithCallback(
    _In_ PROCESS_TREE_CALLBACK_ROUTINE CallbackRoutine, _In_opt_ PVOID Context)
{
    PPROCESS_TREE_HEAD tree = GetProcessTreeHead();
    PPROCESS_TREE_NODE node = NULL;

    for (node = RtlEnumerateGenericTable(&tree->table, TRUE); node != NULL;
         node = RtlEnumerateGenericTable(&tree->table, FALSE)) {
        CallbackRoutine(node, Context);
    }
}

VOID
CleanupProcessTree()
{
    PPROCESS_TREE_HEAD tree = GetProcessTreeHead();
    PPROCESS_TREE_NODE node = NULL;

    tree->active = FALSE;

    KeAcquireGuardedMutex(&tree->lock);

    /* We could do this in a single pass, but this is good enough for now -
     * especially when performance doesnt really matter since we are unloading
     * the driver... Will fix later.*/
    EnumerateProcessTreeWithCallback(FreeProcessNodeModuleList, NULL);

    for (node = RtlEnumerateGenericTable(&tree->table, TRUE); node != NULL;
         node = RtlEnumerateGenericTable(&tree->table, FALSE)) {
        RtlDeleteElementGenericTable(&tree->table, node);
    }

    ExDeleteLookasideListEx(&tree->module_list_entry_lookaside);

end:
    KeReleaseGuardedMutex(&tree->lock);
}

#if DEBUG
STATIC
VOID
PrintEntireProcessTreeWithModules()
{
    PPROCESS_TREE_HEAD              tree   = get_process_tree_head();
    PPROCESS_TREE_NODE              node   = NULL;
    PLIST_ENTRY                     entry  = NULL;
    PPROCESS_TREE_MODULE_LIST_ENTRY module = NULL;

    KeAcquireGuardedMutex(&tree->lock);

    for (node = RtlEnumerateGenericTable(&tree->table, TRUE); node != NULL;
         node = RtlEnumerateGenericTable(&tree->table, FALSE)) {
        DEBUG_VERBOSE("Process: %p, Parent: %p, Module Count: %u",
                      node->process,
                      node->parent,
                      node->list_count);

        // Iterate through the module list for the current process
        for (entry = node->module_list.Flink; entry != &node->module_list;
             entry = entry->Flink) {
            module =
                CONTAINING_RECORD(entry, PROCESS_TREE_MODULE_LIST_ENTRY, entry);
            DEBUG_VERBOSE("  Module Base: %llx, Size: %x, Path: %s",
                          module->base,
                          module->size,
                          module->path);
        }
    }

    KeReleaseGuardedMutex(&tree->lock);
}
#endif

VOID
ProcessCreateNotifyRoutine(_In_ HANDLE  ParentId,
                           _In_ HANDLE  ProcessId,
                           _In_ BOOLEAN Create)
{
    BOOLEAN new                     = FALSE;
    PKPROCESS          parent       = NULL;
    PKPROCESS          process      = NULL;
    PDRIVER_LIST_HEAD  driver_list  = GetDriverList();
    LPCSTR             process_name = NULL;
    PPROCESS_TREE_HEAD tree         = GetProcessTreeHead();
    PPROCESS_TREE_NODE node         = NULL;

    if (!tree->active)
        return;

    ImpPsLookupProcessByProcessId(ParentId, &parent);
    ImpPsLookupProcessByProcessId(ProcessId, &process);

    if (!parent || !process)
        return;

    process_name = ImpPsGetProcessImageFileName(process);

    KeAcquireGuardedMutex(&tree->lock);

    if (Create) {
        node = RtlInsertElementGenericTable(
            &tree->table, &process, sizeof(PROCESS_TREE_NODE), &new);

        if (!new) {
            DEBUG_ERROR("Unable to insert new process tree node!");
            goto end;
        }

        InitialiseProcessNodeEntry(node, process, parent);
        /*
         * Notify to our driver that we can hash x86 modules, and hash
         * any x86 modules that werent hashed.
         */
        if (CanInitiateDeferredHashing(process_name, driver_list)) {
            IoQueueWorkItem(driver_list->work_item,
                            DeferredModuleHashingCallback,
                            NormalWorkQueue,
                            NULL);
        }

        DEBUG_VERBOSE("Inserted process node: %llx", (UINT64)process);
    }
    else {
        node = RtlLookupElementGenericTable(&tree->table, &process);

        if (!node) {
            DEBUG_ERROR("UNABLE TO FIND PROCESS NODE!!!");
            goto end;
        }

        FreeProcessNodeModuleList(node);

        ImpObDereferenceObject(node->parent);
        ImpObDereferenceObject(node->process);

        if (!RtlDeleteElementGenericTable(&tree->table, node)) {
            DEBUG_ERROR("Failed to delete node from process tree: %llx",
                        (UINT64)node);
            goto end;
        }

        DEBUG_VERBOSE("Removed process node: %llx", (UINT64)process);
    }

end:
    KeReleaseGuardedMutex(&tree->lock);
}

VOID
ThreadCreateNotifyRoutine(_In_ HANDLE  ProcessId,
                          _In_ HANDLE  ThreadId,
                          _In_ BOOLEAN Create)
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

    if (Create) {
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
    else {
        FindThreadListEntryByThreadAddress(thread, &entry);

        if (!entry)
            return;

        ImpObDereferenceObject(entry->thread);
        ImpObDereferenceObject(entry->owning_process);

        LookasideListRemoveEntry(&list->start, entry, &list->lock);
    }
}

VOID
ObPostOpCallbackRoutine(_In_ PVOID RegistrationContext,
                        _In_ POB_POST_OPERATION_INFORMATION
                            OperationInformation)
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(RegistrationContext);
    UNREFERENCED_PARAMETER(OperationInformation);
}

#define MAX_PROCESS_NAME_LENGTH             30
#define PROCESS_HANDLE_OPEN_DOWNGRADE_COUNT 4

#define DOWNGRADE_LSASS    0
#define DOWNGRADE_CSRSS    1
#define DOWNGRADE_WERFAULT 2
#define DOWNGRADE_MSMPENG  3

CHAR PROCESS_HANDLE_OPEN_DOWNGRADE[PROCESS_HANDLE_OPEN_DOWNGRADE_COUNT]
                                  [MAX_PROCESS_NAME_LENGTH] = {"lsass.exe",
                                                               "csrss.exe",
                                                               "WerFault.exe",
                                                               "MsMpEng.exe"};

#define PROCESS_HANDLE_OPEN_WHITELIST_COUNT 3

CHAR PROCESS_HANDLE_OPEN_WHITELIST[PROCESS_HANDLE_OPEN_WHITELIST_COUNT]
                                  [MAX_PROCESS_NAME_LENGTH] = {"Discord.exe",
                                                               "svchost.exe",
                                                               "explorer.exe"};

STATIC
BOOLEAN
IsWhitelistedHandleOpenProcess(_In_ LPCSTR ProcessName)
{
    for (UINT32 index = 0; index < PROCESS_HANDLE_OPEN_WHITELIST_COUNT;
         index++) {
        if (!strcmp(ProcessName, PROCESS_HANDLE_OPEN_WHITELIST[index]))
            return TRUE;
    }

    return FALSE;
}

STATIC
BOOLEAN
IsDowngradeHandleOpenProcess(_In_ LPCSTR ProcessName)
{
    for (UINT32 index = 0; index < PROCESS_HANDLE_OPEN_DOWNGRADE_COUNT;
         index++) {
        if (!strcmp(ProcessName, PROCESS_HANDLE_OPEN_DOWNGRADE[index]))
            return TRUE;
    }

    return FALSE;
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
    NTSTATUS  status                 = STATUS_UNSUCCESSFUL;
    PEPROCESS process_creator        = PsGetCurrentProcess();
    PEPROCESS protected_process      = NULL;
    PEPROCESS target_process         = (PEPROCESS)OperationInformation->Object;
    HANDLE    process_creator_id     = ImpPsGetProcessId(process_creator);
    LONG      protected_process_id   = 0;
    LPCSTR    process_creator_name   = NULL;
    LPCSTR    target_process_name    = NULL;
    LPCSTR    protected_process_name = NULL;
    POB_CALLBACKS_CONFIG configuration = NULL;
    UINT32               report_size   = 0;

    /*
     * This is to prevent the condition where the thread executing this
     * function is scheduled whilst we are cleaning up the callbacks on
     * driver unload. We must hold the driver config lock to ensure the pool
     * containing the callback configuration lock is not freed
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

    if (strcmp(protected_process_name, target_process_name))
        goto end;
    /*
     * WerFault is some windows 11 application that cries when it
     * cant get a handle, so well allow it for now... todo; learn
     * more about it
     *
     * todo: perform stricter checks rather then the image name.
     * perhapds check some certificate or something.
     */
    if (IsDowngradeHandleOpenProcess(process_creator_name) ||
        !strcmp(process_creator_name, target_process_name)) {
        /* We will downgrade these handles later */
        // DEBUG_LOG("Handles created by CSRSS, LSASS and
        // WerFault are allowed for now...");
    }
    else if (target_process == process_creator) {
        // DEBUG_LOG("handles made by NOTEPAD r okay :)");
        /* handles created by the game (notepad) are okay */
    }
    else {
        OperationInformation->Parameters->CreateHandleInformation
            .DesiredAccess = deny_access;
        OperationInformation->Parameters->DuplicateHandleInformation
            .DesiredAccess = deny_access;

        /*
         * These processes will constantly open handles to any
         * open process for various reasons, so we will still
         * strip them but we won't report them.. for now
         * atleast.
         */

        if (IsWhitelistedHandleOpenProcess(process_creator_name))
            goto end;

        report_size = CryptRequestRequiredBufferLength(
            sizeof(OPEN_HANDLE_FAILURE_REPORT));

        POPEN_HANDLE_FAILURE_REPORT report = ImpExAllocatePool2(
            POOL_FLAG_NON_PAGED, report_size, REPORT_POOL_TAG);

        if (!report)
            goto end;

        INIT_REPORT_PACKET(report, REPORT_ILLEGAL_HANDLE_OPERATION, 0);

        report->is_kernel_handle = OperationInformation->KernelHandle;
        report->process_id       = process_creator_id;
        report->thread_id        = ImpPsGetCurrentThreadId();
        report->access           = OperationInformation->Parameters
                             ->CreateHandleInformation.DesiredAccess;

        RtlCopyMemory(report->process_name,
                      process_creator_name,
                      HANDLE_REPORT_PROCESS_NAME_MAX_LENGTH);

        status = CryptEncryptBuffer(report, report_size);

        if (!NT_SUCCESS(status)) {
            DEBUG_ERROR("CryptEncryptBuffer: %x", status);
            ExFreePoolWithTag(report, report_size);
            goto end;
        }

        IrpQueueSchedulePacket(report, report_size);
    }

end:

    ImpKeReleaseGuardedMutex(&configuration->lock);
    return OB_PREOP_SUCCESS;
}

/* stolen from ReactOS xD */
VOID NTAPI
ExUnlockHandleTableEntry(IN PHANDLE_TABLE       HandleTable,
                         IN PHANDLE_TABLE_ENTRY HandleTableEntry)
{
    INT64 old_value;
    PAGED_CODE();

    /* Set the lock bit and make sure it wasn't earlier */
    old_value = InterlockedOr((PLONG)&HandleTableEntry->VolatileLowValue, 1);

    /* Unblock any waiters */
#pragma warning(push)
#pragma warning(disable : C6387)
    ImpExfUnblockPushLock(&HandleTable->HandleContentionEvent, NULL);
#pragma warning(pop)
}

FORCEINLINE
STATIC
ACCESS_MASK
GetHandleAccessMask(_In_ PHANDLE_TABLE_ENTRY Entry)
{
    return (ACCESS_MASK)Entry->GrantedAccessBits;
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

    UNREFERENCED_PARAMETER(Context);

    NTSTATUS     status                 = STATUS_UNSUCCESSFUL;
    PVOID        object                 = NULL;
    PVOID        object_header          = NULL;
    POBJECT_TYPE object_type            = NULL;
    PEPROCESS    process                = NULL;
    PEPROCESS    protected_process      = NULL;
    LPCSTR       process_name           = NULL;
    LPCSTR       protected_process_name = NULL;
    ACCESS_MASK  handle_access_mask     = 0;
    UINT32       report_size            = 0;

    object_header = GET_OBJECT_HEADER_FROM_HANDLE(Entry->ObjectPointerBits);

    /* Object header is the first 30 bytes of the object */
    object      = (uintptr_t)object_header + OBJECT_HEADER_SIZE;
    object_type = ImpObGetObjectType(object);

    /* TODO: check for threads aswell */
    if (ImpRtlCompareUnicodeString(
            &object_type->Name, &OBJECT_TYPE_PROCESS, TRUE)) {
        goto end;
    }

    process      = (PEPROCESS)object;
    process_name = ImpPsGetProcessImageFileName(process);

    SessionGetProcess(&protected_process);

    protected_process_name = ImpPsGetProcessImageFileName(protected_process);

    if (strcmp(process_name, protected_process_name))
        goto end;

    DEBUG_VERBOSE(
        "Handle references our protected process with access mask: %lx",
        (ACCESS_MASK)Entry->GrantedAccessBits);

    handle_access_mask = GetHandleAccessMask(Entry);

    /* These permissions can be stripped from every process
     * including CSRSS and LSASS */
    if (handle_access_mask & PROCESS_CREATE_PROCESS) {
        Entry->GrantedAccessBits &= ~PROCESS_CREATE_PROCESS;
        DEBUG_VERBOSE("Stripped PROCESS_CREATE_PROCESS");
    }

    if (handle_access_mask & PROCESS_CREATE_THREAD) {
        Entry->GrantedAccessBits &= ~PROCESS_CREATE_THREAD;
        DEBUG_VERBOSE("Stripped PROCESS_CREATE_THREAD");
    }

    if (handle_access_mask & PROCESS_DUP_HANDLE) {
        Entry->GrantedAccessBits &= ~PROCESS_DUP_HANDLE;
        DEBUG_VERBOSE("Stripped PROCESS_DUP_HANDLE");
    }

    if (handle_access_mask & PROCESS_QUERY_INFORMATION) {
        Entry->GrantedAccessBits &= ~PROCESS_QUERY_INFORMATION;
        DEBUG_VERBOSE("Stripped PROCESS_QUERY_INFORMATION");
    }

    if (handle_access_mask & PROCESS_QUERY_LIMITED_INFORMATION) {
        Entry->GrantedAccessBits &= ~PROCESS_QUERY_LIMITED_INFORMATION;
        DEBUG_VERBOSE("Stripped PROCESS_QUERY_LIMITED_INFORMATION");
    }

    if (handle_access_mask & PROCESS_VM_READ) {
        Entry->GrantedAccessBits &= ~PROCESS_VM_READ;
        DEBUG_VERBOSE("Stripped PROCESS_VM_READ");
    }

    if (!strcmp(process_name, "csrss.exe") ||
        !strcmp(process_name, "lsass.exe")) {
        DEBUG_VERBOSE(
            "Required system process allowed, only stripping some permissions");
        goto end;
    }

    /* Permissions beyond here can only be stripped from non
     * critical processes */
    if (handle_access_mask & PROCESS_SET_INFORMATION) {
        Entry->GrantedAccessBits &= ~PROCESS_SET_INFORMATION;
        DEBUG_VERBOSE("Stripped PROCESS_SET_INFORMATION");
    }

    if (handle_access_mask & PROCESS_SET_QUOTA) {
        Entry->GrantedAccessBits &= ~PROCESS_SET_QUOTA;
        DEBUG_VERBOSE("Stripped PROCESS_SET_QUOTA");
    }

    if (handle_access_mask & PROCESS_SUSPEND_RESUME) {
        Entry->GrantedAccessBits &= ~PROCESS_SUSPEND_RESUME;
        DEBUG_VERBOSE("Stripped PROCESS_SUSPEND_RESUME ");
    }

    if (handle_access_mask & PROCESS_TERMINATE) {
        Entry->GrantedAccessBits &= ~PROCESS_TERMINATE;
        DEBUG_VERBOSE("Stripped PROCESS_TERMINATE");
    }

    if (handle_access_mask & PROCESS_VM_OPERATION) {
        Entry->GrantedAccessBits &= ~PROCESS_VM_OPERATION;
        DEBUG_VERBOSE("Stripped PROCESS_VM_OPERATION");
    }

    if (handle_access_mask & PROCESS_VM_WRITE) {
        Entry->GrantedAccessBits &= ~PROCESS_VM_WRITE;
        DEBUG_VERBOSE("Stripped PROCESS_VM_WRITE");
    }

    report_size =
        CryptRequestRequiredBufferLength(sizeof(OPEN_HANDLE_FAILURE_REPORT));

    POPEN_HANDLE_FAILURE_REPORT report =
        ImpExAllocatePool2(POOL_FLAG_NON_PAGED, report_size, REPORT_POOL_TAG);

    if (!report)
        goto end;

    /*
     * Using the same report structure as the ObRegisterCallbacks
     * report since both of these reports are closely related by the
     * fact they are triggered by a process either opening a handle
     * to our protected process or have a valid open handle to it. I
     * also don't think its worth creating another queue
     * specifically for open handle reports since they will be rare.
     */
    INIT_REPORT_PACKET(report, REPORT_ILLEGAL_HANDLE_OPERATION, 0);

    report->is_kernel_handle = Entry->Attributes & OBJ_KERNEL_HANDLE;
    report->process_id       = ImpPsGetProcessId(process);
    report->thread_id        = 0;
    report->access           = handle_access_mask;

    RtlCopyMemory(&report->process_name,
                  process_name,
                  HANDLE_REPORT_PROCESS_NAME_MAX_LENGTH);

    status = CryptEncryptBuffer(report, report_size);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("CryptEncryptBuffer: %lx", status);
        ImpExFreePoolWithTag(report, report_size);
        goto end;
    }

    IrpQueueSchedulePacket(report, report_size);

end:
    ExUnlockHandleTableEntry(HandleTable, Entry);
    return FALSE;
}

NTSTATUS
EnumerateProcessHandles(_In_ PPROCESS_TREE_NODE Node, _In_opt_ PVOID Context)
{
    /* Handles are stored in pageable memory */
    PAGED_CODE();

    UNREFERENCED_PARAMETER(Context);

    if (!Node)
        return STATUS_INVALID_PARAMETER;

    if (Node->process == PsInitialSystemProcess)
        return STATUS_SUCCESS;

    PHANDLE_TABLE handle_table =
        *(PHANDLE_TABLE*)((uintptr_t)Node->process +
                          EPROCESS_HANDLE_TABLE_OFFSET);

    if (!handle_table)
        return STATUS_INVALID_ADDRESS;

    if (!ImpMmIsAddressValid(handle_table))
        return STATUS_INVALID_ADDRESS;

#pragma warning(push)
#pragma warning(suppress : 6387)

    ImpExEnumHandleTable(handle_table, EnumHandleCallback, NULL, NULL);

#pragma warning(pop)

    return STATUS_SUCCESS;
}

#define REPEAT_TIME_10_SEC 10000

STATIC
VOID
TimerObjectWorkItemRoutine(_In_ PDEVICE_OBJECT DeviceObject,
                           _In_opt_ PVOID      Context)
{
    NTSTATUS          status  = STATUS_UNSUCCESSFUL;
    PTIMER_OBJECT     timer   = (PTIMER_OBJECT)Context;
    PDRIVER_LIST_HEAD list    = GetDriverList();
    PACTIVE_SESSION   session = GetActiveSession();

    UNREFERENCED_PARAMETER(DeviceObject);

    if (!ARGUMENT_PRESENT(Context))
        return;

    if (!list->active)
        goto end;

    DEBUG_VERBOSE("Integrity check timer callback invoked.");

    if (!ValidateOurDriversDispatchRoutines()) {
        DEBUG_VERBOSE("l");
    }

    status = ValidateOurDriverImage();

    if (!NT_SUCCESS(status))
        DEBUG_ERROR("ValidateOurDriverImage failed with status %x", status);

    KeAcquireGuardedMutex(&session->lock);
    if (!session->is_session_active) {
        KeReleaseGuardedMutex(&session->lock);
        goto end;
    }

    // note 2 self: not sure if the incoming messages are encrypted yet.

    KeReleaseGuardedMutex(&session->lock);
end:
    InterlockedExchange(&timer->state, FALSE);
}

/*
 * This routine is executed every x seconds, and is run at IRQL = DISPATCH_LEVEL
 */
STATIC
VOID
TimerObjectCallbackRoutine(_In_ PKDPC     Dpc,
                           _In_opt_ PVOID DeferredContext,
                           _In_opt_ PVOID SystemArgument1,
                           _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (!HasDriverLoaded() || !ARGUMENT_PRESENT(DeferredContext))
        return;

    PTIMER_OBJECT timer = (PTIMER_OBJECT)DeferredContext;

    /* we dont want to queue our work item if it hasnt executed */
    if (timer->state)
        return;

    /* we queue a work item because DPCs run at IRQL = DISPATCH_LEVEL and we
     * need certain routines which cannot be run at an IRQL this high.*/
    InterlockedExchange(&timer->state, TRUE);
    IoQueueWorkItem(timer->work_item,
                    TimerObjectWorkItemRoutine,
                    BackgroundWorkQueue,
                    timer);
}

NTSTATUS
InitialiseTimerObject(_Out_ PTIMER_OBJECT Timer)
{
    LARGE_INTEGER due_time = {.QuadPart = -ABSOLUTE(SECONDS(5))};

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
CleanupDriverTimerObjects(_Inout_ PTIMER_OBJECT Timer)
{
    /* this routine blocks until all queued DPCs on all processors have
     * executed. */
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

    if (config->callback_configuration.registration_handle) {
        ImpObUnRegisterCallbacks(
            config->callback_configuration.registration_handle);
        config->callback_configuration.registration_handle = NULL;
    }

    ReleaseDriverConfigLock();
}

NTSTATUS
RegisterProcessObCallbacks()
{
    PAGED_CODE();

    NTSTATUS                  status                 = STATUS_UNSUCCESSFUL;
    PACTIVE_SESSION           config                 = GetActiveSession();
    OB_CALLBACK_REGISTRATION  callback_registration  = {0};
    OB_OPERATION_REGISTRATION operation_registration = {0};

    DEBUG_VERBOSE("Enabling ObRegisterCallbacks.");
    AcquireDriverConfigLock();

    operation_registration.ObjectType = PsProcessType;
    operation_registration.Operations |= OB_OPERATION_HANDLE_CREATE;
    operation_registration.Operations |= OB_OPERATION_HANDLE_DUPLICATE;
    operation_registration.PreOperation  = ObPreOpCallbackRoutine;
    operation_registration.PostOperation = ObPostOpCallbackRoutine;

    callback_registration.Version               = OB_FLT_REGISTRATION_VERSION;
    callback_registration.OperationRegistration = &operation_registration;
    callback_registration.OperationRegistrationCount = 1;
    callback_registration.RegistrationContext        = NULL;

    status = ImpObRegisterCallbacks(
        &callback_registration,
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