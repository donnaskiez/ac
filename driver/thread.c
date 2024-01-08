#include "thread.h"

#include <intrin.h>

#include "pool.h"
#include "callbacks.h"
#include "driver.h"
#include "queue.h"
#include "imports.h"

#ifdef ALLOC_PRAGMA
#        pragma alloc_text(PAGE, DetectThreadsAttachedToProtectedProcess)
#        pragma alloc_text(PAGE, ValidateThreadsPspCidTableEntry)
#endif

BOOLEAN
ValidateThreadsPspCidTableEntry(_In_ PETHREAD Thread)
{
        PAGED_CODE();

        NTSTATUS status    = STATUS_UNSUCCESSFUL;
        HANDLE   thread_id = NULL;
        PETHREAD thread    = NULL;

        /*
         * PsGetThreadId simply returns ETHREAD->Cid.UniqueThread
         */
        thread_id = ImpPsGetThreadId(Thread);

        /*
         * For each core on the processor, the first x threads equal to x cores will be assigned a
         * cid equal to its equivalent core. These threads are generally executing the HLT
         * instruction or some other boring stuff while the processor is not busy. The reason this
         * is important is because passing in a handle value of 0 which, even though is a valid cid,
         * returns a non success status meaning we mark it an invalid cid entry even though it is.
         * To combat this we simply add a little check here. The problem is this can be easily
         * bypassed by simply modifying the ETHREAD->Cid.UniqueThread identifier.. So while it isnt
         * a perfect detection method for now it's good enough.
         */
        if ((UINT64)thread_id < (UINT64)ImpKeQueryActiveProcessorCount(NULL))
                return TRUE;

        /*
         * PsLookupThreadByThreadId will use a threads id to find its cid entry, and return
         * the pointer contained in the HANDLE_TABLE entry pointing to the thread object.
         * Meaning if we pass a valid thread id which we retrieved above and dont receive a
         * STATUS_SUCCESS the cid entry could potentially be removed or disrupted..
         */
        status = ImpPsLookupThreadByThreadId(thread_id, &thread);

        if (!NT_SUCCESS(status))
        {
                DEBUG_WARNING(
                    "Failed to lookup thread by id. PspCidTable entry potentially removed.");
                return FALSE;
        }

        return TRUE;
}

/*
 * I did not reverse this myself and previously had no idea how you would go about
 * detecting KiAttachProcess so credits to KANKOSHEV for the find:
 *
 * https://github.com/KANKOSHEV/Detect-KeAttachProcess/tree/main
 * https://doxygen.reactos.org/d0/dc9/procobj_8c.html#adec6dc539d4a5c0ee7d0f48e24ef0933
 *
 * To expand on his writeup a little, the offset that he provides is equivalent to
 * PKAPC_STATE->Process. This is where KiAttachProcess writes the process that thread is attaching
 * to when it's called. The APC_STATE structure holds relevant information about the thread's APC
 * state and is quite important during context switch scenarios as it's how the thread determines if
 * it has any APC's queued.
 */
STATIC VOID
DetectAttachedThreadsProcessCallback(_In_ PTHREAD_LIST_ENTRY ThreadListEntry,
                                     _Inout_opt_ PVOID       Context)
{
        UNREFERENCED_PARAMETER(Context);

        PKAPC_STATE apc_state         = NULL;
        PEPROCESS   protected_process = NULL;

        GetProtectedProcessEProcess(&protected_process);

        if (!protected_process)
                return;

        apc_state = (PKAPC_STATE)((UINT64)ThreadListEntry->thread + KTHREAD_APC_STATE_OFFSET);

        /*
         * Just a sanity check even though it doesnt really make sense for internal threads of our
         * protected process to attach..
         *
         * todo: this is filterless and will just report anything, need to have a look into what
         * processes actually attach to real games
         */
        if (apc_state->Process == protected_process)
        {
                DEBUG_WARNING("Thread is attached to our protected process: %llx",
                              (UINT64)ThreadListEntry->thread);

                PATTACH_PROCESS_REPORT report = ImpExAllocatePool2(
                    POOL_FLAG_NON_PAGED, sizeof(ATTACH_PROCESS_REPORT), REPORT_POOL_TAG);

                if (!report)
                        return;

                report->report_code    = REPORT_ILLEGAL_ATTACH_PROCESS;
                report->thread_id      = ImpPsGetThreadId(ThreadListEntry->thread);
                report->thread_address = ThreadListEntry->thread;

                InsertReportToQueue(report);
        }
}

VOID
DetectThreadsAttachedToProtectedProcess()
{
        PAGED_CODE();

        EnumerateThreadListWithCallbackRoutine(DetectAttachedThreadsProcessCallback, NULL);
}
