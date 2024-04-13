#include "session.h"

#include "imports.h"

/* for now, lets just xor the aes key with our cookie */

typedef struct _SESSION_INITIATION_PACKET {
    UINT32 session_cookie;
    CHAR   session_aes_key[AES_128_KEY_SIZE];
    PVOID  protected_process_id;

} SESSION_INITIATION_PACKET, *PSESSION_INITIATION_PACKET;

VOID
SessionInitialiseStructure()
{
    PAGED_CODE();
    ImpKeInitializeGuardedMutex(&GetActiveSession()->lock);
}

VOID
SessionInitialiseCallbackConfiguration()
{
    PAGED_CODE();
    InitialiseObCallbacksConfiguration(GetActiveSession());
}

VOID
SessionIsActive(_Out_ PBOOLEAN Flag)
{
    PAGED_CODE();
    ImpKeAcquireGuardedMutex(&GetActiveSession()->lock);
    *Flag = GetActiveSession()->is_session_active;
    ImpKeReleaseGuardedMutex(&GetActiveSession()->lock);
}

VOID
SessionGetProcess(_Out_ PEPROCESS* Process)
{
    PAGED_CODE();
    ImpKeAcquireGuardedMutex(&GetActiveSession()->lock);
    *Process = GetActiveSession()->process;
    ImpKeReleaseGuardedMutex(&GetActiveSession()->lock);
}

VOID
SessionGetProcessId(_Out_ PLONG ProcessId)
{
    PAGED_CODE();
    ImpKeAcquireGuardedMutex(&GetActiveSession()->lock);
    *ProcessId = GetActiveSession()->km_handle;
    ImpKeReleaseGuardedMutex(&GetActiveSession()->lock);
}

VOID
SessionGetCallbackConfiguration(
    _Out_ POB_CALLBACKS_CONFIG* CallbackConfiguration)
{
    ImpKeAcquireGuardedMutex(&GetActiveSession()->lock);
    *CallbackConfiguration = &GetActiveSession()->callback_configuration;
    ImpKeReleaseGuardedMutex(&GetActiveSession()->lock);
}

VOID
SessionTerminate()
{
    PAGED_CODE();
    DEBUG_INFO("Termination active session.");

    PACTIVE_SESSION session = GetActiveSession();

    ImpKeAcquireGuardedMutex(&session->lock);
    session->km_handle         = NULL;
    session->um_handle         = NULL;
    session->process           = NULL;
    session->is_session_active = FALSE;
    ImpKeReleaseGuardedMutex(&session->lock);
}

NTSTATUS
SessionInitialise(_In_ PIRP Irp)
{
    PAGED_CODE();

    NTSTATUS                   status      = STATUS_UNSUCCESSFUL;
    PEPROCESS                  process     = NULL;
    PSESSION_INITIATION_PACKET information = NULL;
    PACTIVE_SESSION            session     = GetActiveSession();

    DEBUG_VERBOSE("Initialising new session.");

    status = ValidateIrpInputBuffer(Irp, sizeof(SESSION_INITIATION_PACKET));

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ValidateIrpInputBuffer failed with status %x", status);
        return status;
    }

    information = (PSESSION_INITIATION_PACKET)Irp->AssociatedIrp.SystemBuffer;

    ImpKeAcquireGuardedMutex(&session->lock);

    session->um_handle = information->protected_process_id;

    /* What if we pass an invalid handle here? not good. */
    status = ImpPsLookupProcessByProcessId(session->um_handle, &process);

    if (!NT_SUCCESS(status)) {
        status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    session->km_handle         = ImpPsGetProcessId(process);
    session->process           = process;
    session->is_session_active = TRUE;
    session->session_cookie    = information->session_cookie;

    RtlCopyMemory(session->session_aes_key,
                  information->session_aes_key,
                  AES_128_KEY_SIZE);

end:
    ImpKeReleaseGuardedMutex(&session->lock);
    return status;
}

VOID
SessionTerminateProcess()
{
    PAGED_CODE();

    NTSTATUS status     = STATUS_UNSUCCESSFUL;
    ULONG    process_id = 0;

    SessionGetProcessId(&process_id);

    if (!process_id) {
        DEBUG_ERROR("Failed to terminate process as process id is null");
        return;
    }

    /* Make sure we pass a km handle to ZwTerminateProcess and NOT a
     * usermode handle. */
    status = ZwTerminateProcess(process_id,
                                STATUS_SYSTEM_INTEGRITY_POLICY_VIOLATION);

    if (!NT_SUCCESS(status)) {
        /*
         * We don't want to clear the process config if
         * ZwTerminateProcess fails so we can try again.
         */
        DEBUG_ERROR("ZwTerminateProcess failed with status %x", status);
        return;
    }
    /* this wont be needed when procloadstuff is implemented */
    SessionTerminate();
}

VOID
SessionIncrementIrpsProcessedCount()
{
    ImpKeAcquireGuardedMutex(&GetActiveSession()->lock);
    GetActiveSession()->irps_processed++;
    ImpKeReleaseGuardedMutex(&GetActiveSession()->lock);
}

VOID
SessionIncrementReportCount()
{
    ImpKeAcquireGuardedMutex(&GetActiveSession()->lock);
    GetActiveSession()->report_count++;
    ImpKeReleaseGuardedMutex(&GetActiveSession()->lock);
}

VOID
SessionIncrementHeartbeatCount()
{
    ImpKeAcquireGuardedMutex(&GetActiveSession()->lock);
    GetActiveSession()->heartbeat_count++;
    ImpKeReleaseGuardedMutex(&GetActiveSession()->lock);
}