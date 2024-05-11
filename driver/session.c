#include "session.h"

#include "imports.h"
#include "crypt.h"

NTSTATUS
SessionInitialiseStructure()
{
    NTSTATUS        status  = STATUS_UNSUCCESSFUL;
    PACTIVE_SESSION session = GetActiveSession();

    KeInitializeSpinLock(&session->lock);

    status = CryptInitialiseProvider();

    if (!NT_SUCCESS(status))
        DEBUG_ERROR("CryptInitialiseProvider: %x", status);

    return status;
}

VOID
SessionInitialiseCallbackConfiguration()
{
    InitialiseObCallbacksConfiguration(GetActiveSession());
}

VOID
SessionIsActive(_Out_ PBOOLEAN Flag)
{
    KIRQL irql = KeAcquireSpinLockRaiseToDpc(&GetActiveSession()->lock);
    *Flag      = GetActiveSession()->is_session_active;
    KeReleaseSpinLock(&GetActiveSession()->lock, irql);
}

VOID
SessionGetProcess(_Out_ PEPROCESS* Process)
{
    KIRQL irql = KeAcquireSpinLockRaiseToDpc(&GetActiveSession()->lock);
    *Process   = GetActiveSession()->process;
    KeReleaseSpinLock(&GetActiveSession()->lock, irql);
}

VOID
SessionGetProcessId(_Out_ PLONG ProcessId)
{
    KIRQL irql = KeAcquireSpinLockRaiseToDpc(&GetActiveSession()->lock);
    *ProcessId = GetActiveSession()->km_handle;
    KeReleaseSpinLock(&GetActiveSession()->lock, irql);
}

VOID
SessionGetCallbackConfiguration(
    _Out_ POB_CALLBACKS_CONFIG* CallbackConfiguration)
{
    KIRQL irql = KeAcquireSpinLockRaiseToDpc(&GetActiveSession()->lock);
    *CallbackConfiguration = &GetActiveSession()->callback_configuration;
    KeReleaseSpinLock(&GetActiveSession()->lock, irql);
}

STATIC
VOID
SessionTerminateHeartbeat(_In_ PHEARTBEAT_CONFIGURATION Configuration)
{
    FreeHeartbeatConfiguration(Configuration);
}

VOID
SessionTerminate()
{
    DEBUG_INFO("Termination active session.");

    PACTIVE_SESSION session = GetActiveSession();
    KIRQL           irql    = {0};

    KeAcquireSpinLock(&session->lock, &irql);
    session->km_handle         = NULL;
    session->um_handle         = NULL;
    session->process           = NULL;
    session->is_session_active = FALSE;
    SessionTerminateHeartbeat(&session->heartbeat_config);
    CryptCloseSessionCryptObjects();
    KeReleaseSpinLock(&GetActiveSession()->lock, irql);
}

NTSTATUS
SessionInitialise(_In_ PIRP Irp)
{
    NTSTATUS                   status     = STATUS_UNSUCCESSFUL;
    PEPROCESS                  process    = NULL;
    PSESSION_INITIATION_PACKET initiation = NULL;
    PACTIVE_SESSION            session    = GetActiveSession();
    KIRQL                      irql       = {0};

    DEBUG_VERBOSE("Initialising new session.");

    status = ValidateIrpInputBuffer(Irp, sizeof(SESSION_INITIATION_PACKET));

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ValidateIrpInputBuffer failed with status %x", status);
        return status;
    }

    initiation = (PSESSION_INITIATION_PACKET)Irp->AssociatedIrp.SystemBuffer;

    KeAcquireSpinLock(&session->lock, &irql);

    session->um_handle = initiation->process_id;

    /* What if we pass an invalid handle here? not good. */
    status = ImpPsLookupProcessByProcessId(session->um_handle, &process);

    if (!NT_SUCCESS(status)) {
        status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    session->km_handle         = ImpPsGetProcessId(process);
    session->process           = process;
    session->is_session_active = TRUE;
    session->cookie            = initiation->cookie;

    RtlCopyMemory(session->aes_key, initiation->aes_key, AES_256_KEY_SIZE);
    RtlCopyMemory(session->iv, initiation->aes_iv, AES_256_IV_SIZE);

    status = CryptInitialiseSessionCryptObjects();

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("CryptInitialiseSessionCryptObjects: %x", status);
        goto end;
    }

    status = InitialiseHeartbeatConfiguration(&session->heartbeat_config);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("InitialiseHeartbeatConfiguration %x", status);
        goto end;
    }

end:
    KeReleaseSpinLock(&GetActiveSession()->lock, irql);
    return status;
}

VOID
SessionTerminateProcess()
{
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
    KIRQL irql = KeAcquireSpinLockRaiseToDpc(&GetActiveSession()->lock);
    GetActiveSession()->irps_received;
    KeReleaseSpinLock(&GetActiveSession()->lock, irql);
}

VOID
SessionIncrementReportCount()
{
    KIRQL irql = KeAcquireSpinLockRaiseToDpc(&GetActiveSession()->lock);
    GetActiveSession()->report_count++;
    KeReleaseSpinLock(&GetActiveSession()->lock, irql);
}

VOID
SessionIncrementHeartbeatCount()
{
    KIRQL irql = KeAcquireSpinLockRaiseToDpc(&GetActiveSession()->lock);
    GetActiveSession()->heartbeat_count++;
    KeReleaseSpinLock(&GetActiveSession()->lock, irql);
}