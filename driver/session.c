#include "session.h"

#include "imports.h"
#include "crypt.h"
#include "util.h"

NTSTATUS
SessionInitialiseStructure()
{
    NTSTATUS        status  = STATUS_UNSUCCESSFUL;
    PACTIVE_SESSION session = GetActiveSession();

    KeInitializeGuardedMutex(&session->lock);

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
    KeAcquireGuardedMutex(&GetActiveSession()->lock);
    *Flag = GetActiveSession()->is_session_active;
    KeReleaseGuardedMutex(&GetActiveSession()->lock);
}

VOID
SessionGetProcess(_Out_ PEPROCESS* Process)
{
    KeAcquireGuardedMutex(&GetActiveSession()->lock);
    *Process = GetActiveSession()->process;
    KeReleaseGuardedMutex(&GetActiveSession()->lock);
}

VOID
SessionGetProcessId(_Out_ PLONG ProcessId)
{
    KeAcquireGuardedMutex(&GetActiveSession()->lock);
    *ProcessId = GetActiveSession()->km_handle;
    KeReleaseGuardedMutex(&GetActiveSession()->lock);
}

VOID
SessionGetCallbackConfiguration(
    _Out_ POB_CALLBACKS_CONFIG* CallbackConfiguration)
{
    KeAcquireGuardedMutex(&GetActiveSession()->lock);
    *CallbackConfiguration = &GetActiveSession()->callback_configuration;
    KeReleaseGuardedMutex(&GetActiveSession()->lock);
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

    KeAcquireGuardedMutex(&session->lock);
    session->km_handle         = NULL;
    session->um_handle         = NULL;
    session->process           = NULL;
    session->is_session_active = FALSE;
    SessionTerminateHeartbeat(&session->heartbeat_config);
    CryptCloseSessionCryptObjects();
    KeReleaseGuardedMutex(&session->lock);
}

/* Return type for this doesnt matter */
STATIC
BOOLEAN
HashOurUserModuleOnEntryCallback(_In_ PPROCESS_MAP_MODULE_ENTRY Entry,
                                 _In_opt_ PVOID                 Context)
{
    NTSTATUS        status  = STATUS_UNSUCCESSFUL;
    PACTIVE_SESSION session = (PACTIVE_SESSION)Context;

    if (!ARGUMENT_PRESENT(Context))
        return FALSE;

    status = HashUserModule(Entry,
                            session->module.module_hash,
                            sizeof(session->module.module_hash));

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("HashUserModule: %lx", status);
        return FALSE;
    }

    DEBUG_VERBOSE("User module hashed!");
    DumpBufferToKernelDebugger(session->module.module_hash,
                               sizeof(session->module.module_hash));

    return TRUE;
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

    status = ValidateIrpInputBuffer(
        Irp, sizeof(SESSION_INITIATION_PACKET) - SHA_256_HASH_LENGTH);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ValidateIrpInputBuffer failed with status %x", status);
        return status;
    }

    initiation = (PSESSION_INITIATION_PACKET)Irp->AssociatedIrp.SystemBuffer;

    KeAcquireGuardedMutex(&session->lock);

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

    session->module.base_address = initiation->module_info.base_address;
    session->module.size         = initiation->module_info.size;

    RtlCopyMemory(
        session->module.path, initiation->module_info.path, MAX_MODULE_PATH);

    DEBUG_VERBOSE("Module base: %llx", session->module.base_address);
    DEBUG_VERBOSE("Module size: %lx ", session->module.size);
    DEBUG_VERBOSE("Module path: %s", session->module.path);

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

    FindOurUserModeModuleEntry(HashOurUserModuleOnEntryCallback, session);

end:
    KeReleaseGuardedMutex(&session->lock);
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
    KeAcquireGuardedMutex(&GetActiveSession()->lock);
    GetActiveSession()->irps_received;
    KeReleaseGuardedMutex(&GetActiveSession()->lock);
}

VOID
SessionIncrementReportCount()
{
    KeAcquireGuardedMutex(&GetActiveSession()->lock);
    GetActiveSession()->report_count++;
    KeReleaseGuardedMutex(&GetActiveSession()->lock);
}

VOID
SessionIncrementHeartbeatCount()
{
    KeAcquireGuardedMutex(&GetActiveSession()->lock);
    GetActiveSession()->heartbeat_count++;
    KeReleaseGuardedMutex(&GetActiveSession()->lock);
}