#ifndef SESSION_H
#define SESSION_H

#include "common.h"

#include "driver.h"

VOID
SessionInitialiseStructure();

VOID
SessionInitialiseCallbackConfiguration();

VOID
SessionIsActive(_Out_ PBOOLEAN Flag);

VOID
SessionGetProcess(_Out_ PEPROCESS* Process);

VOID
SessionGetProcessId(_Out_ PLONG ProcessId);

VOID
SessionGetCallbackConfiguration(_Out_ POB_CALLBACKS_CONFIG* CallbackConfiguration);

VOID
SessionTerminate();

NTSTATUS
SessionInitialise(_In_ PIRP Irp);

VOID
SessionTerminateProcess();

#endif