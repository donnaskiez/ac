#ifndef POOL_H
#define POOL_H

#include <ntifs.h>
#include "common.h"

NTSTATUS
FindUnlinkedProcesses();

VOID
GetPsActiveProcessHead(_Out_ PUINT64 Address);

PKDDEBUGGER_DATA64
GetGlobalDebuggerData();

NTSTATUS
EnumerateBigPoolAllocations();

#endif