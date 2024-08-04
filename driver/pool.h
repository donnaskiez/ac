#ifndef POOL_H
#define POOL_H

#include <ntifs.h>
#include "common.h"

typedef BOOLEAN (*PAGE_CALLBACK)(_In_ UINT64 Page, _In_ UINT32 PageSize, _In_opt_ PVOID Context);

NTSTATUS
PoolScanSystemSpace(_In_ PAGE_CALLBACK Callback, _In_opt_ PVOID Context);

NTSTATUS
PoolScanForManualMappedDrivers();

#endif