#ifndef DRIVER_H
#define DRIVER_H

#include <ntifs.h>
#include <wdftypes.h>
#include <wdf.h>

VOID UpdateProtectedProcessId(
	_In_ LONG NewProcessId 
);

VOID GetProtectedProcessId(
	_Out_ PLONG ProcessId
);

VOID GetProtectedProcessParentId(
	_Out_ PLONG ProcessId
);

VOID UpdateProtectedProcessParentId(
	_In_ LONG NewProcessId
);

#endif