#ifndef DRIVER_H
#define DRIVER_H

#include <ntifs.h>
#include <wdftypes.h>
#include <wdf.h>

UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING( L"\\Device\\DonnaAC" );
UNICODE_STRING DEVICE_SYMBOLIC_LINK = RTL_CONSTANT_STRING( L"\\??\\DonnaAC" );

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