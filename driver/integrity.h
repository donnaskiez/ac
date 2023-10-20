#ifndef INTEGRITY_H
#define INTEGRITY_H

#include <ntifs.h>
#include "common.h"

NTSTATUS
GetDriverImageSize(
	_Inout_ PIRP Irp
);

NTSTATUS
VerifyInMemoryImageVsDiskImage(
	//_In_ PIRP Irp
);

NTSTATUS
RetrieveInMemoryModuleExecutableSections(
	_Inout_ PIRP Irp
);

NTSTATUS
ValidateProcessLoadedModule(
	_Inout_ PIRP Irp
);

NTSTATUS
GetHardDiskDriveSerialNumber(
	_Inout_ PVOID ConfigDrive0Serial,
	_In_ SIZE_T ConfigDrive0MaxSize
);

NTSTATUS
ParseSMBIOSTable(
	_In_ PVOID ConfigMotherboardSerialNumber,
	_In_ SIZE_T ConfigMotherboardSerialNumberMaxSize
);

NTSTATUS
DetectEptHooksInKeyFunctions();

PVOID
ScanForSignature(
	_In_ PVOID BaseAddress,
	_In_ SIZE_T MaxLength,
	_In_ LPCSTR Signature,
	_In_ SIZE_T SignatureLength
);

//NTSTATUS
//DetermineIfTestSigningIsEnabled(
//	_Inout_ PBOOLEAN Result
//);

NTSTATUS
ValidateSystemModules();

#endif
