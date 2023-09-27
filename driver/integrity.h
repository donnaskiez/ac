#ifndef INTEGRITY_H
#define INTEGRITY_H

#include <ntifs.h>
#include "common.h"

NTSTATUS 
GetDriverImageSize(
	_In_ PIRP Irp
);

NTSTATUS 
VerifyInMemoryImageVsDiskImage(
    //_In_ PIRP Irp
);

NTSTATUS 
RetrieveInMemoryModuleExecutableSections(
    _In_ PIRP Irp
);

NTSTATUS 
ValidateProcessLoadedModule(
	_In_ PIRP Irp
);

NTSTATUS 
GetHardDiskDriveSerialNumber(
	_In_ PVOID ConfigDrive0Serial,
	_In_ SIZE_T ConfigDrive0MaxSize
);

NTSTATUS
ParseSMBIOSTable(
	_In_ PVOID ConfigMotherboardSerialNumber,
	_In_ SIZE_T ConfigMotherboardSerialNumberMaxSize
);

#endif
