#ifndef INTEGRITY_H
#define INTEGRITY_H

#include <ntifs.h>
#include "common.h"

#define SMBIOS_TABLE 'RSMB'
#define SMBIOS_SYSTEM_INFORMATION_TYPE_2_TABLE 2
#define NULL_TERMINATOR '\0'
#define MOTHERBOARD_SERIAL_CODE_TABLE_INDEX 4

NTSTATUS CopyDriverExecutableRegions(
	_In_ PIRP Irp
);

NTSTATUS GetDriverImageSize(
	_In_ PIRP Irp
);

NTSTATUS VerifyInMemoryImageVsDiskImage(
    //_In_ PIRP Irp
);

NTSTATUS RetrieveInMemoryModuleExecutableSections(
    _In_ PIRP Irp
);

NTSTATUS ParseSMBIOSTable(
	_In_ PVOID ConfigMotherboardSerialNumber,
	_In_ SIZE_T ConfigMotherboardSerialNumberSize
);

#endif
