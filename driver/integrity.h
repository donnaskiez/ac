#ifndef INTEGRITY_H
#define INTEGRITY_H

#include <ntifs.h>
#include "common.h"

#define SMBIOS_TABLE 'RSMB'
#define SMBIOS_SYSTEM_INFORMATION_TYPE_2_TABLE 2
#define NULL_TERMINATOR '\0'
#define MOTHERBOARD_SERIAL_CODE_TABLE_INDEX 4

/* for testing purposes */
#define VMWARE_SMBIOS_TABLE 1
#define VMWARE_SMBIOS_TABLE_INDEX 3

#define MAX_MODULE_PATH 256

typedef struct _PROCESS_MODULE_INFORMATION
{
	PVOID module_base;
	SIZE_T module_size;
	WCHAR module_path[ MAX_MODULE_PATH ];

}PROCESS_MODULE_INFORMATION, *PPROCESS_MODULE_INFORMATION;

typedef struct _PROCESS_MODULE_VALIDATION_RESULT
{
	INT is_module_valid;

}PROCESS_MODULE_VALIDATION_RESULT, *PPROCESS_MODULE_VALIDATION_RESULT;

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

NTSTATUS ValidateProcessLoadedModule(
	_In_ PIRP Irp
);

#endif
