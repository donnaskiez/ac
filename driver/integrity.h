#ifndef INTEGRITY_H
#define INTEGRITY_H

#include <ntifs.h>

#include "common.h"

typedef enum _SMBIOS_TABLE_INDEX
{
        SmbiosInformation = 0,
        SystemInformation,
        VendorSpecificInformation,
        ChassisInformation

} SMBIOS_TABLE_INDEX;

#define SMBIOS_VMWARE_SERIAL_NUMBER_SUB_INDEX 3
#define SMBIOS_NATIVE_SERIAL_NUMBER_SUB_INDEX  4
#define SMBIOS_VENDOR_STRING_SUB_INDEX 1

NTSTATUS
GetDriverImageSize(_Inout_ PIRP Irp);

NTSTATUS
VerifyInMemoryImageVsDiskImage(
    //_In_ PIRP Irp
);

NTSTATUS
RetrieveInMemoryModuleExecutableSections(_Inout_ PIRP Irp);

NTSTATUS
ValidateProcessLoadedModule(_Inout_ PIRP Irp);

NTSTATUS
GetHardDiskDriveSerialNumber(_Inout_ PVOID ConfigDrive0Serial, _In_ SIZE_T ConfigDrive0MaxSize);

NTSTATUS
ParseSMBIOSTable(_Out_ PVOID Buffer,
                 _In_ SIZE_T BufferSize,
                 _In_ ULONG  TableIndex,
                 _In_ ULONG  TableSubIndex);

NTSTATUS
DetectEptHooksInKeyFunctions();

PVOID
ScanForSignature(_In_ PVOID  BaseAddress,
                 _In_ SIZE_T MaxLength,
                 _In_ LPCSTR Signature,
                 _In_ SIZE_T SignatureLength);

// NTSTATUS
// DetermineIfTestSigningIsEnabled(
//	_Inout_ PBOOLEAN Result
//);

NTSTATUS
ValidateSystemModules();

NTSTATUS
ValidateNtoskrnl();

NTSTATUS
GetOsVersionInformation(_Out_ PRTL_OSVERSIONINFOW VersionInfo);

#endif
