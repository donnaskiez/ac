#ifndef INTEGRITY_H
#define INTEGRITY_H

#include <ntifs.h>
#include "common.h"

#define IOCTL_STORAGE_QUERY_PROPERTY CTL_CODE(0x0000002d, 0x0500, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define SMBIOS_TABLE 'RSMB'
#define SMBIOS_SYSTEM_INFORMATION_TYPE_2_TABLE 2
#define NULL_TERMINATOR '\0'
#define MOTHERBOARD_SERIAL_CODE_TABLE_INDEX 4

typedef enum _STORAGE_BUS_TYPE {
    BusTypeUnknown = 0x00,
    BusTypeScsi,
    BusTypeAtapi,
    BusTypeAta,
    BusType1394,
    BusTypeSsa,
    BusTypeFibre,
    BusTypeUsb,
    BusTypeRAID,
    BusTypeiScsi,
    BusTypeSas,
    BusTypeSata,
    BusTypeSd,
    BusTypeMmc,
    BusTypeVirtual,
    BusTypeFileBackedVirtual,
    BusTypeSpaces,
    BusTypeNvme,
    BusTypeSCM,
    BusTypeUfs,
    BusTypeMax,
    BusTypeMaxReserved = 0x7F
} STORAGE_BUS_TYPE, * PSTORAGE_BUS_TYPE;

//
// Standard property descriptor header.  All property pages should use this
// as their first element or should contain these two elements
//

typedef struct _STORAGE_DESCRIPTOR_HEADER {

    UINT32 Version;

    UINT32 Size;

} STORAGE_DESCRIPTOR_HEADER, * PSTORAGE_DESCRIPTOR_HEADER;

//
// Device property descriptor - this is really just a rehash of the inquiry
// data retrieved from a scsi device
//
// This may only be retrieved from a target device.  Sending this to the bus
// will result in an error
//

typedef struct _STORAGE_DEVICE_DESCRIPTOR {

    //
    // Sizeof(STORAGE_DEVICE_DESCRIPTOR)
    //

    UINT32 Version;

    //
    // Total size of the descriptor, including the space for additional
    // data and id strings
    //

    UINT32 Size;

    //
    // The SCSI-2 device type
    //

    BYTE  DeviceType;

    //
    // The SCSI-2 device type modifier (if any) - this may be zero
    //

    BYTE  DeviceTypeModifier;

    //
    // Flag indicating whether the device's media (if any) is removable.  This
    // field should be ignored for media-less devices
    //

    BOOLEAN RemovableMedia;

    //
    // Flag indicating whether the device can support mulitple outstanding
    // commands.  The actual synchronization in this case is the responsibility
    // of the port driver.
    //

    BOOLEAN CommandQueueing;

    //
    // Byte offset to the zero-terminated ascii string containing the device's
    // vendor id string.  For devices with no such ID this will be zero
    //

    UINT32 VendorIdOffset;

    //
    // Byte offset to the zero-terminated ascii string containing the device's
    // product id string.  For devices with no such ID this will be zero
    //

    UINT32 ProductIdOffset;

    //
    // Byte offset to the zero-terminated ascii string containing the device's
    // product revision string.  For devices with no such string this will be
    // zero
    //

    UINT32 ProductRevisionOffset;

    //
    // Byte offset to the zero-terminated ascii string containing the device's
    // serial number.  For devices with no serial number this will be zero
    //

    UINT32 SerialNumberOffset;

    //
    // Contains the bus type (as defined above) of the device.  It should be
    // used to interpret the raw device properties at the end of this structure
    // (if any)
    //

    STORAGE_BUS_TYPE BusType;

    //
    // The number of bytes of bus-specific data which have been appended to
    // this descriptor
    //

    UINT32 RawPropertiesLength;

    //
    // Place holder for the first byte of the bus specific property data
    //

    BYTE  RawDeviceProperties[ 1 ];

} STORAGE_DEVICE_DESCRIPTOR, * PSTORAGE_DEVICE_DESCRIPTOR;

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

NTSTATUS QueryDiskDriverForDiskInformation();

#endif
