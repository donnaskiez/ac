#include "hw.h"

#include "crypt.h"
#include "imports.h"
#include "lib/stdlib.h"
#include "modules.h"

#define PCI_VENDOR_ID_OFFSET 0x00
#define PCI_DEVICE_ID_OFFSET 0x02

#define FLAGGED_DEVICE_ID_COUNT 2

USHORT FLAGGED_DEVICE_IDS[FLAGGED_DEVICE_ID_COUNT] = {
    0x0666, // default PCIe Squirrel DeviceID (used by PCI Leech)
    0xffff};

typedef NTSTATUS (*PCI_DEVICE_CALLBACK)(
    _In_ PDEVICE_OBJECT DeviceObject, _In_opt_ PVOID Context);

/*
 * Every PCI device has a set of registers commonly referred to as the PCI
 * configuration space. In modern PCI-e devices an extended configuration space
 * was implemented. These configuration spaces are mapped into main memory and
 * this allows us to read/write to the registers.
 *
 * The configuration space consists of a standard header, containing information
 * such as the DeviceID, VendorID, Status and so on. Below is the header schema
 * including offsets.
 *
 *  | Offset 0x00: Header Type
 *  | Offset 0x01: Multi-Function Device Indicator
 *  | Offset 0x02: Device ID (Low Byte)
 *  | Offset 0x03: Device ID (High Byte)
 *  | Offset 0x04: Status Register (16 bits)
 *  | Offset 0x06: Command Register (16 bits)
 *  | Offset 0x08: Class Code
 *  | Offset 0x09: Subclass Code
 *  | Offset 0x0A: Prog IF (Programming Interface)
 *  | Offset 0x0B: Revision ID
 *  | Offset 0x0C: BIST (Built-in Self-Test)
 *  | Offset 0x0D: Header Type (Secondary)
 *  | Offset 0x0E: Latency Timer
 *  | Offset 0x0F: Cache Line Size
 *  | Offset 0x10: Base Address Register 0 (BAR0) - 32 bits
 *  | Offset 0x14: Base Address Register 1 (BAR1) - 32 bits
 *  | Offset 0x18: Base Address Register 2 (BAR2) - 32 bits
 *  | Offset 0x1C: Base Address Register 3 (BAR3) - 32 bits
 *  | Offset 0x20: Base Address Register 4 (BAR4) - 32 bits
 *  | Offset 0x24: Base Address Register 5 (BAR5) - 32 bits
 *  | Offset 0x28: Cardbus CIS Pointer (for Cardbus bridges)
 *  | Offset 0x2C: Subsystem Vendor ID
 *  | Offset 0x2E: Subsystem ID
 *  | Offset 0x30: Expansion ROM Base Address
 *  | Offset 0x34: Reserved
 *  | Offset 0x38: Reserved
 *  | Offset 0x3C: Max_Lat (Maximum Latency)
 *  | Offset 0x3D: Min_Gnt (Minimum Grant)
 *  | Offset 0x3E: Interrupt Pin
 *  | Offset 0x3F: Interrupt Line
 *
 * We can use this to then query important information from PCI devices within
 * the device tree. To keep up with modern windows kernel programming, we can
 * make use of the IRP_MN_READ_CONFIG code, which as the name suggests, reads
 * from a PCI devices configuration space.
 */
STATIC
NTSTATUS
QueryPciDeviceConfigurationSpace(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ UINT32 Offset,
    _Out_opt_ PVOID Buffer,
    _In_ UINT32 BufferLength)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    KEVENT event = {0};
    IO_STATUS_BLOCK io = {0};
    PIRP irp = NULL;
    PIO_STACK_LOCATION packet = NULL;

    if (BufferLength == 0)
        return STATUS_BUFFER_TOO_SMALL;

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    /*
     * we dont need to free this IRP as the IO manager will free it when the
     * request is completed
     */
    irp = IoBuildSynchronousFsdRequest(
        IRP_MJ_PNP,
        DeviceObject,
        NULL,
        0,
        NULL,
        &event,
        &io);

    if (!irp) {
        DEBUG_ERROR("IoBuildSynchronousFsdRequest failed with no status.");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    packet = IoGetNextIrpStackLocation(irp);
    packet->MinorFunction = IRP_MN_READ_CONFIG;
    packet->Parameters.ReadWriteConfig.WhichSpace = PCI_WHICHSPACE_CONFIG;
    packet->Parameters.ReadWriteConfig.Offset = Offset;
    packet->Parameters.ReadWriteConfig.Buffer = Buffer;
    packet->Parameters.ReadWriteConfig.Length = BufferLength;

    status = IoCallDriver(DeviceObject, irp);

    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = io.Status;
    }

    if (!NT_SUCCESS(status))
        DEBUG_ERROR(
            "Failed to read configuration space with status %x",
            status);

    return status;
}

/*
 * NOTE: Caller is responsible for freeing the array.
 */
STATIC
NTSTATUS
EnumerateDriverObjectDeviceObjects(
    _In_ PDRIVER_OBJECT DriverObject,
    _Out_ PDEVICE_OBJECT** DeviceObjectArray,
    _Out_ PUINT32 ArrayEntries)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UINT32 object_count = 0;
    PDEVICE_OBJECT* buffer = NULL;
    UINT32 buffer_size = 0;

    *DeviceObjectArray = NULL;
    *ArrayEntries = 0;

    status = IoEnumerateDeviceObjectList(DriverObject, NULL, 0, &object_count);

    if (status != STATUS_BUFFER_TOO_SMALL) {
        DEBUG_ERROR(
            "IoEnumerateDeviceObjectList failed with status %x",
            status);
        return status;
    }

    buffer_size = object_count * sizeof(UINT64);
    buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, buffer_size, POOL_TAG_HW);

    if (!buffer)
        return STATUS_INSUFFICIENT_RESOURCES;

    status = IoEnumerateDeviceObjectList(
        DriverObject,
        buffer,
        buffer_size,
        &object_count);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR(
            "IoEnumerateDeviceObjectList failed with status %x",
            status);
        ExFreePoolWithTag(buffer, POOL_TAG_HW);
        return status;
    }

    DEBUG_VERBOSE(
        "EnumerateDriverObjectDeviceObjects: Object Count: %lx",
        object_count);

    *DeviceObjectArray = buffer;
    *ArrayEntries = object_count;

    return status;
}

/*
 * While this isnt a perfect check to determine whether a DEVICE_OBJECT is
 * indeed a PDO or FDO, this is Peters preferred method... hence it is now my
 * preferred method... :smiling_imp:
 */
STATIC
BOOLEAN
IsDeviceObjectValidPdo(_In_ PDEVICE_OBJECT DeviceObject)
{
    return DeviceObject->Flags & DO_BUS_ENUMERATED_DEVICE ? TRUE : FALSE;
}

/*
 * Windows splits DEVICE_OBJECTS up into 2 categories:
 *
 * Physical Device Object (PDO)
 * Functional Device Object (FDO)
 *
 * A PDO represents each device that is connected to a physical bus. Each PDO
 * has an associated DEVICE_NODE. An FDO represents the functionality of the
 * device. Its how the system interacts with the device objects.
 *
 * More information can be found here:
 * https://learn.microsoft.com/en-gb/windows-hardware/drivers/gettingstarted/device-nodes-and-device-stacks
 *
 * A device stack can have multiple PDO's, but can only have one FDO. This means
 * to access each PCI device on the system, we can enumerate all device objects
 * given the PCI FDO which is called pci.sys.
 */
NTSTATUS
EnumeratePciDeviceObjects(
    _In_ PCI_DEVICE_CALLBACK CallbackRoutine, _In_opt_ PVOID Context)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING pci = RTL_CONSTANT_STRING(L"\\Driver\\pci");
    PDRIVER_OBJECT pci_driver_object = NULL;
    PDEVICE_OBJECT* pci_device_objects = NULL;
    PDEVICE_OBJECT current_device = NULL;
    UINT32 pci_device_objects_count = 0;

    status = GetDriverObjectByDriverName(&pci, &pci_driver_object);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR(
            "GetDriverObjectByDriverName failed with status %x",
            status);
        return status;
    }

    status = EnumerateDriverObjectDeviceObjects(
        pci_driver_object,
        &pci_device_objects,
        &pci_device_objects_count);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR(
            "EnumerateDriverObjectDeviceObjects failed with status %x",
            status);
        return status;
    }

    for (UINT32 index = 0; index < pci_device_objects_count; index++) {
        current_device = pci_device_objects[index];

        /* make sure we have a valid PDO */
        if (!IsDeviceObjectValidPdo(current_device)) {
            ObDereferenceObject(current_device);
            continue;
        }

        status = CallbackRoutine(current_device, Context);

        if (!NT_SUCCESS(status))
            DEBUG_ERROR(
                "EnumeratePciDeviceObjects CallbackRoutine failed with status %x",
                status);

        ObDereferenceObject(current_device);
    }

    if (pci_device_objects)
        ExFreePoolWithTag(pci_device_objects, POOL_TAG_HW);

    return status;
}

BOOLEAN
IsPciConfigurationSpaceFlagged(_In_ PPCI_COMMON_HEADER Configuration)
{
    for (UINT32 index = 0; index < FLAGGED_DEVICE_ID_COUNT; index++) {
        if (Configuration->DeviceID == FLAGGED_DEVICE_IDS[index])
            return TRUE;
    }

    return FALSE;
}

STATIC
VOID
ReportBlacklistedPcieDevice(
    _In_ PDEVICE_OBJECT DeviceObject, _In_ PPCI_COMMON_HEADER Header)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UINT32 len = 0;
    PBLACKLISTED_PCIE_DEVICE_REPORT report = NULL;

    len = CryptRequestRequiredBufferLength(
        sizeof(BLACKLISTED_PCIE_DEVICE_REPORT));
    report = ImpExAllocatePool2(POOL_FLAG_NON_PAGED, len, REPORT_POOL_TAG);

    if (!report)
        return;

    INIT_REPORT_PACKET(report, REPORT_BLACKLISTED_PCIE_DEVICE, 0);

    report->device_object = (UINT64)DeviceObject;
    report->device_id = Header->DeviceID;
    report->vendor_id = Header->VendorID;

    status = CryptEncryptBuffer(report, len);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("CryptEncryptBuffer: %lx", status);
        ImpExFreePoolWithTag(report, len);
        return;
    }

    IrpQueueSchedulePacket(report, len);
}

STATIC
NTSTATUS
PciDeviceQueryCallback(_In_ PDEVICE_OBJECT DeviceObject, _In_opt_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PCI_COMMON_HEADER header = {0};

    status = QueryPciDeviceConfigurationSpace(
        DeviceObject,
        PCI_VENDOR_ID_OFFSET,
        &header,
        sizeof(PCI_COMMON_HEADER));

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR(
            "QueryPciDeviceConfigurationSpace failed with status %x",
            status);
        return status;
    }

    if (IsPciConfigurationSpaceFlagged(&header)) {
        DEBUG_VERBOSE(
            "Flagged DeviceID found. Device: %llx, DeviceId: %lx",
            (UINT64)DeviceObject,
            header.DeviceID);
        ReportBlacklistedPcieDevice(DeviceObject, &header);
    }

    return status;
}

NTSTATUS
ValidatePciDevices()
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    status = EnumeratePciDeviceObjects(PciDeviceQueryCallback, NULL);

    if (!NT_SUCCESS(status))
        DEBUG_ERROR("EnumeratePciDeviceObjects failed with status %x", status);

    return status;
}