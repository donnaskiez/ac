#include "integrity.h"

#include "common.h"
#include "driver.h"
#include "modules.h"
#include "callbacks.h"
#include "io.h"
#include "imports.h"
#include "session.h"
#include "util.h"
#include "pe.h"
#include "crypt.h"

#include <bcrypt.h>
#include <initguid.h>
#include <devpkey.h>

typedef struct _INTEGRITY_CHECK_HEADER {
    INT  executable_section_count;
    LONG total_packet_size;

} INTEGRITY_CHECK_HEADER, *PINTEGRITY_CHECK_HEADER;

typedef struct _PROCESS_MODULE_INFORMATION {
    PVOID  module_base;
    SIZE_T module_size;
    WCHAR  module_path[MAX_MODULE_PATH];

} PROCESS_MODULE_INFORMATION, *PPROCESS_MODULE_INFORMATION;

typedef struct _PROCESS_MODULE_VALIDATION_RESULT {
    INT is_module_valid;

} PROCESS_MODULE_VALIDATION_RESULT, *PPROCESS_MODULE_VALIDATION_RESULT;

STATIC
NTSTATUS
InitiateEptFunctionAddressArrays();

STATIC
NTSTATUS
GetModuleInformationByName(_Out_ PRTL_MODULE_EXTENDED_INFO ModuleInfo,
                           _In_ LPCSTR                     ModuleName);

STATIC
NTSTATUS
StoreModuleExecutableRegionsInBuffer(_Out_ PVOID*  Buffer,
                                     _In_ PVOID    ModuleBase,
                                     _In_ SIZE_T   ModuleSize,
                                     _Out_ PSIZE_T BytesWritten,
                                     _In_ BOOLEAN  IsModulex86);

STATIC
NTSTATUS
MapDiskImageIntoVirtualAddressSpace(_Inout_ PHANDLE      SectionHandle,
                                    _Out_ PVOID*         Section,
                                    _In_ PUNICODE_STRING Path,
                                    _Out_ PSIZE_T        Size);

STATIC
NTSTATUS
ComputeHashOfBuffer(_In_ PVOID   Buffer,
                    _In_ ULONG   BufferSize,
                    _Out_ PVOID* HashResult,
                    _Out_ PULONG HashResultSize);

STATIC
VOID
GetNextSMBIOSStructureInTable(_Inout_ PSMBIOS_TABLE_HEADER* CurrentStructure);

STATIC
NTSTATUS
GetStringAtIndexFromSMBIOSTable(_In_ PSMBIOS_TABLE_HEADER Table,
                                _In_ INT                  Index,
                                _In_ PVOID                Buffer,
                                _In_ SIZE_T               BufferSize);

STATIC
NTSTATUS
GetAverageReadTimeAtRoutine(_In_ PVOID    RoutineAddress,
                            _Out_ PUINT64 AverageTime);

STATIC
VOID
HeartbeatDpcRoutine(_In_ PKDPC     Dpc,
                    _In_opt_ PVOID DeferredContext,
                    _In_opt_ PVOID SystemArgument1,
                    _In_opt_ PVOID SystemArgument2);

#ifdef ALLOC_PRAGMA
#    pragma alloc_text(PAGE, GetDriverImageSize)
#    pragma alloc_text(PAGE, GetModuleInformationByName)
#    pragma alloc_text(PAGE, StoreModuleExecutableRegionsInBuffer)
#    pragma alloc_text(PAGE, MapDiskImageIntoVirtualAddressSpace)
#    pragma alloc_text(PAGE, ComputeHashOfBuffer)
// #        pragma alloc_text(PAGE, VerifyInMemoryImageVsDiskImage)
#    pragma alloc_text(PAGE, RetrieveInMemoryModuleExecutableSections)
#    pragma alloc_text(PAGE, GetNextSMBIOSStructureInTable)
#    pragma alloc_text(PAGE, GetStringAtIndexFromSMBIOSTable)
#    pragma alloc_text(PAGE, ParseSMBIOSTable)
#    pragma alloc_text(PAGE, ValidateProcessLoadedModule)
#    pragma alloc_text(PAGE, GetHardDiskDriveSerialNumber)
#    pragma alloc_text(PAGE, ScanForSignature)
#    pragma alloc_text(PAGE, InitiateEptFunctionAddressArrays)
#    pragma alloc_text(PAGE, DetectEptHooksInKeyFunctions)
// #pragma alloc_text(PAGE, DetermineIfTestSigningIsEnabled)
#endif

/*
 * note: this can be put into its own function wihtout an IRP as argument then
 * it can be used in both the get driver image ioctl handler and the
 * CopyDriverExecvutableRegions func
 */
NTSTATUS
GetDriverImageSize(_Inout_ PIRP Irp)
{
    PAGED_CODE();

    NTSTATUS                  status      = STATUS_UNSUCCESSFUL;
    LPCSTR                    driver_name = GetDriverName();
    SYSTEM_MODULES            modules     = {0};
    PRTL_MODULE_EXTENDED_INFO driver_info = NULL;

    status = GetSystemModuleInformation(&modules);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("GetSystemModuleInformation failed with status %x", status);
        return status;
    }

    driver_info = FindSystemModuleByName(driver_name, &modules);

    if (!driver_info) {
        DEBUG_ERROR("FindSystemModuleByName failed with no status code");
        ImpExFreePoolWithTag(modules.address, SYSTEM_MODULES_POOL);
        return STATUS_NOT_FOUND;
    }

    status = ValidateIrpOutputBuffer(Irp, sizeof(ULONG));

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ValidateIrpOutputBuffer failed with status %x", status);
        goto end;
    }

    Irp->IoStatus.Information = sizeof(ULONG);
    RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer,
                  &driver_info->ImageSize,
                  sizeof(ULONG));

end:

    if (modules.address)
        ImpExFreePoolWithTag(modules.address, SYSTEM_MODULES_POOL);

    return status;
}

STATIC
NTSTATUS
GetModuleInformationByName(_Out_ PRTL_MODULE_EXTENDED_INFO ModuleInfo,
                           _In_ LPCSTR                     ModuleName)
{
    PAGED_CODE();

    NTSTATUS                  status      = STATUS_UNSUCCESSFUL;
    LPCSTR                    driver_name = GetDriverName();
    SYSTEM_MODULES            modules     = {0};
    PRTL_MODULE_EXTENDED_INFO driver_info = NULL;

    status = GetSystemModuleInformation(&modules);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("GetSystemModuleInformation failed with status %x", status);
        return status;
    }

    /* TODO: think this remains from testing, we only use this to find our
     * driver anyway but should be fixed. */
    driver_info = FindSystemModuleByName(driver_name, &modules);

    if (!driver_info) {
        DEBUG_ERROR("FindSystemModuleByName failed with no status");
        ImpExFreePoolWithTag(modules.address, SYSTEM_MODULES_POOL);
        return STATUS_NOT_FOUND;
    }

    ModuleInfo->FileNameOffset = driver_info->FileNameOffset;
    ModuleInfo->ImageBase      = driver_info->ImageBase;
    ModuleInfo->ImageSize      = driver_info->ImageSize;

    RtlCopyMemory(ModuleInfo->FullPathName,
                  driver_info->FullPathName,
                  sizeof(ModuleInfo->FullPathName));

    if (modules.address)
        ImpExFreePoolWithTag(modules.address, SYSTEM_MODULES_POOL);

    return status;
}

#define PE_TYPE_32_BIT 0x10b

FORCEINLINE
STATIC
BOOLEAN
IsSectionExecutable(_In_ PIMAGE_SECTION_HEADER Section)
{
    return Section->Characteristics & IMAGE_SCN_MEM_EXECUTE ? TRUE : FALSE;
}

FORCEINLINE
STATIC
BOOLEAN
IsModuleAddressSafe(_In_ PVOID Base, _In_ BOOLEAN x86)
{
    return !MmIsAddressValid(Base) && !x86 ? FALSE : TRUE;
}

FORCEINLINE
STATIC
UINT32
GetSectionTotalPacketSize(_In_ PIMAGE_SECTION_HEADER Section)
{
    return Section->SizeOfRawData + sizeof(IMAGE_SECTION_HEADER);
}

FORCEINLINE
STATIC
VOID
InitIntegrityCheckHeader(_Out_ PINTEGRITY_CHECK_HEADER Header,
                         _In_ UINT32                   SectionCount,
                         _In_ UINT32                   TotalSize)
{
    Header->executable_section_count = SectionCount;
    Header->total_packet_size = TotalSize + sizeof(INTEGRITY_CHECK_HEADER);
}

STATIC
NTSTATUS
StoreModuleExecutableRegionsInBuffer(_Out_ PVOID*  Buffer,
                                     _In_ PVOID    ModuleBase,
                                     _In_ SIZE_T   ModuleSize,
                                     _Out_ PSIZE_T BytesWritten,
                                     _In_ BOOLEAN  IsModulex86)
{
    PAGED_CODE();

    NTSTATUS               status                  = STATUS_UNSUCCESSFUL;
    PNT_HEADER_64          nt_header               = NULL;
    PIMAGE_SECTION_HEADER  section                 = NULL;
    ULONG                  total_packet_size       = 0;
    ULONG                  num_sections            = 0;
    ULONG                  num_executable_sections = 0;
    UINT64                 buffer_base             = 0;
    ULONG                  bytes_returned          = 0;
    MM_COPY_ADDRESS        address                 = {0};
    INTEGRITY_CHECK_HEADER header                  = {0};

    // DEBUG_VERBOSE("Storing x regions -> x86 module: %lx",
    // (UINT32)IsModulex86); DEBUG_VERBOSE("MmIsAddressValid: %lx",
    // MmIsAddressValid(ModuleBase));

    if (!ModuleBase || !ModuleSize)
        return STATUS_INVALID_PARAMETER;

    if (!IsModuleAddressSafe(ModuleBase, IsModulex86))
        return STATUS_UNSUCCESSFUL;

    /*
     * The reason we allocate a buffer to temporarily hold the section data
     * is that we don't know the total size until after we iterate over the
     * sections meaning we cant set Irp->IoStatus.Information to the size of
     * our reponse until we enumerate and count all executable sections for
     * the file.
     */
    *BytesWritten = 0;
    *Buffer       = ImpExAllocatePool2(POOL_FLAG_NON_PAGED,
                                 ModuleSize + sizeof(INTEGRITY_CHECK_HEADER),
                                 POOL_TAG_INTEGRITY);

    if (*Buffer == NULL)
        return STATUS_MEMORY_NOT_ALLOCATED;

    /* For context, when we are hashing x86 modules, MmIsAddressValid will
     * return FALSE. Yet we still need protection for when an invalid address is
     * passed for a non-x86 based image.*/

    /*
     * The IMAGE_DOS_HEADER.e_lfanew stores the offset of the
     * IMAGE_NT_HEADER from the base of the image.
     */
    nt_header    = PeGetNtHeader(ModuleBase);
    num_sections = GetSectionCount(nt_header);

    /*
     * The IMAGE_FIRST_SECTION macro takes in an IMAGE_NT_HEADER and returns
     * the address of the first section of the PE file.
     */
    section     = IMAGE_FIRST_SECTION(nt_header);
    buffer_base = (UINT64)*Buffer + sizeof(INTEGRITY_CHECK_HEADER);

    for (ULONG index = 0; index < num_sections - 1; index++) {
        if (!IsSectionExecutable(section)) {
            section++;
            continue;
        }

        address.VirtualAddress = section;
        status = ImpMmCopyMemory((UINT64)buffer_base + total_packet_size,
                                 address,
                                 sizeof(IMAGE_SECTION_HEADER),
                                 MM_COPY_MEMORY_VIRTUAL,
                                 &bytes_returned);

        if (!NT_SUCCESS(status)) {
            ImpExFreePoolWithTag(*Buffer, POOL_TAG_INTEGRITY);
            *Buffer = NULL;
            return status;
        }

        address.VirtualAddress = (UINT64)ModuleBase + section->PointerToRawData;
        status = ImpMmCopyMemory((UINT64)buffer_base + total_packet_size +
                                     sizeof(IMAGE_SECTION_HEADER),
                                 address,
                                 section->SizeOfRawData,
                                 MM_COPY_MEMORY_VIRTUAL,
                                 &bytes_returned);

        if (!NT_SUCCESS(status)) {
            ImpExFreePoolWithTag(*Buffer, POOL_TAG_INTEGRITY);
            *Buffer = NULL;
            return status;
        }

        total_packet_size += GetSectionTotalPacketSize(section);
        num_executable_sections++;
        section++;
    }

    InitIntegrityCheckHeader(
        &header, num_executable_sections, total_packet_size);

    RtlCopyMemory(*Buffer, &header, sizeof(INTEGRITY_CHECK_HEADER));
    *BytesWritten = total_packet_size + sizeof(INTEGRITY_CHECK_HEADER);
    return status;
}

STATIC
NTSTATUS
MapDiskImageIntoVirtualAddressSpace(_Inout_ PHANDLE      SectionHandle,
                                    _Out_ PVOID*         Section,
                                    _In_ PUNICODE_STRING Path,
                                    _Out_ PSIZE_T        Size)
{
    PAGED_CODE();

    NTSTATUS          status            = STATUS_UNSUCCESSFUL;
    HANDLE            file_handle       = NULL;
    OBJECT_ATTRIBUTES object_attributes = {0};
    PIO_STATUS_BLOCK  pio_block         = NULL;
    UNICODE_STRING    path              = {0};

    *Section = NULL;
    *Size    = 0;

    ImpRtlInitUnicodeString(&path, Path->Buffer);

    InitializeObjectAttributes(
        &object_attributes, &path, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ImpZwOpenFile(
        &file_handle, GENERIC_READ, &object_attributes, &pio_block, NULL, NULL);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ZwOpenFile failed with status %x", status);
        return status;
    }

    object_attributes.ObjectName = NULL;

    /*
     * Its important that we set the SEC_IMAGE flag with the PAGE_READONLY
     * flag as we are mapping an executable image.
     */
    status = ImpZwCreateSection(SectionHandle,
                                SECTION_ALL_ACCESS,
                                &object_attributes,
                                NULL,
                                PAGE_READONLY,
                                SEC_IMAGE,
                                file_handle);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ZwCreateSection failed with status %x", status);
        ImpZwClose(file_handle);
        *SectionHandle = NULL;
        return status;
    }

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ObReferenceObjectByHandle failed with status %x", status);
        return status;
    }
    /*
     * Mapping a section with the flag SEC_IMAGE (see function above) tells
     * the os we are mapping an executable image. This then allows the OS to
     * take care of parsing the PE header and dealing with all relocations
     * for us, meaning the mapped image will be identical to the in memory
     * image.
     */
    status = ImpZwMapViewOfSection(*SectionHandle,
                                   ZwCurrentProcess(),
                                   Section,
                                   NULL,
                                   NULL,
                                   NULL,
                                   Size,
                                   ViewUnmap,
                                   MEM_TOP_DOWN,
                                   PAGE_READONLY);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ZwMapViewOfSection failed with status %x", status);
        ImpZwClose(file_handle);
        ImpZwClose(*SectionHandle);
        *SectionHandle = NULL;
        return status;
    }

    ImpZwClose(file_handle);
    return status;
}

STATIC
NTSTATUS
ComputeHashOfBuffer(_In_ PVOID   Buffer,
                    _In_ ULONG   BufferSize,
                    _Out_ PVOID* HashResult,
                    _Out_ PULONG HashResultSize)
{
    PAGED_CODE();

    NTSTATUS           status              = STATUS_UNSUCCESSFUL;
    BCRYPT_ALG_HANDLE* algo_handle         = GetCryptHandle_Sha256();
    BCRYPT_HASH_HANDLE hash_handle         = NULL;
    ULONG              bytes_copied        = 0;
    ULONG              resulting_hash_size = 0;
    ULONG              hash_object_size    = 0;
    PCHAR              hash_object         = NULL;
    PCHAR              resulting_hash      = NULL;

    *HashResult     = NULL;
    *HashResultSize = 0;

    /*
     * Request the size of the hash object buffer, this is different then
     * the buffer that will store the resulting hash, instead this will be
     * used to store the hash object used to create the hash.
     */
    status = BCryptGetProperty(*algo_handle,
                               BCRYPT_OBJECT_LENGTH,
                               (PCHAR)&hash_object_size,
                               sizeof(ULONG),
                               &bytes_copied,
                               NULL);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("BCryptGetProperty failed with status %x", status);
        goto end;
    }

    hash_object = ImpExAllocatePool2(
        POOL_FLAG_NON_PAGED, hash_object_size, POOL_TAG_INTEGRITY);

    if (!hash_object) {
        status = STATUS_MEMORY_NOT_ALLOCATED;
        goto end;
    }

    /*
     * This call gets the size of the resulting hash, which we will use to
     * allocate the resulting hash buffer.
     */
    status = BCryptGetProperty(*algo_handle,
                               BCRYPT_HASH_LENGTH,
                               (PCHAR)&resulting_hash_size,
                               sizeof(ULONG),
                               &bytes_copied,
                               NULL);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("BCryptGetProperty failed with status %x", status);
        goto end;
    }

    resulting_hash = ImpExAllocatePool2(
        POOL_FLAG_NON_PAGED, resulting_hash_size, POOL_TAG_INTEGRITY);

    if (!resulting_hash) {
        status = STATUS_MEMORY_NOT_ALLOCATED;
        goto end;
    }

    /*
     * Here we create our hash object and store it in the hash_object
     * buffer.
     */
    status = BCryptCreateHash(*algo_handle,
                              &hash_handle,
                              hash_object,
                              hash_object_size,
                              NULL,
                              NULL,
                              NULL);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("BCryptCreateHash failed with status %x", status);
        goto end;
    }

    /*
     * This function hashes the buffer, but does NOT store it in our
     * resulting buffer yet, we need to call BCryptFinishHash to retrieve
     * the final hash.
     */
    status = BCryptHashData(hash_handle, Buffer, BufferSize, NULL);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("BCryptHashData failed with status %x", status);
        goto end;
    }

    /*
     * As said in the previous comment, this is where we retrieve the final
     * hash and store it in our output buffer.
     */
    status = BCryptFinishHash(
        hash_handle, resulting_hash, resulting_hash_size, NULL);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("BCryptFinishHash failed with status %x", status);
        goto end;
    }

    *HashResult     = resulting_hash;
    *HashResultSize = resulting_hash_size;

end:

    if (hash_handle)
        BCryptDestroyHash(hash_handle);

    if (hash_object)
        ImpExFreePoolWithTag(hash_object, POOL_TAG_INTEGRITY);

    return status;
}

NTSTATUS
RetrieveInMemoryModuleExecutableSections(_Inout_ PIRP Irp)
{
    PAGED_CODE();

    NTSTATUS                 status        = STATUS_UNSUCCESSFUL;
    SIZE_T                   bytes_written = NULL;
    PVOID                    buffer        = NULL;
    RTL_MODULE_EXTENDED_INFO module_info   = {0};
    LPCSTR                   driver_name   = GetDriverName();

    status = GetModuleInformationByName(&module_info, driver_name);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("GetModuleInformationByName failed with status %x", status);
        return status;
    }

    status = StoreModuleExecutableRegionsInBuffer(&buffer,
                                                  module_info.ImageBase,
                                                  module_info.ImageSize,
                                                  &bytes_written,
                                                  FALSE);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("StoreModuleExecutableRegionsInBuffe failed with status %x",
                    status);
        return status;
    }

    status = ValidateIrpOutputBuffer(Irp, bytes_written);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ValidateIrpOutputBuffer failed with status %x", status);
        goto end;
    }

    Irp->IoStatus.Information = bytes_written;
    RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, buffer, bytes_written);

end:
    if (buffer)
        ImpExFreePoolWithTag(buffer, POOL_TAG_INTEGRITY);

    return status;
}
#define SMBIOS_TABLE    'RSMB'
#define NULL_TERMINATOR '\0'
/*
 * From line 727 in the SMBIOS Specification:
 *
 *    727 • Each structure shall be terminated by a double-null (0000h), either
 * directly following the 728   formatted area (if no strings are present) or
 * directly following the last string. This includes 729   system- and
 * OEM-specific structures and allows upper-level software to easily traverse
 * the 730   structure table. (See structure-termination examples later in this
 * clause.)
 *
 * TLDR is that if the first two characters proceeding the structure are null
 * terminators, then there are no strings, otherwise to find the end of the
 * string section simply iterate until there is a double null terminator.
 *
 * source:
 * https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_2.7.1.pdf
 */
STATIC
VOID
GetNextSMBIOSStructureInTable(_Inout_ PSMBIOS_TABLE_HEADER* CurrentStructure)
{
    PAGED_CODE();

    PCHAR string_section_start =
        (PCHAR)((UINT64)*CurrentStructure + (*CurrentStructure)->Length);

    PCHAR current_char_in_strings = string_section_start;
    PCHAR next_char_in_strings    = string_section_start + 1;

    for (;;) {
        if (*current_char_in_strings == NULL_TERMINATOR &&
            *next_char_in_strings == NULL_TERMINATOR) {
            *CurrentStructure =
                (PSMBIOS_TABLE_HEADER)(next_char_in_strings + 1);
            return;
        }

        current_char_in_strings++;
        next_char_in_strings++;
    }
}

/*
 * Remember that the string index does not start from the beginning of the
 * struct. For example, lets take RAW_SMBIOS_TABLE_02: the first string is NOT
 * "Type" at index 0, the first string is Manufacturer. So if we want to find
 * the SerialNumber, the string index would be 4, as the previous 3 values
 * (after the header) are all strings. So remember, the index is into the number
 * of strings that exist for the given table, NOT the size of the structure or a
 * values index into the struct.
 *
 * Here we count the number of strings by incrementing the string_count each
 * time we pass a null terminator so we know when we're at the beginning of the
 * target string.
 */
STATIC
NTSTATUS
GetStringAtIndexFromSMBIOSTable(_In_ PSMBIOS_TABLE_HEADER Table,
                                _In_ INT                  Index,
                                _In_ PVOID                Buffer,
                                _In_ SIZE_T               BufferSize)
{
    PAGED_CODE();

    INT   current_string_char_index = 0;
    INT   string_count              = 0;
    PCHAR current_string_char       = (PCHAR)((UINT64)Table + Table->Length);
    PCHAR next_string_char          = current_string_char + 1;

    for (;;) {
        if (*current_string_char == NULL_TERMINATOR &&
            *next_string_char == NULL_TERMINATOR)
            return STATUS_NOT_FOUND;

        if (current_string_char_index >= BufferSize)
            return STATUS_BUFFER_TOO_SMALL;

        if (string_count + 1 == Index) {
            if (*current_string_char == NULL_TERMINATOR)
                return STATUS_SUCCESS;

            UINT64 dest = (UINT64)Buffer + current_string_char_index;

            RtlCopyMemory(dest, current_string_char, sizeof(CHAR));
            current_string_char_index++;
            goto increment;
        }

        if (*current_string_char == NULL_TERMINATOR) {
            current_string_char_index = 0;
            string_count++;
        }

    increment:
        current_string_char++;
        next_string_char++;
    }

    return STATUS_NOT_FOUND;
}

FORCEINLINE
STATIC
PRAW_SMBIOS_DATA
GetRawSmbiosData(_In_ PVOID FirmwareTable)
{
    return (PRAW_SMBIOS_DATA)FirmwareTable;
}

FORCEINLINE
STATIC
PSMBIOS_TABLE_HEADER
GetSmbiosTableHeader(_In_ PRAW_SMBIOS_DATA Data)
{
    return (PSMBIOS_TABLE_HEADER)(&Data->SMBIOSTableData[0]);
}

NTSTATUS
ParseSMBIOSTable(_Out_ PVOID             Buffer,
                 _In_ SIZE_T             BufferSize,
                 _In_ SMBIOS_TABLE_INDEX TableIndex,
                 _In_ ULONG              TableSubIndex)
{
    PAGED_CODE();

    NTSTATUS             status                       = STATUS_UNSUCCESSFUL;
    PVOID                firmware_table_buffer        = NULL;
    ULONG                firmware_table_buffer_size   = 0;
    ULONG                bytes_returned               = 0;
    PRAW_SMBIOS_DATA     smbios_data                  = NULL;
    PSMBIOS_TABLE_HEADER smbios_table_header          = NULL;
    PRAW_SMBIOS_TABLE_01 smbios_baseboard_information = NULL;

    status = ImpExGetSystemFirmwareTable(
        SMBIOS_TABLE, 0, NULL, 0, &firmware_table_buffer_size);

    /*
     * Because we pass a null buffer here, the NTSTATUS result will be a
     * BUFFER_TOO_SMALL error, so to validate this function call we check
     * the return bytes returned (which indicate required buffer size) is
     * above 0.
     */
    if (firmware_table_buffer_size == NULL) {
        DEBUG_ERROR(
            "ExGetSystemFirmwareTable call 1 failed to get required buffer size.");
        return STATUS_BUFFER_TOO_SMALL;
    }

    firmware_table_buffer = ImpExAllocatePool2(
        POOL_FLAG_NON_PAGED, firmware_table_buffer_size, POOL_TAG_INTEGRITY);

    if (!firmware_table_buffer)
        return STATUS_MEMORY_NOT_ALLOCATED;

    status = ImpExGetSystemFirmwareTable(SMBIOS_TABLE,
                                         NULL,
                                         firmware_table_buffer,
                                         firmware_table_buffer_size,
                                         &bytes_returned);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ExGetSystemFirmwareTable call 2 failed with status %x",
                    status);
        goto end;
    }

    smbios_data         = GetRawSmbiosData(firmware_table_buffer);
    smbios_table_header = GetSmbiosTableHeader(smbios_data);

    /*
     * The System Information table is equal to Type == 2 and contains the
     * serial number of the motherboard in the computer among various other
     * things.
     *
     * source:
     * https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_2.7.1.pdf
     * line 823
     */
    while (smbios_table_header->Type != TableIndex)
        GetNextSMBIOSStructureInTable(&smbios_table_header);

    status = GetStringAtIndexFromSMBIOSTable(
        smbios_table_header, TableSubIndex, Buffer, BufferSize);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("GetStringAtIndexFromSMBIOSTable failed with status %x",
                    status);
        goto end;
    }

end:

    if (firmware_table_buffer)
        ImpExFreePoolWithTag(firmware_table_buffer, POOL_TAG_INTEGRITY);

    return status;
}

STATIC
NTSTATUS
ComputeHashOfSections(_In_ PIMAGE_SECTION_HEADER DiskSection,
                      _In_ PIMAGE_SECTION_HEADER MemorySection,
                      _Out_ PVOID*               DiskHash,
                      _Out_ PULONG               DiskHashSize,
                      _Out_ PVOID*               MemoryHash,
                      _Out_ PULONG               MemoryHashSize)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (DiskSection->SizeOfRawData != MemorySection->SizeOfRawData) {
        DEBUG_WARNING("Executable section sizes differ between images.");
        return STATUS_INVALID_BUFFER_SIZE;
    }

    status =
        ComputeHashOfBuffer((UINT64)DiskSection + sizeof(IMAGE_SECTION_HEADER),
                            DiskSection->SizeOfRawData,
                            DiskHash,
                            DiskHashSize);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ComputeHashOfBuffer failed with status %x", status);
        return status;
    }

    status = ComputeHashOfBuffer((UINT64)MemorySection +
                                     sizeof(IMAGE_SECTION_HEADER),
                                 MemorySection->SizeOfRawData,
                                 MemoryHash,
                                 MemoryHashSize);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ComputeHashOfBuffer 2 failed with status %x", status);
        return status;
    }

    return status;
}

FORCEINLINE
STATIC
BOOLEAN
CompareHashes(_In_ PVOID Hash1, _In_ PVOID Hash2, _In_ UINT32 Length)
{
    return RtlCompareMemory(Hash1, Hash2, Length) == Length ? TRUE : FALSE;
}

typedef struct _VAL_INTEGRITY_HEADER {
    INTEGRITY_CHECK_HEADER integrity_check_header;
    IMAGE_SECTION_HEADER   section_header;
    CHAR                   section_base[];

} VAL_INTEGRITY_HEADER, *PVAL_INTEGRITY_HEADER;

STATIC
VOID
ReportInvalidProcessModule(_In_ PPROCESS_MODULE_INFORMATION Module)
{
    NTSTATUS status      = STATUS_UNSUCCESSFUL;
    UINT32   report_size = CryptRequestRequiredBufferLength(
        sizeof(PROCESS_MODULE_VALIDATION_REPORT));

    PPROCESS_MODULE_VALIDATION_REPORT report =
        ImpExAllocatePool2(POOL_FLAG_NON_PAGED, report_size, REPORT_POOL_TAG);

    if (!report)
        return;

    INIT_REPORT_PACKET(report, REPORT_INVALID_PROCESS_MODULE, 0);

    report->image_base = Module->module_base;
    report->image_size = Module->module_size;
    RtlCopyMemory(
        report->module_path, Module->module_path, sizeof(report->module_path));

    status = CryptEncryptBuffer(report, report_size);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("CryptEncryptBuffer: %lx", status);
        ImpExFreePoolWithTag(report, report_size);
        return;
    }

    IrpQueueSchedulePacket(report, report_size);
}

/*
 * Because the infrastructure has already been setup to validate modules in the
 * driver, that is how I will validate the usermode modules as well. Another
 * reason is that the win32 api makes it very easy to take a snapshot of the
 * modules and enumerate them with easy to use functions and macros.
 *
 * 1. Take a snapshot of the modules in the process from our dll
 * 2. pass the image base, image size and the image path to our driver via an
 * IRP
 * 3. from our driver, to first verify the in memory module, attach to our
 * protected process and using the base + size simply use
 * StoreModuleExecutableRegionsInBuffer()
 * 4. Next we use the path to map the image on disk into memory, and pass the
 * image to StoreModuleExecutableRegionsInBuffer() just as we did before.
 * 5. With the 2 buffers that contain both images executable regions, we hash
 * them and compare for anomalies.
 *
 * note: Its important to realise that since these are user mode modules, they
 * are often hooked by various legitimate programs - such as discord, nvidia
 * etc. So this needs to be rethinked.
 */
NTSTATUS
ValidateProcessLoadedModule(_Inout_ PIRP Irp)
{
    PAGED_CODE();

    NTSTATUS                         status            = STATUS_UNSUCCESSFUL;
    PROCESS_MODULE_VALIDATION_RESULT validation_result = {0};
    PPROCESS_MODULE_INFORMATION      module_info       = NULL;
    PKPROCESS                        process           = NULL;
    KAPC_STATE                       apc_state         = {0};
    PVAL_INTEGRITY_HEADER            memory_buffer     = NULL;
    PVAL_INTEGRITY_HEADER            disk_buffer       = NULL;
    PVOID                            memory_hash       = NULL;
    PVOID                            disk_hash         = NULL;
    ULONG                            memory_hash_size  = 0;
    ULONG                            disk_hash_size    = 0;
    SIZE_T                           bytes_written     = 0;
    UNICODE_STRING                   module_path       = {0};
    HANDLE                           section_handle    = NULL;
    PVOID                            section           = NULL;
    ULONG                            section_size      = 0;

    status = ValidateIrpInputBuffer(Irp, sizeof(PROCESS_MODULE_INFORMATION));

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ValidateIrpInputBuffer failed with status %x", status);
        return status;
    }

    module_info = (PPROCESS_MODULE_INFORMATION)Irp->AssociatedIrp.SystemBuffer;

    SessionGetProcess(&process);
    ImpRtlInitUnicodeString(&module_path, &module_info->module_path);

    /*
     * Attach because the offsets given are from the process' context.
     */
    ImpKeStackAttachProcess(process, &apc_state);

    status = StoreModuleExecutableRegionsInBuffer(&memory_buffer,
                                                  module_info->module_base,
                                                  module_info->module_size,
                                                  &bytes_written,
                                                  FALSE);

    ImpKeUnstackDetachProcess(&apc_state);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR(
            "StoreModuleExecutableRegionsInBuffer failed with status %x",
            status);
        goto end;
    }

    status = MapDiskImageIntoVirtualAddressSpace(
        &section_handle, &section, &module_path, &section_size);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("MapDiskImageIntoVirtualAddressSpace failed with status %x",
                    status);
        goto end;
    }

    status = StoreModuleExecutableRegionsInBuffer(
        &disk_buffer, section, section_size, &bytes_written, FALSE);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR(
            "StoreModuleExecutableRegionsInbuffer 2 failed with status %x",
            status);
        goto end;
    }

    status = ComputeHashOfSections(&memory_buffer->section_header,
                                   &disk_buffer->section_header,
                                   &disk_hash,
                                   &disk_hash_size,
                                   &memory_hash,
                                   &memory_hash_size);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ComputeHashOfSections failed with status %x", status);
        goto end;
    }

    if (!CompareHashes(disk_hash, memory_hash, memory_hash_size))
        ReportInvalidProcessModule(module_info);

end:

    if (section_handle)
        ImpZwClose(section_handle);

    if (section)
        ImpZwUnmapViewOfSection(ZwCurrentProcess(), section);

    if (memory_buffer)
        ImpExFreePoolWithTag(memory_buffer, POOL_TAG_INTEGRITY);

    if (memory_hash)
        ImpExFreePoolWithTag(memory_hash, POOL_TAG_INTEGRITY);

    if (disk_buffer)
        ImpExFreePoolWithTag(disk_buffer, POOL_TAG_INTEGRITY);

    if (disk_hash)
        ImpExFreePoolWithTag(disk_hash, POOL_TAG_INTEGRITY);

    return status;
}

NTSTATUS
HashUserModule(_In_ PPROCESS_MAP_MODULE_ENTRY Entry,
               _Out_ PVOID                    OutBuffer,
               _In_ UINT32                    OutBufferSize)
{
    PAGED_CODE();

    NTSTATUS              status           = STATUS_UNSUCCESSFUL;
    KAPC_STATE            apc_state        = {0};
    PVAL_INTEGRITY_HEADER memory_buffer    = NULL;
    PVOID                 memory_hash      = NULL;
    ULONG                 memory_hash_size = 0;
    SIZE_T                bytes_written    = 0;
    PACTIVE_SESSION       session          = GetActiveSession();

    /*
     * Attach because the offsets given are from the process' context.
     */
    ImpKeStackAttachProcess(session->process, &apc_state);

    status = StoreModuleExecutableRegionsInBuffer(
        &memory_buffer, Entry->base, Entry->size, &bytes_written, FALSE);

    ImpKeUnstackDetachProcess(&apc_state);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR(
            "StoreModuleExecutableRegionsInBuffer failed with status %x",
            status);
        goto end;
    }

    status = ComputeHashOfBuffer(memory_buffer->section_base,
                                 memory_buffer->section_header.SizeOfRawData,
                                 &memory_hash,
                                 &memory_hash_size);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ComputeHashOfBuffer failed with status %x", status);
        goto end;
    }

    if (OutBufferSize > memory_hash_size) {
        status = STATUS_BUFFER_TOO_SMALL;
        goto end;
    }

    RtlCopyMemory(OutBuffer, memory_hash, memory_hash_size);

end:

    if (memory_buffer)
        ImpExFreePoolWithTag(memory_buffer, POOL_TAG_INTEGRITY);

    if (memory_hash)
        ImpExFreePoolWithTag(memory_hash, POOL_TAG_INTEGRITY);

    return status;
}

FORCEINLINE
STATIC
PCHAR
GetStorageDescriptorSerialNumber(_In_ PSTORAGE_DEVICE_DESCRIPTOR Descriptor)
{
    return (PCHAR)((UINT64)Descriptor + Descriptor->SerialNumberOffset);
}

FORCEINLINE
STATIC
SIZE_T
GetStorageDescriptorSerialLength(_In_ PCHAR SerialNumber)
{
    return strnlen_s(SerialNumber, DEVICE_DRIVE_0_SERIAL_CODE_LENGTH) + 1;
}

FORCEINLINE
STATIC
VOID
InitStorageProperties(_Out_ PSTORAGE_PROPERTY_QUERY Query,
                      _In_ STORAGE_PROPERTY_ID      PropertyId,
                      _In_ STORAGE_QUERY_TYPE       QueryType)
{
    Query->PropertyId = PropertyId;
    Query->QueryType  = QueryType;
}

/*
 * TODO: Query PhysicalDrive%n to get the serial numbers for all harddrives, can
 * use the command "wmic diskdrive" check in console.
 */
NTSTATUS
GetHardDiskDriveSerialNumber(_Inout_ PVOID ConfigDrive0Serial,
                             _In_ SIZE_T   ConfigDrive0MaxSize)
{
    PAGED_CODE();

    NTSTATUS                   status                    = STATUS_UNSUCCESSFUL;
    HANDLE                     handle                    = NULL;
    OBJECT_ATTRIBUTES          attributes                = {0};
    IO_STATUS_BLOCK            status_block              = {0};
    STORAGE_PROPERTY_QUERY     query                     = {0};
    STORAGE_DESCRIPTOR_HEADER  storage_descriptor_header = {0};
    PSTORAGE_DEVICE_DESCRIPTOR device_descriptor         = NULL;
    UNICODE_STRING             physical_drive_path       = {0};
    PCHAR                      serial_number             = NULL;
    SIZE_T                     serial_length             = 0;

    ImpRtlInitUnicodeString(&physical_drive_path,
                            L"\\DosDevices\\PhysicalDrive0");

    /*
     * No need to use the flag OBJ_FORCE_ACCESS_CHECK since we arent passing
     * a handle given to us from usermode.
     */
    InitializeObjectAttributes(&attributes,
                               &physical_drive_path,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);

    status = ImpZwOpenFile(
        &handle, GENERIC_READ, &attributes, &status_block, NULL, NULL);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ZwOpenFile on PhysicalDrive0 failed with status %x",
                    status);
        goto end;
    }

    InitStorageProperties(&query, StorageDeviceProperty, PropertyStandardQuery);

    status = ImpZwDeviceIoControlFile(handle,
                                      NULL,
                                      NULL,
                                      NULL,
                                      &status_block,
                                      IOCTL_STORAGE_QUERY_PROPERTY,
                                      &query,
                                      sizeof(STORAGE_PROPERTY_QUERY),
                                      &storage_descriptor_header,
                                      sizeof(STORAGE_DESCRIPTOR_HEADER));

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ZwDeviceIoControlFile first call failed with status %x",
                    status);
        goto end;
    }

    device_descriptor = ImpExAllocatePool2(POOL_FLAG_NON_PAGED,
                                           storage_descriptor_header.Size,
                                           POOL_TAG_INTEGRITY);

    if (!device_descriptor) {
        status = STATUS_MEMORY_NOT_ALLOCATED;
        goto end;
    }

    status = ImpZwDeviceIoControlFile(handle,
                                      NULL,
                                      NULL,
                                      NULL,
                                      &status_block,
                                      IOCTL_STORAGE_QUERY_PROPERTY,
                                      &query,
                                      sizeof(STORAGE_PROPERTY_QUERY),
                                      device_descriptor,
                                      storage_descriptor_header.Size);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("ZwDeviceIoControlFile second call failed with status %x",
                    status);
        goto end;
    }

    if (!device_descriptor->SerialNumberOffset)
        goto end;

    serial_number = GetStorageDescriptorSerialNumber(device_descriptor);
    serial_length = GetStorageDescriptorSerialLength(serial_number);

    if (serial_length > ConfigDrive0MaxSize) {
        status = STATUS_BUFFER_TOO_SMALL;
        goto end;
    }

    RtlCopyMemory(ConfigDrive0Serial, serial_number, serial_length);

end:

    if (handle)
        ImpZwClose(handle);

    if (device_descriptor)
        ImpExFreePoolWithTag(device_descriptor, POOL_TAG_INTEGRITY);

    return status;
}
PVOID
ScanForSignature(_In_ PVOID  BaseAddress,
                 _In_ SIZE_T MaxLength,
                 _In_ LPCSTR Signature,
                 _In_ SIZE_T SignatureLength)
{
    PAGED_CODE();

    CHAR current_char     = 0;
    CHAR current_sig_char = 0;

    for (INT index = 0; index < MaxLength; index++) {
        for (INT sig = 0; sig < SignatureLength + 1; sig++) {
            current_char     = *(PCHAR)((UINT64)BaseAddress + index + sig);
            current_sig_char = Signature[sig];

            if (sig == SignatureLength)
                return (PVOID)((UINT64)BaseAddress + index);

            if (current_char != current_sig_char)
                break;
        }
    }

    return NULL;
}

/*
 * Lets ensure to the compiler doens't optimise out our useless instructions...
 */
#pragma optimize("", off)

STATIC
UINT64
MeasureInstructionRead(_In_ PVOID InstructionAddress)
{
    CONST UINT64 start = __readmsr(IA32_APERF_MSR) << 32;
    CHAR         value = *(PCHAR)InstructionAddress;
    return (__readmsr(IA32_APERF_MSR) << 32) - start;
}

#pragma optimize("", on)

STATIC
UINT64
MeasureReads(_In_ PVOID Address, _In_ ULONG Count)
{
    UINT64 read_average = 0;
    KIRQL  irql         = {0};

    MeasureInstructionRead(Address);

    KeRaiseIrql(HIGH_LEVEL, &irql);
    _disable();

    for (ULONG iteration = 0; iteration < Count; iteration++)
        read_average += MeasureInstructionRead(Address);

    _enable();
    KeLowerIrql(irql);

    DEBUG_VERBOSE("EPT Detection - Read Average: %llx", read_average);

    return read_average / Count;
}

#define EPT_CHECK_NUM_ITERATIONS      30
#define EPT_CONTROL_FUNCTIONS_COUNT   4
#define EPT_PROTECTED_FUNCTIONS_COUNT 2
#define EPT_MAX_FUNCTION_NAME_LENGTH  128
#define EPT_EXECUTION_TIME_MULTIPLIER 10

/*
 * Even though we test for the presence of a hypervisor, we should still test
 * for the presence of EPT hooks on key functions as this is a primary method
 * for reversing AC's.
 *
 * Credits to momo5502 for the idea: https://momo5502.com/blog/?p=255
 *
 * [+] EPT: Read average: 14991c28f5c2
 * [+] no EPT: Read average: 28828f5c28
 *
 * On average a read when HyperDbg's !epthook is active is around ~125x longer.
 * Will need to continue testing with other HV's, however it is a good start.
 */
STATIC
NTSTATUS
GetAverageReadTimeAtRoutine(_In_ PVOID    RoutineAddress,
                            _Out_ PUINT64 AverageTime)
{
    if (!RoutineAddress || !AverageTime)
        return STATUS_UNSUCCESSFUL;

    if (!MmIsAddressValid(RoutineAddress))
        return STATUS_INVALID_ADDRESS;

    *AverageTime = MeasureReads(RoutineAddress, EPT_CHECK_NUM_ITERATIONS);

    return *AverageTime == 0 ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}

/*
 * todo: encrypt both arrays
 *
 * The goal with the control functions is to find a reference time for an
 * average read on a function that is not EPT hooked. To accomplish this I've
 * selected some arbitrary, rarely used functions that shouldn't really ever
 * have an EPT hook active on them. This will give us a baseline that we can
 * then average out to find a relatively accurate average read time.
 *
 * From here, we have an array of protected functions which are commonly hooked
 * via EPT to reverse anti cheats. We then check the read times of these
 * functions and compare them to the average of the read times for the control
 * functions. If the read threshold exceeds a multiple of 10, we can be fairly
 * certain an EPT hook is active.
 *
 * Each time we measure the read we perform 30 iterations to ensure we get a
 * consistent result aswell as disabling interrupts + raising IRQL to ensure the
 * test is as accurate as possible.
 *
 * The following open source Intel VT-X hv's w/ EPT functionality have been
 * tested and detected in a non vm environment:
 *
 * HyperDbg !epthook (https://github.com/HyperDbg/HyperDbg):  detected
 * DdiMon (https://github.com/tandasat/DdiMon):               detected
 */
WCHAR CONTROL_FUNCTIONS[EPT_CONTROL_FUNCTIONS_COUNT]
                       [EPT_MAX_FUNCTION_NAME_LENGTH] = {
                           L"RtlAssert",
                           L"PsAcquireSiloHardReference",
                           L"PsDereferencePrimaryToken",
                           L"ZwCommitEnlistment"};

WCHAR PROTECTED_FUNCTIONS[EPT_PROTECTED_FUNCTIONS_COUNT]
                         [EPT_MAX_FUNCTION_NAME_LENGTH] = {
                             L"ExAllocatePoolWithTag", L"MmCopyMemory"};

/*
 * For whatever reason MmGetSystemRoutineAddress only works once, then every
 * call thereafter fails. So will be storing the routine addresses in arrays
 * since they dont change once the kernel is loaded.
 */
#pragma section("NonPagedPool", read, write)
__declspec(allocate("NonPagedPool")) UINT64
    CONTROL_FUNCTION_ADDRESSES[EPT_CONTROL_FUNCTIONS_COUNT] = {0};
__declspec(allocate("NonPagedPool")) UINT64
    PROTECTED_FUNCTION_ADDRESSES[EPT_PROTECTED_FUNCTIONS_COUNT] = {0};

STATIC
NTSTATUS
InitiateEptFunctionAddressArrays()
{
    PAGED_CODE();

    UNICODE_STRING current_function;

    for (INT index = 0; index < EPT_CONTROL_FUNCTIONS_COUNT; index++) {
        ImpRtlInitUnicodeString(&current_function, CONTROL_FUNCTIONS[index]);
        CONTROL_FUNCTION_ADDRESSES[index] =
            ImpMmGetSystemRoutineAddress(&current_function);

        if (!CONTROL_FUNCTION_ADDRESSES[index])
            return STATUS_UNSUCCESSFUL;
    }

    for (INT index = 0; index < EPT_PROTECTED_FUNCTIONS_COUNT; index++) {
        ImpRtlInitUnicodeString(&current_function, PROTECTED_FUNCTIONS[index]);
        PROTECTED_FUNCTION_ADDRESSES[index] =
            ImpMmGetSystemRoutineAddress(&current_function);

        if (!PROTECTED_FUNCTION_ADDRESSES[index])
            return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
DetectEptHooksInKeyFunctions()
{
    PAGED_CODE();

    NTSTATUS status           = STATUS_UNSUCCESSFUL;
    UINT32   control_fails    = 0;
    UINT64   instruction_time = 0;
    UINT64   control_time_sum = 0;
    UINT64   control_average  = 0;

    /* todo: once we call this, we need to set a flag to skip this,
     * otherwise we just return early */
    status = InitiateEptFunctionAddressArrays();

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("InitiateEptFunctionAddressArrays failed with status %x",
                    status);
        return status;
    }

    for (INT index = 0; index < EPT_CONTROL_FUNCTIONS_COUNT; index++) {
        status = GetAverageReadTimeAtRoutine(CONTROL_FUNCTION_ADDRESSES[index],
                                             &instruction_time);

        if (!NT_SUCCESS(status)) {
            DEBUG_ERROR("DetectEptPresentOnFunction failed with status %x",
                        status);
            control_fails += 1;
            continue;
        }

        control_time_sum += instruction_time;
    }

    if (control_time_sum == 0)
        return STATUS_UNSUCCESSFUL;

    control_average =
        control_time_sum / (EPT_CONTROL_FUNCTIONS_COUNT - control_fails);

    if (control_average == 0)
        return STATUS_UNSUCCESSFUL;

    for (INT index = 0; index < EPT_PROTECTED_FUNCTIONS_COUNT; index++) {
        status = GetAverageReadTimeAtRoutine(
            PROTECTED_FUNCTION_ADDRESSES[index], &instruction_time);

        if (!NT_SUCCESS(status)) {
            DEBUG_ERROR("DetectEptPresentOnFunction failed with status %x",
                        status);
            continue;
        }

        /* [+] EPT hook detected at function: ExAllocatePoolWithTag with
         * execution time of: 149b7777777 */
        if (control_average * EPT_EXECUTION_TIME_MULTIPLIER <
            instruction_time) {
            DEBUG_WARNING(
                "EPT hook detected at function: %llx with execution time of: %llx",
                PROTECTED_FUNCTION_ADDRESSES[index],
                instruction_time);

            /* close game etc. */
        }
    }

    return status;
}

VOID
FindWinLogonProcess(_In_ PPROCESS_LIST_ENTRY Node, _In_opt_ PVOID Context)
{
    LPCSTR     process_name = NULL;
    PEPROCESS* process      = (PEPROCESS*)Context;

    if (!Context)
        return;

    process_name = ImpPsGetProcessImageFileName(Node->process);

    if (!strcmp(process_name, "winlogon.exe"))
        *process = Node->process;
}

STATIC
NTSTATUS
StoreModuleExecutableRegionsx86(_In_ PRTL_MODULE_EXTENDED_INFO Module,
                                _In_ PVOID*                    Buffer,
                                _In_ PULONG                    BufferSize)
{
    NTSTATUS   status    = STATUS_UNSUCCESSFUL;
    PEPROCESS  process   = NULL;
    KAPC_STATE apc_state = {0};

    RtlEnumerateHashmap(GetProcessHashmap(), FindWinLogonProcess, &process);

    if (!process)
        return STATUS_NOT_FOUND;

    ImpKeStackAttachProcess(process, &apc_state);

    status = StoreModuleExecutableRegionsInBuffer(
        Buffer, Module->ImageBase, Module->ImageSize, BufferSize, TRUE);

    ImpKeUnstackDetachProcess(&apc_state);

    if (!NT_SUCCESS(status))
        DEBUG_ERROR(
            "StoreModuleExecutableRegionsInBuffer-x86 failed with status %x",
            status);

    return status;
}

FORCEINLINE
STATIC
VOID
Enablex86Hashing(_In_ PDRIVER_LIST_HEAD Head)
{
    Head->can_hash_x86 = TRUE;
}

VOID
DeferredModuleHashingCallback(_In_ PDEVICE_OBJECT DeviceObject,
                              _In_opt_ PVOID      Context)
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS                 status        = STATUS_UNSUCCESSFUL;
    RTL_MODULE_EXTENDED_INFO module        = {0};
    PDRIVER_LIST_HEAD        driver_list   = GetDriverList();
    PLIST_ENTRY              deferred_head = &GetDriverList()->deferred_list;
    PLIST_ENTRY              list_entry    = NULL;
    PDRIVER_LIST_ENTRY       entry         = NULL;

    Enablex86Hashing(driver_list);

    list_entry = RemoveHeadList(deferred_head);

    if (list_entry == deferred_head)
        goto end;

    while (list_entry != deferred_head) {
        entry =
            CONTAINING_RECORD(list_entry, DRIVER_LIST_ENTRY, deferred_entry);

        DriverListEntryToExtendedModuleInfo(entry, &module);

        DEBUG_VERBOSE("Hashing Deferred Module: %s", module.FullPathName);

        status = HashModule(&module, &entry->text_hash);

        if (!NT_SUCCESS(status)) {
            DEBUG_ERROR("HashModule-x86 failed with status %x", status);
            entry->hashed = FALSE;
            list_entry    = RemoveHeadList(deferred_head);
            continue;
        }

        entry->hashed = TRUE;
        list_entry    = RemoveHeadList(deferred_head);
    }

end:

    DEBUG_VERBOSE("All deferred modules hashed.");
    ImpIoFreeWorkItem(driver_list->work_item);
    driver_list->work_item = NULL;
}

NTSTATUS
HashModule(_In_ PRTL_MODULE_EXTENDED_INFO Module, _Out_ PVOID Hash)
{
    NTSTATUS              status             = STATUS_UNSUCCESSFUL;
    ANSI_STRING           ansi_string        = {0};
    UNICODE_STRING        path               = {0};
    ULONG                 memory_text_size   = 0;
    PVOID                 memory_hash        = NULL;
    ULONG                 memory_hash_size   = 0;
    PVAL_INTEGRITY_HEADER memory_buffer      = NULL;
    ULONG                 memory_buffer_size = 0;
    PDRIVER_LIST_HEAD     list               = GetDriverList();

    ImpRtlInitAnsiString(&ansi_string, Module->FullPathName);

    if (!ansi_string.Buffer) {
        DEBUG_ERROR("RtlInitAnsiString failed with status %x", status);
        return STATUS_UNSUCCESSFUL;
    }

    status = ImpRtlAnsiStringToUnicodeString(&path, &ansi_string, TRUE);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("RtlAnsiStringToUnicodeString failed with status %x",
                    status);
        return status;
    }

    /*
     * For win32k and related modules, because they are 32bit for us to read
     * the memory we need to attach to a 32 bit process. A simple check is
     * that the 32 bit image base wont be a valid address, while this is
     * hacky it works. Then we simply attach to a 32 bit address space, in
     * our case winlogon, which will allow us to perform the copy.
     *
     * Since the driver loads at system startup, our driver is loaded before
     * the WinLogon process has started, so to combat this return return
     * early with a status code. This will mark the module as not hashed and
     * x86. We will then queue a work item to hash these modules later once
     * WinLogon has started.
     */
    if (!ImpMmIsAddressValid(Module->ImageBase) && !list->can_hash_x86) {
        status = STATUS_INVALID_IMAGE_WIN_32;
        goto end;
    }
    else if (!ImpMmIsAddressValid(Module->ImageBase) && list->can_hash_x86) {
        /*
         * Once the WinLogon process has started, we can then hash new
         * x86 modules.
         */
        status = StoreModuleExecutableRegionsx86(
            Module, (PVOID)&memory_buffer, &memory_buffer_size);
    }
    else {
        status = StoreModuleExecutableRegionsInBuffer((PVOID)&memory_buffer,
                                                      Module->ImageBase,
                                                      Module->ImageSize,
                                                      &memory_buffer_size,
                                                      FALSE);
    }

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR(
            "StoreModuleExecutableRegionsInbuffer 2 failed with status %x",
            status);
        goto end;
    }

    status = ComputeHashOfBuffer(memory_buffer->section_base,
                                 memory_buffer->section_header.SizeOfRawData,
                                 &memory_hash,
                                 &memory_hash_size);

    if (!NT_SUCCESS(status)) {
        DEBUG_VERBOSE("ComputeHashOfSections failed with status %x", status);
        goto end;
    }

    RtlCopyMemory(Hash, memory_hash, memory_hash_size);

end:

    if (memory_buffer)
        ImpExFreePoolWithTag(memory_buffer, POOL_TAG_INTEGRITY);

    if (memory_hash)
        ImpExFreePoolWithTag(memory_hash, POOL_TAG_INTEGRITY);

    if (path.Buffer)
        ImpRtlFreeUnicodeString(&path);

    return status;
}

/*
 * As said in the comment below, in the future we want to be able to copy a
 * small part of the spot where the image has changed, say the next 50 bytes.
 * This would be useful for scanning for any jmp x etc. For this thisl do.
 */
STATIC
VOID
ReportModifiedSystemImage(_In_ PRTL_MODULE_EXTENDED_INFO Module)
{
    NTSTATUS status      = STATUS_UNSUCCESSFUL;
    UINT32   packet_size = CryptRequestRequiredBufferLength(
        sizeof(SYSTEM_MODULE_INTEGRITY_CHECK_REPORT));

    PSYSTEM_MODULE_INTEGRITY_CHECK_REPORT report =
        ImpExAllocatePool2(POOL_FLAG_NON_PAGED, packet_size, REPORT_POOL_TAG);

    if (!report)
        return;

    INIT_REPORT_PACKET(report, REPORT_PATCHED_SYSTEM_MODULE, 0);

    report->image_base = Module->ImageBase;
    report->image_size = Module->ImageSize;

    RtlCopyMemory(
        report->path_name, Module->FullPathName, sizeof(report->path_name));

    status = CryptEncryptBuffer(report, packet_size);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("CryptEncryptBuffer: %lx", status);
        ImpExFreePoolWithTag(report, packet_size);
        return;
    }

    IrpQueueSchedulePacket(report, packet_size);
}

VOID
ValidateSystemModule(_In_ PRTL_MODULE_EXTENDED_INFO Module)
{
    NTSTATUS           status = STATUS_UNSUCCESSFUL;
    PDRIVER_LIST_ENTRY entry  = NULL;
    PVOID              hash   = NULL;

    hash = ExAllocatePool2(
        POOL_FLAG_NON_PAGED, SHA_256_HASH_LENGTH, POOL_TAG_INTEGRITY);

    if (!hash)
        return;

    FindDriverEntryByBaseAddress(Module->ImageBase, &entry);

    if (!entry) {
        DEBUG_ERROR("FindDriverEntryByBaseAddress failed with no status");
        goto end;
    }

    /* For now, there is some issue that sometimes occurs when validing x86
     * modules, for now lets skip them.*/
    if (entry->x86)
        goto end;

    /*
     * Ideally, we would like to have access to the offset into the module that
     * doesnt match, allowing us to copy the next 50 bytes for example. Since we
     * only store the hash, we can only check whether something has changed, but
     * we dont really have access to any information regarding what changed. In
     * the future it might be nice (though requires a fair amount of memory) to
     * store a copy of images on load in the list alongside the hash. That way
     * if there is a change in the hash, we can access the old buffer, perform a
     * memory comparison, and find the point where the change exists.
     */
    status = HashModule(Module, hash);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("HashModule failed with status %x", status);
        goto end;
    }

    if (CompareHashes(hash, entry->text_hash, SHA_256_HASH_LENGTH)) {
        DEBUG_VERBOSE("Module: %s text regions are valid.",
                      Module->FullPathName);
    }
    else {
        DEBUG_WARNING("**!!** Module: %s text regions are NOT valid **!!**",
                      Module->FullPathName);
        ReportModifiedSystemImage(Module);
    }

end:

    if (hash)
        ExFreePoolWithTag(hash, POOL_TAG_INTEGRITY);
}

STATIC
VOID
ReportModifiedSelfDriverImage(_In_ PRTL_MODULE_EXTENDED_INFO Module)
{
    NTSTATUS status      = STATUS_UNSUCCESSFUL;
    UINT32   packet_size = CryptRequestRequiredBufferLength(
        sizeof(DRIVER_SELF_INTEGRITY_CHECK_REPORT));

    PDRIVER_SELF_INTEGRITY_CHECK_REPORT report =
        ImpExAllocatePool2(POOL_FLAG_NON_PAGED, packet_size, REPORT_POOL_TAG);

    if (!report)
        return;

    INIT_REPORT_PACKET(report, REPORT_SELF_DRIVER_PATCHED, 0);

    report->image_base = Module->ImageBase;
    report->image_size = Module->ImageSize;

    RtlCopyMemory(
        report->path_name, Module->FullPathName, sizeof(report->path_name));

    status = CryptEncryptBuffer(report, packet_size);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("CryptEncryptBuffer: %lx", status);
        ImpExFreePoolWithTag(report, packet_size);
        return;
    }

    IrpQueueSchedulePacket(report, packet_size);
}

NTSTATUS
ValidateOurDriverImage()
{
    NTSTATUS                  status           = STATUS_UNSUCCESSFUL;
    SYSTEM_MODULES            modules          = {0};
    PRTL_MODULE_EXTENDED_INFO module_info      = NULL;
    PVOID                     memory_hash      = NULL;
    ULONG                     memory_hash_size = 0;
    PDRIVER_LIST_ENTRY        entry            = NULL;
    LPCSTR                    driver_name      = GetDriverName();
    PUNICODE_STRING           path             = GetDriverPath();

    status = GetSystemModuleInformation(&modules);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("GetSystemModuleInformation failed with status %x", status);
        return status;
    }

    module_info = FindSystemModuleByName(driver_name, &modules);

    if (!module_info) {
        DEBUG_ERROR("FindSystemModuleByName failed with no status.");
        goto end;
    }

    memory_hash = ExAllocatePool2(
        POOL_FLAG_NON_PAGED, SHA_256_HASH_LENGTH, POOL_TAG_INTEGRITY);

    if (!memory_hash)
        goto end;

    FindDriverEntryByBaseAddress(module_info->ImageBase, &entry);

    if (!entry) {
        DEBUG_ERROR("FindDriverEntryByBaseAddress failed with no status.");
        goto end;
    }

    if (entry->hashed == FALSE) {
        DEBUG_WARNING("Our module has not been hashed, returning.");
        status = STATUS_HASH_NOT_PRESENT;
        goto end;
    }

    status = HashModule(module_info, memory_hash);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("HashModule failed with status %x", status);
        goto end;
    }

    /*
     * Since we don't pass a return value, I think we would raise an invalid
     * module error and stop the users game session ? since module .text
     * section error would be a large red flag
     */
    if (CompareHashes(memory_hash, entry->text_hash, SHA_256_HASH_LENGTH)) {
        DEBUG_VERBOSE("Driver image is valid. Integrity check complete");
    }
    else {
        DEBUG_WARNING("**!!** Driver image is NOT valid. **!!**");
        ReportModifiedSelfDriverImage(module_info);
    }

end:

    if (memory_hash)
        ExFreePoolWithTag(memory_hash, POOL_TAG_INTEGRITY);

    if (modules.address)
        ExFreePoolWithTag(modules.address, SYSTEM_MODULES_POOL);

    return status;
}

FORCEINLINE
STATIC
VOID
IncrementActiveThreadCount(_Inout_ PSYS_MODULE_VAL_CONTEXT Context)
{
    InterlockedIncrement(&Context->active_thread_count);
}

FORCEINLINE
STATIC
VOID
DecrementActiveThreadCount(_Inout_ PSYS_MODULE_VAL_CONTEXT Context)
{
    InterlockedDecrement(&Context->active_thread_count);
}

FORCEINLINE
STATIC
VOID
SetVerificationBlockAsComplete(_In_ PSYS_MODULE_VAL_CONTEXT Context)
{
    InterlockedExchange(&Context->complete, TRUE);
}

FORCEINLINE
STATIC
UINT32
GetCurrentVerificationIndex(_In_ PSYS_MODULE_VAL_CONTEXT Context)
{
    return InterlockedExchange(&Context->current_count, Context->current_count);
}

FORCEINLINE
STATIC
UINT32
GetCurrentVerificationMaxIndex(_In_ PSYS_MODULE_VAL_CONTEXT Context,
                               _In_ UINT32                  Count)
{
    return Count + Context->block_size;
}

FORCEINLINE
STATIC
VOID
UpdateCurrentVerificationIndex(_In_ PSYS_MODULE_VAL_CONTEXT Context,
                               _In_ UINT32                  Count)
{
    InterlockedExchange(&Context->current_count, Count);
}

STATIC
VOID
SystemModuleVerificationDispatchFunction(_In_ PDEVICE_OBJECT DeviceObject,
                                         _In_ PSYS_MODULE_VAL_CONTEXT Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    IncrementActiveThreadCount(Context);

    UINT32 count = GetCurrentVerificationIndex(Context);

    /*
     * theres a race condition here, where if the max is taken after a thread
     * has alredy completed an iteration, meaning the current_count will be +1
     * then what the starting thread is expecting, meaning the final iteration
     * will be off by one. To fix just need to calculate the block max before
     * threads are dispatched. todo!
     */
    UINT32 max = GetCurrentVerificationMaxIndex(Context, count);

    for (; count < max && count < Context->total_count; count++) {
        if (!InterlockedCompareExchange(
                &Context->dispatcher_info[count].validated, TRUE, FALSE)) {
            ValidateSystemModule(&Context->module_info[count]);
        }
    }

    if (count == Context->total_count)
        SetVerificationBlockAsComplete(Context);

    UpdateCurrentVerificationIndex(Context, count);
    DecrementActiveThreadCount(Context);
}

#define VALIDATION_BLOCK_SIZE 25

FORCEINLINE
STATIC
VOID
InitSysModuleValidationContext(_Out_ PSYS_MODULE_VAL_CONTEXT  Context,
                               _In_ PMODULE_DISPATCHER_HEADER DispatcherArray,
                               _In_ PSYSTEM_MODULES           SystemModules)
{
    Context->active_thread_count = 0;
    Context->active              = TRUE;
    Context->complete            = FALSE;
    Context->dispatcher_info     = DispatcherArray;
    Context->module_info         = SystemModules->address;
    Context->total_count         = SystemModules->module_count;
    Context->block_size          = VALIDATION_BLOCK_SIZE;

    /* skip hal.dll and ntosrnl.exe  */
    Context->current_count = 2;
}

/*
 * Multithreaded delayed priority work items improve 1% lows by 25% and reduces
 * average PC latency by 10% compared to traditional multithreading. This is
 * important as having high average fps but low 1% lows just leads to stuttery
 * gameplay which in competitive multiplayer games is simply not alright.
 * Overall still room for improvement but from a statistical and feel standpoint
 * which the gameplay is much smoother (tested in cs2).
 *
 * A potential idea for further improvement is finding the cores with the least
 * cpu usages and setting the worker threads affinity accordingly.
 */
STATIC
NTSTATUS
InitialiseSystemModuleVerificationContext(PSYS_MODULE_VAL_CONTEXT Context)
{
    NTSTATUS                  status     = STATUS_UNSUCCESSFUL;
    SYSTEM_MODULES            modules    = {0};
    PMODULE_DISPATCHER_HEADER dispatcher = NULL;

    status = GetSystemModuleInformation(&modules);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("GetSystemModuleInformation failed with status %x", status);
        return status;
    }

    DEBUG_VERBOSE("driver count: %lx", modules.module_count);

    dispatcher = ImpExAllocatePool2(POOL_FLAG_NON_PAGED,
                                    modules.module_count *
                                        sizeof(MODULE_DISPATCHER_HEADER),
                                    POOL_TAG_INTEGRITY);

    if (!dispatcher) {
        ImpExFreePoolWithTag(modules.address, SYSTEM_MODULES_POOL);
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    InitSysModuleValidationContext(Context, dispatcher, &modules);
    return status;
}

VOID
FreeWorkItems(_In_ PSYS_MODULE_VAL_CONTEXT Context)
{
    for (INT index = 0; index < VERIFICATION_THREAD_COUNT; index++) {
        if (Context->work_items[index]) {
            ImpIoFreeWorkItem(Context->work_items[index]);
            Context->work_items[index] = NULL;
        }
    }
}

STATIC
VOID
FreeModuleVerificationItems(_In_ PSYS_MODULE_VAL_CONTEXT Context)
{
    /* if a thread hasnt completed by this point, something catastrophic has
     * gone wrong and maybe its better not to yield..*/
    while (Context->active_thread_count)
        YieldProcessor();

    if (Context->module_info) {
        ImpExFreePoolWithTag(Context->module_info, SYSTEM_MODULES_POOL);
        Context->module_info = NULL;
    }

    if (Context->dispatcher_info) {
        ImpExFreePoolWithTag(Context->dispatcher_info, POOL_TAG_INTEGRITY);
        Context->dispatcher_info = NULL;
    }
}

VOID
CleanupValidationContextOnUnload(_In_ PSYS_MODULE_VAL_CONTEXT Context)
{
    Context->active   = FALSE;
    Context->complete = TRUE;
    FreeWorkItems(Context);
    FreeModuleVerificationItems(Context);
}

STATIC
VOID
DispatchVerificationWorkerThreads(_In_ PSYS_MODULE_VAL_CONTEXT Context)
{
    for (INT index = 0; index < VERIFICATION_THREAD_COUNT; index++) {
        Context->work_items[index] =
            ImpIoAllocateWorkItem(GetDriverDeviceObject());

        if (!Context->work_items[index])
            continue;

        ImpIoQueueWorkItem(Context->work_items[index],
                           SystemModuleVerificationDispatchFunction,
                           DelayedWorkQueue,
                           Context);
    }
}

NTSTATUS
SystemModuleVerificationDispatcher()
{
    NTSTATUS                status    = STATUS_UNSUCCESSFUL;
    PIO_WORKITEM            work_item = NULL;
    PSYS_MODULE_VAL_CONTEXT context   = GetSystemModuleValidationContext();

    if (context->complete) {
        DEBUG_VERBOSE(
            "System modules integrity check complete. Freeing items.");
        context->active   = FALSE;
        context->complete = FALSE;
        FreeModuleVerificationItems(context);
        FreeWorkItems(context);
        return STATUS_SUCCESS;
    }

    if (!context->active) {
        DEBUG_VERBOSE("Context not active, generating new one");

        status = InitialiseSystemModuleVerificationContext(context);

        if (!NT_SUCCESS(status)) {
            DEBUG_ERROR(
                "InitialiseSystemModuleVerificationContext failed with status %x",
                status);
            return status;
        }
    }
    else {
        FreeWorkItems(context);
    }

    DispatchVerificationWorkerThreads(context);

    DEBUG_VERBOSE(
        "All worker threads dispatched for system module validation.");

    return STATUS_SUCCESS;
}

NTSTATUS
GetOsVersionInformation(_Out_ PRTL_OSVERSIONINFOW VersionInfo)
{
    NTSTATUS           status = STATUS_ABANDONED;
    RTL_OSVERSIONINFOW info   = {0};

    if (!VersionInfo)
        return STATUS_INVALID_PARAMETER;

    status = ImpRtlGetVersion(&info);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("RtlGetVersion failed with status %x", status);
        return status;
    }

    VersionInfo->dwBuildNumber       = info.dwBuildNumber;
    VersionInfo->dwMajorVersion      = info.dwMajorVersion;
    VersionInfo->dwMinorVersion      = info.dwMinorVersion;
    VersionInfo->dwOSVersionInfoSize = info.dwOSVersionInfoSize;
    VersionInfo->dwPlatformId        = info.dwPlatformId;

    RtlCopyMemory(VersionInfo->szCSDVersion,
                  info.szCSDVersion,
                  sizeof(VersionInfo->szCSDVersion));

    return status;
}

#define KPCR_KPRCB_OFFSET        0x180
#define KPCRB_IDLE_THREAD_OFFSET 0x018
#define KTHREAD_IDLE_TIME_OFFSET 0x28c
#define KPCRB_KERNEL_TIME_OFFSET 0x7e84
#define KPCRB_USER_TIME_OFFSET   0x7e88

UINT32
CalculateCpuCoreUsage(_In_ UINT32 Core)
{
    PVOID  kpcr        = NULL;
    PVOID  kpcrb       = NULL;
    PVOID  idle_thread = NULL;
    UINT32 idle_time   = 0;
    UINT32 kernel_time = 0;
    UINT32 user_time   = 0;

    KeSetSystemAffinityThread(1ull << Core);

    while (Core != KeGetCurrentProcessorNumber())
        YieldProcessor();

    kpcr        = __readmsr(IA32_GS_BASE);
    kpcrb       = (UINT64)kpcr + KPCR_KPRCB_OFFSET;
    idle_thread = *(UINT64*)((UINT64)kpcrb + KPCRB_IDLE_THREAD_OFFSET);

    idle_time   = *(UINT32*)((UINT64)idle_thread + KTHREAD_IDLE_TIME_OFFSET);
    kernel_time = *(UINT32*)((UINT64)kpcrb + KPCRB_KERNEL_TIME_OFFSET);
    user_time   = *(UINT32*)((UINT64)kpcrb + KPCRB_USER_TIME_OFFSET);

    return (100 - (UINT32)(UInt32x32To64(idle_time, 100) /
                           (UINT64)(kernel_time + user_time)));
}

BOOLEAN
ValidateOurDriversDispatchRoutines()
{
    PDRIVER_OBJECT driver = GetDriverObject();

    if (driver->MajorFunction[IRP_MJ_CREATE] != DeviceCreate ||
        driver->MajorFunction[IRP_MJ_CLOSE] != DeviceClose ||
        driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] != DeviceControl) {
        DEBUG_WARNING(
            "**!!** Drivers dispatch routine has been tampered with. **!!**");
        return FALSE;
    }

    return TRUE;
}

STATIC
VOID
FreeHeartbeatObjects(_Inout_ PHEARTBEAT_CONFIGURATION Configuration)
{
    if (Configuration->dpc) {
        ImpExFreePoolWithTag(Configuration->dpc, POOL_TAG_HEARTBEAT);
        Configuration->dpc = NULL;
    }

    if (Configuration->timer) {
        ImpExFreePoolWithTag(Configuration->timer, POOL_TAG_HEARTBEAT);
        Configuration->timer = NULL;
    }
}

STATIC
NTSTATUS
AllocateHeartbeatObjects(_Inout_ PHEARTBEAT_CONFIGURATION Configuration)
{
    Configuration->dpc = ImpExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(KDPC), POOL_TAG_HEARTBEAT);

    if (!Configuration->dpc)
        return STATUS_INSUFFICIENT_RESOURCES;

    Configuration->timer = ImpExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(KTIMER), POOL_TAG_HEARTBEAT);

    if (!Configuration->timer) {
        ImpExFreePoolWithTag(Configuration->dpc, POOL_TAG_HEARTBEAT);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    return STATUS_SUCCESS;
}

#define HEARTBEAT_NANOSECONDS_LOW \
    (60ULL * 10000000ULL) // 1 min in 100-nanosecond intervals
#define HEARTBEAT_NANOSECONDS_HIGH \
    (240ULL * 10000000ULL) // 4 mins in 100-nanosecond intervals

#define TICKS_TO_100_NS_INTERVALS(tick_count) ((tick_count) * 100000)

/* Generate a random due time between 1 and 4 minutes in 100-nanosecond
 * intervals. */
STATIC
LARGE_INTEGER
GenerateHeartbeatDueTime()
{
    LARGE_INTEGER ticks = {0};
    KeQueryTickCount(&ticks);

    UINT64 interval =
        HEARTBEAT_NANOSECONDS_LOW +
        (TICKS_TO_100_NS_INTERVALS(ticks.QuadPart) %
         (HEARTBEAT_NANOSECONDS_HIGH - HEARTBEAT_NANOSECONDS_LOW));

    LARGE_INTEGER due_time = {.QuadPart = -interval};
    return due_time;
}

FORCEINLINE
STATIC
VOID
InitialiseHeartbeatObjects(_Inout_ PHEARTBEAT_CONFIGURATION Configuration)
{
    KeInitializeDpc(Configuration->dpc, HeartbeatDpcRoutine, Configuration);
    KeInitializeTimer(Configuration->timer);
    KeSetTimer(
        Configuration->timer, GenerateHeartbeatDueTime(), Configuration->dpc);
}

FORCEINLINE
STATIC
VOID
SetHeartbeatActive(_Inout_ PHEARTBEAT_CONFIGURATION Configuration)
{
    InterlockedIncrement(&Configuration->active);
}

FORCEINLINE
STATIC
VOID
SetHeartbeatInactive(_Inout_ PHEARTBEAT_CONFIGURATION Configuration)
{
    InterlockedDecrement(&Configuration->active);
}

/* Blocks until heartbeat execution is complete */
FORCEINLINE
STATIC
VOID
WaitForHeartbeatCompletion(_In_ PHEARTBEAT_CONFIGURATION Configuration)
{
    while (Configuration->active)
        YieldProcessor();
}

FORCEINLINE
STATIC
VOID
IncrementHeartbeatCounter(_In_ PHEARTBEAT_CONFIGURATION Configuration)
{
    InterlockedIncrement(&Configuration->counter);
}

FORCEINLINE
STATIC
PHEARTBEAT_PACKET
BuildHeartbeatPacket(_In_ UINT32 PacketSize)
{
    PIRP_QUEUE_HEAD queue = GetIrpQueueHead();

    PHEARTBEAT_PACKET packet =
        ImpExAllocatePool2(POOL_FLAG_NON_PAGED, PacketSize, POOL_TAG_HEARTBEAT);

    if (!packet)
        return NULL;

    INIT_HEARTBEAT_PACKET(packet);

    KeAcquireGuardedMutex(&queue->lock);

    /*
     * Its important to remember that since we query the packet metrics before
     * the metrics are incremented for the current packets they will always be 1
     * less then whats noted.
     */
    packet->total_heartbeats_completed = queue->total_heartbeats_completed;
    packet->total_irps_completed       = queue->total_irps_completed;
    packet->total_reports_completed    = queue->total_reports_completed;
    KeReleaseGuardedMutex(&queue->lock);

    return packet;
}

STATIC
VOID
HeartbeatWorkItem(_In_ PDEVICE_OBJECT DeviceObject, _In_opt_ PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    if (!ARGUMENT_PRESENT(Context))
        return;

    UINT32                   packet_size = 0;
    NTSTATUS                 status      = STATUS_UNSUCCESSFUL;
    PHEARTBEAT_PACKET        packet      = NULL;
    PHEARTBEAT_CONFIGURATION config      = (PHEARTBEAT_CONFIGURATION)Context;

    DEBUG_VERBOSE("Heartbeat timer alerted. Generating heartbeat packet.");

    SetHeartbeatActive(config);

    packet_size = CryptRequestRequiredBufferLength(sizeof(HEARTBEAT_PACKET));
    packet      = BuildHeartbeatPacket(packet_size);

    if (packet) {
        status = CryptEncryptBuffer(packet, packet_size);

        if (!NT_SUCCESS(status)) {
            DEBUG_ERROR("CryptEncryptBuffer: %lx", status);
            ImpExFreePoolWithTag(packet, POOL_TAG_HEARTBEAT);
            goto queue_next;
        }

        IrpQueueSchedulePacket(packet, packet_size);
        IncrementHeartbeatCounter(config);
    }

queue_next:
    /* Ensure we wait until our heartbeats DPC has terminated. */
    KeFlushQueuedDpcs();
    FreeHeartbeatObjects(config);

    status = AllocateHeartbeatObjects(config);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("AllocateHeartbeatObjects %x", status);
        return;
    }

    InitialiseHeartbeatObjects(config);
    SetHeartbeatInactive(config);
}

STATIC
VOID
HeartbeatDpcRoutine(_In_ PKDPC     Dpc,
                    _In_opt_ PVOID DeferredContext,
                    _In_opt_ PVOID SystemArgument1,
                    _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (!ARGUMENT_PRESENT(DeferredContext))
        return;

    PHEARTBEAT_CONFIGURATION config = (PHEARTBEAT_CONFIGURATION)DeferredContext;

    IoQueueWorkItem(
        config->work_item, HeartbeatWorkItem, NormalWorkQueue, config);
}

/*
 * The premise behind this initial heartbeat monitor is that at a random
 * interval a timer will be set. Once this timer is set, a dpc routine will
 * run that will insert a heartbeat packet into the io queue which will be
 * processed by user mode. Once the heartbeat is inserted, we queue a work
 * item which will wait until the dpc routine is finished, free the current
 * timer and work item (this is safe as the timer is removed from the timer
 * queue when its alerted) and allocate a new timer and dpc object. We will
 * then initalise them and insert them with another random value.
 *
 * The goal of this is to make reverse engineering the heartbeat process as
 * hard as possible. And while it is only a start, I think its a start in
 * the right direction.
 */
NTSTATUS
InitialiseHeartbeatConfiguration(_Out_ PHEARTBEAT_CONFIGURATION Configuration)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    Configuration->counter   = 0;
    Configuration->active    = FALSE;
    Configuration->seed      = GenerateRandSeed();
    Configuration->work_item = IoAllocateWorkItem(GetDriverDeviceObject());

    if (!Configuration->work_item)
        return STATUS_INSUFFICIENT_RESOURCES;

    status = AllocateHeartbeatObjects(Configuration);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("AllocateHeartbeatObjects %x", status);
        return status;
    }

    InitialiseHeartbeatObjects(Configuration);
    return status;
}

VOID
FreeHeartbeatConfiguration(_Inout_ PHEARTBEAT_CONFIGURATION Configuration)
{
    WaitForHeartbeatCompletion(Configuration);
    KeCancelTimer(Configuration->timer);
    FreeHeartbeatObjects(Configuration);
    IoFreeWorkItem(Configuration->work_item);
}