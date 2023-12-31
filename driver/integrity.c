#include "integrity.h"

#include "common.h"
#include "driver.h"
#include "modules.h"
#include "callbacks.h"
#include "ioctl.h"

#include <bcrypt.h>
#include <initguid.h>
#include <devpkey.h>

typedef struct _INTEGRITY_CHECK_HEADER
{
        INT  executable_section_count;
        LONG total_packet_size;

} INTEGRITY_CHECK_HEADER, *PINTEGRITY_CHECK_HEADER;

#define MAX_MODULE_PATH 256

typedef struct _PROCESS_MODULE_INFORMATION
{
        PVOID  module_base;
        SIZE_T module_size;
        WCHAR  module_path[MAX_MODULE_PATH];

} PROCESS_MODULE_INFORMATION, *PPROCESS_MODULE_INFORMATION;

typedef struct _PROCESS_MODULE_VALIDATION_RESULT
{
        INT is_module_valid;

} PROCESS_MODULE_VALIDATION_RESULT, *PPROCESS_MODULE_VALIDATION_RESULT;

STATIC
NTSTATUS
InitiateEptFunctionAddressArrays();

STATIC
NTSTATUS
GetModuleInformationByName(_Out_ PRTL_MODULE_EXTENDED_INFO ModuleInfo, _In_ LPCSTR ModuleName);

STATIC
NTSTATUS
StoreModuleExecutableRegionsInBuffer(_Outptr_result_bytebuffer_(*BytesWritten) PVOID* Buffer,
                                     _In_ PVOID                                       ModuleBase,
                                     _In_ SIZE_T                                      ModuleSize,
                                     _Out_ _Deref_out_range_(>, 0) PSIZE_T BytesWritten);

STATIC
NTSTATUS
MapDiskImageIntoVirtualAddressSpace(_Inout_ PHANDLE                          SectionHandle,
                                    _Outptr_result_bytebuffer_(*Size) PVOID* Section,
                                    _In_ PUNICODE_STRING                     Path,
                                    _Out_ _Deref_out_range_(>, 0) PSIZE_T Size);

STATIC
NTSTATUS
ComputeHashOfBuffer(_In_ PVOID                                         Buffer,
                    _In_ ULONG                                         BufferSize,
                    _Outptr_result_bytebuffer_(*HashResultSize) PVOID* HashResult,
                    _Out_ _Deref_out_range_(>, 0) PULONG HashResultSize);

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
GetAverageReadTimeAtRoutine(_In_ PVOID RoutineAddress, _Out_ PUINT64 AverageTime);

STATIC
NTSTATUS
RegistryPathQueryTestSigningCallback(IN PWSTR ValueName,
                                     IN ULONG ValueType,
                                     IN PVOID ValueData,
                                     IN ULONG ValueLength,
                                     IN PVOID Context,
                                     IN PVOID EntryContext);

#ifdef ALLOC_PRAGMA
#        pragma alloc_text(PAGE, GetDriverImageSize)
#        pragma alloc_text(PAGE, GetModuleInformationByName)
#        pragma alloc_text(PAGE, StoreModuleExecutableRegionsInBuffer)
#        pragma alloc_text(PAGE, MapDiskImageIntoVirtualAddressSpace)
#        pragma alloc_text(PAGE, ComputeHashOfBuffer)
#        pragma alloc_text(PAGE, VerifyInMemoryImageVsDiskImage)
#        pragma alloc_text(PAGE, RetrieveInMemoryModuleExecutableSections)
#        pragma alloc_text(PAGE, GetNextSMBIOSStructureInTable)
#        pragma alloc_text(PAGE, GetStringAtIndexFromSMBIOSTable)
#        pragma alloc_text(PAGE, ParseSMBIOSTable)
#        pragma alloc_text(PAGE, ValidateProcessLoadedModule)
#        pragma alloc_text(PAGE, GetHardDiskDriveSerialNumber)
#        pragma alloc_text(PAGE, ScanForSignature)
#        pragma alloc_text(PAGE, InitiateEptFunctionAddressArrays)
#        pragma alloc_text(PAGE, DetectEptHooksInKeyFunctions)
#        pragma alloc_text(PAGE, RegistryPathQueryTestSigningCallback)
// #pragma alloc_text(PAGE, DetermineIfTestSigningIsEnabled)
#endif

/*
 * note: this can be put into its own function wihtout an IRP as argument then it can be used
 * in both the get driver image ioctl handler and the CopyDriverExecvutableRegions func
 */
NTSTATUS
GetDriverImageSize(_Inout_ PIRP Irp)
{
        PAGED_CODE();

        NTSTATUS                  status      = STATUS_UNSUCCESSFUL;
        LPCSTR                    driver_name = NULL;
        SYSTEM_MODULES            modules     = {0};
        PRTL_MODULE_EXTENDED_INFO driver_info = NULL;

        GetDriverName(&driver_name);

        if (!driver_name)
        {
                DEBUG_ERROR("GetDriverName failed with no status.");
                return status;
        }

        status = GetSystemModuleInformation(&modules);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("GetSystemModuleInformation failed with status %x", status);
                return status;
        }

        driver_info = FindSystemModuleByName(driver_name, &modules);

        if (!driver_info)
        {
                DEBUG_ERROR("FindSystemModuleByName failed with no status code");
                ExFreePoolWithTag(modules.address, SYSTEM_MODULES_POOL);
                return STATUS_NOT_FOUND;
        }

        status = ValidateIrpOutputBuffer(Irp, sizeof(ULONG));

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ValidateIrpOutputBuffer failed with status %x", status);
                goto end;
        }

        Irp->IoStatus.Information = sizeof(ULONG);
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &driver_info->ImageSize, sizeof(ULONG));

end:

        if (modules.address)
                ExFreePoolWithTag(modules.address, SYSTEM_MODULES_POOL);

        return status;
}

STATIC
NTSTATUS
GetModuleInformationByName(_Out_ PRTL_MODULE_EXTENDED_INFO ModuleInfo, _In_ LPCSTR ModuleName)
{
        PAGED_CODE();

        NTSTATUS                  status      = STATUS_UNSUCCESSFUL;
        LPCSTR                    driver_name = NULL;
        SYSTEM_MODULES            modules     = {0};
        PRTL_MODULE_EXTENDED_INFO driver_info = NULL;

        GetDriverName(&driver_name);

        if (!driver_name)
        {
                DEBUG_ERROR("GetDriverName failed with no status.");
                return status;
        }

        status = GetSystemModuleInformation(&modules);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("GetSystemModuleInformation failed with status %x", status);
                return status;
        }

        driver_info = FindSystemModuleByName(driver_name, &modules);

        if (!driver_info)
        {
                DEBUG_ERROR("FindSystemModuleByName failed with no status");
                ExFreePoolWithTag(modules.address, SYSTEM_MODULES_POOL);
                return STATUS_NOT_FOUND;
        }

        ModuleInfo->FileNameOffset = driver_info->FileNameOffset;
        ModuleInfo->ImageBase      = driver_info->ImageBase;
        ModuleInfo->ImageSize      = driver_info->ImageSize;

        RtlCopyMemory(
            ModuleInfo->FullPathName, driver_info->FullPathName, sizeof(ModuleInfo->FullPathName));

        if (modules.address)
                ExFreePoolWithTag(modules.address, SYSTEM_MODULES_POOL);

        return status;
}

#define PE_TYPE_32_BIT 0x10b

STATIC
NTSTATUS
StoreModuleExecutableRegionsInBuffer(_Outptr_result_bytebuffer_(*BytesWritten) PVOID* Buffer,
                                     _In_ PVOID                                       ModuleBase,
                                     _In_ SIZE_T                                      ModuleSize,
                                     _Out_ _Deref_out_range_(>, 0) PSIZE_T BytesWritten)
{
        PAGED_CODE();

        NTSTATUS              status                  = STATUS_ABANDONED;
        PIMAGE_DOS_HEADER     dos_header              = NULL;
        PLOCAL_NT_HEADER      nt_header               = NULL;
        PIMAGE_SECTION_HEADER section                 = NULL;
        ULONG                 total_packet_size       = 0;
        ULONG                 num_sections            = 0;
        ULONG                 num_executable_sections = 0;
        UINT64                buffer_base             = 0;
        ULONG                 bytes_returned          = 0;
        MM_COPY_ADDRESS       address                 = {0};
        ULONG                 buffer_size             = 0;

        if (!ModuleBase || !ModuleSize)
                return STATUS_INVALID_PARAMETER;

        /*
         * The reason we allocate a buffer to temporarily hold the section data is that
         * we don't know the total size until after we iterate over the sections meaning
         * we cant set Irp->IoStatus.Information to the size of our reponse until we
         * enumerate and count all executable sections for the file.
         */
        buffer_size = ModuleSize + sizeof(INTEGRITY_CHECK_HEADER);

        *BytesWritten = 0;
        *Buffer       = ExAllocatePool2(POOL_FLAG_NON_PAGED, buffer_size, POOL_TAG_INTEGRITY);

        if (*Buffer == NULL)
                return STATUS_MEMORY_NOT_ALLOCATED;

        /*
         * Note: Verifier doesn't like it when we map the module so rather then mapping it to our
         * address space we will simply use MmCopyMemory on the module to avoid upsetting verifier
         * :)
         */
        dos_header = (PIMAGE_DOS_HEADER)ModuleBase;

        /*
         * The IMAGE_DOS_HEADER.e_lfanew stores the offset of the IMAGE_NT_HEADER from the base
         * of the image.
         */
        nt_header = (struct _IMAGE_NT_HEADERS64*)((UINT64)ModuleBase + dos_header->e_lfanew);

        num_sections = nt_header->FileHeader.NumberOfSections;

        /*
         * The IMAGE_FIRST_SECTION macro takes in an IMAGE_NT_HEADER and returns the address of
         * the first section of the PE file.
         */
        section     = IMAGE_FIRST_SECTION(nt_header);
        buffer_base = (UINT64)*Buffer + sizeof(INTEGRITY_CHECK_HEADER);

        for (ULONG index = 0; index < num_sections; index++)
        {
                if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE)
                {
                        /*
                         * Note: MmCopyMemory will fail on discardable sections.
                         */
                        address.VirtualAddress = section;

                        status = MmCopyMemory((UINT64)buffer_base + total_packet_size,
                                              address,
                                              sizeof(IMAGE_SECTION_HEADER),
                                              MM_COPY_MEMORY_VIRTUAL,
                                              &bytes_returned);

                        if (!NT_SUCCESS(status))
                        {
                                DEBUG_ERROR("MmCopyMemory failed with status %x", status);
                                ExFreePoolWithTag(*Buffer, POOL_TAG_INTEGRITY);
                                *Buffer = NULL;
                                return status;
                        }

                        address.VirtualAddress = (UINT64)ModuleBase + section->PointerToRawData;

                        status = MmCopyMemory((UINT64)buffer_base + total_packet_size +
                                                  sizeof(IMAGE_SECTION_HEADER),
                                              address,
                                              section->SizeOfRawData,
                                              MM_COPY_MEMORY_VIRTUAL,
                                              &bytes_returned);

                        if (!NT_SUCCESS(status))
                        {
                                DEBUG_ERROR("MmCopyMemory failed with status %x", status);
                                ExFreePoolWithTag(*Buffer, POOL_TAG_INTEGRITY);
                                *Buffer = NULL;
                                return status;
                        }

                        total_packet_size += section->SizeOfRawData + sizeof(IMAGE_SECTION_HEADER);
                        num_executable_sections += 1;
                }

                section++;
        }

        INTEGRITY_CHECK_HEADER header   = {0};
        header.executable_section_count = num_executable_sections;
        header.total_packet_size        = total_packet_size + sizeof(INTEGRITY_CHECK_HEADER);

        RtlCopyMemory(*Buffer, &header, sizeof(INTEGRITY_CHECK_HEADER));

        *BytesWritten = total_packet_size + sizeof(INTEGRITY_CHECK_HEADER);

        return status;
}

STATIC
NTSTATUS
MapDiskImageIntoVirtualAddressSpace(_Inout_ PHANDLE                          SectionHandle,
                                    _Outptr_result_bytebuffer_(*Size) PVOID* Section,
                                    _In_ PUNICODE_STRING                     Path,
                                    _Out_ _Deref_out_range_(>, 0) PSIZE_T Size)
{
        PAGED_CODE();

        NTSTATUS          status            = STATUS_UNSUCCESSFUL;
        HANDLE            file_handle       = NULL;
        OBJECT_ATTRIBUTES object_attributes = {0};
        PIO_STATUS_BLOCK  pio_block         = NULL;
        UNICODE_STRING    path              = {0};

        *Section = NULL;
        *Size    = 0;

        RtlInitUnicodeString(&path, Path->Buffer);

        InitializeObjectAttributes(
            &object_attributes, &path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

        status = ZwOpenFile(&file_handle, GENERIC_READ, &object_attributes, &pio_block, NULL, NULL);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ZwOpenFile failed with status %x", status);
                return status;
        }

        object_attributes.ObjectName = NULL;

        /*
         * Its important that we set the SEC_IMAGE flag with the PAGE_READONLY
         * flag as we are mapping an executable image.
         */
        status = ZwCreateSection(SectionHandle,
                                 SECTION_ALL_ACCESS,
                                 &object_attributes,
                                 NULL,
                                 PAGE_READONLY,
                                 SEC_IMAGE,
                                 file_handle);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ZwCreateSection failed with status %x", status);
                ZwClose(file_handle);
                *SectionHandle = NULL;
                return status;
        }

        /*
         * Mapping a section with the flag SEC_IMAGE (see function above) tells the os we
         * are mapping an executable image. This then allows the OS to take care of parsing
         * the PE header and dealing with all relocations for us, meaning the mapped image
         * will be identical to the in memory image.
         */
        status = ZwMapViewOfSection(*SectionHandle,
                                    ZwCurrentProcess(),
                                    Section,
                                    NULL,
                                    NULL,
                                    NULL,
                                    Size,
                                    ViewUnmap,
                                    MEM_TOP_DOWN,
                                    PAGE_READONLY);

        if (!NT_SUCCESS(status))
        {
                /*
                 * It is of utmost importants to mark SectionHandle as null after closing the
                 * handle from inside this function since an error has occured. The reason this is
                 * so important is because we are not responsible for freeing the function if it
                 * succeeds and even if it fails, we still allocate a value to the handle via
                 * ZwCreateSection. Meaning when the caller goes to check if the handle is null, it
                 * will not be null and will cause a double free.
                 */
                DEBUG_ERROR("ZwMapViewOfSection failed with status %x", status);

                ZwClose(file_handle);
                ZwClose(*SectionHandle);

                *SectionHandle = NULL;

                return status;
        }

        ZwClose(file_handle);
        return status;
}

STATIC
NTSTATUS
ComputeHashOfBuffer(_In_ PVOID                                         Buffer,
                    _In_ ULONG                                         BufferSize,
                    _Outptr_result_bytebuffer_(*HashResultSize) PVOID* HashResult,
                    _Out_ _Deref_out_range_(>, 0) PULONG HashResultSize)
{
        PAGED_CODE();

        /*
         * Since the windows documentation for the BCrypt functions contain the worst variable
         * naming scheme in existence, I will try to explain what they do. (for my sake and any
         * readers who also aren't smart enough to understand their otherworldy naming convention)
         *
         * algo_handle: handle to our BCrypt algorithm
         * hash_handle: handle to our BCrypt hash
         * bytes_copied: number of bytes that were copied to the output buffer when using
         * BCryptGetProperty resulting_hash_size: this is the size of the final buffer hash, it
         * should be equal to 32 (sizeof SHA256 hash) hash_object_size: the size of the buffer that
         * will temporarily store our hash object hash_object: pointer to the buffer storing our
         * hash object which is used to hash our buffer resulting_hash: pointer to the buffer that
         * stores the resulting hash of our buffer, this is what we care about
         */

        NTSTATUS           status              = STATUS_ABANDONED;
        BCRYPT_ALG_HANDLE  algo_handle         = NULL;
        BCRYPT_HASH_HANDLE hash_handle         = NULL;
        ULONG              bytes_copied        = 0;
        ULONG              resulting_hash_size = 0;
        ULONG              hash_object_size    = 0;
        PCHAR              hash_object         = NULL;
        PCHAR              resulting_hash      = NULL;

        *HashResult     = NULL;
        *HashResultSize = 0;

        status = BCryptOpenAlgorithmProvider(&algo_handle, BCRYPT_SHA256_ALGORITHM, NULL, NULL);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("BCryptOpenAlogrithmProvider failed with status %x", status);
                goto end;
        }

        /*
         * Request the size of the hash object buffer, this is different then the buffer that
         * will store the resulting hash, instead this will be used to store the hash object
         * used to create the hash.
         */
        status = BCryptGetProperty(algo_handle,
                                   BCRYPT_OBJECT_LENGTH,
                                   (PCHAR)&hash_object_size,
                                   sizeof(ULONG),
                                   &bytes_copied,
                                   NULL);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("BCryptGetProperty failed with status %x", status);
                goto end;
        }

        hash_object = ExAllocatePool2(POOL_FLAG_NON_PAGED, hash_object_size, POOL_TAG_INTEGRITY);

        if (!hash_object)
        {
                status = STATUS_MEMORY_NOT_ALLOCATED;
                goto end;
        }

        /*
         * This call gets the size of the resulting hash, which we will use to allocate the
         * resulting hash buffer.
         */
        status = BCryptGetProperty(algo_handle,
                                   BCRYPT_HASH_LENGTH,
                                   (PCHAR)&resulting_hash_size,
                                   sizeof(ULONG),
                                   &bytes_copied,
                                   NULL);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("BCryptGetProperty failed with status %x", status);
                goto end;
        }

        resulting_hash =
            ExAllocatePool2(POOL_FLAG_NON_PAGED, resulting_hash_size, POOL_TAG_INTEGRITY);

        if (!resulting_hash)
        {
                status = STATUS_MEMORY_NOT_ALLOCATED;
                goto end;
        }

        /*
         * Here we create our hash object and store it in the hash_object buffer.
         */
        status = BCryptCreateHash(
            algo_handle, &hash_handle, hash_object, hash_object_size, NULL, NULL, NULL);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("BCryptCreateHash failed with status %x", status);
                goto end;
        }

        /*
         * This function hashes the buffer, but does NOT store it in our resulting buffer yet,
         * we need to call BCryptFinishHash to retrieve the final hash.
         */
        status = BCryptHashData(hash_handle, Buffer, BufferSize, NULL);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("BCryptHashData failed with status %x", status);
                goto end;
        }

        /*
         * As said in the previous comment, this is where we retrieve the final hash and store
         * it in our output buffer.
         */
        status = BCryptFinishHash(hash_handle, resulting_hash, resulting_hash_size, NULL);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("BCryptFinishHash failed with status %x", status);
                goto end;
        }

        *HashResult     = resulting_hash;
        *HashResultSize = resulting_hash_size;

end:

        if (algo_handle)
                BCryptCloseAlgorithmProvider(algo_handle, NULL);

        if (hash_handle)
                BCryptDestroyHash(hash_handle);

        if (hash_object)
                ExFreePoolWithTag(hash_object, POOL_TAG_INTEGRITY);

        return status;
}

/*
 * 1. map driver to memory
 * 2. store executable sections in buffer
 * 3. do the same with the in-memory module
 * 4. hash both buffers
 * 5. compare
 */
NTSTATUS
VerifyInMemoryImageVsDiskImage(
    //_In_ PIRP Irp
)
{
        PAGED_CODE();

        NTSTATUS                 status                = STATUS_UNSUCCESSFUL;
        UNICODE_STRING           path                  = {0};
        HANDLE                   section_handle        = NULL;
        PVOID                    section               = NULL;
        SIZE_T                   section_size          = 0;
        SIZE_T                   bytes_written         = 0;
        PVOID                    disk_buffer           = NULL;
        PVOID                    in_memory_buffer      = NULL;
        RTL_MODULE_EXTENDED_INFO module_info           = {0};
        UINT64                   disk_base             = 0;
        UINT64                   memory_base           = 0;
        PIMAGE_SECTION_HEADER    disk_text_header      = NULL;
        PIMAGE_SECTION_HEADER    memory_text_header    = NULL;
        PVOID                    disk_text_hash        = NULL;
        PVOID                    memory_text_hash      = NULL;
        ULONG                    disk_text_hash_size   = 0;
        ULONG                    memory_text_hash_size = 0;
        SIZE_T                   result                = 0;
        LPCSTR                   driver_name           = NULL;

        GetDriverPath(&path);
        GetDriverName(&driver_name);

        if (!driver_name)
        {
                DEBUG_ERROR("GetDriverName failed with no status");
                return status;
        }

        status =
            MapDiskImageIntoVirtualAddressSpace(&section_handle, &section, &path, &section_size);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("MapDiskImageIntoVirtualAddressSpace failed with status %x", status);
                return status;
        }

        status = StoreModuleExecutableRegionsInBuffer(
            &disk_buffer, section, section_size, &bytes_written);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("StoreModuleExecutableRegionsInBuffer failed with status %x", status);
                goto end;
        }

        /*
         * Parse the in-memory module
         */
        status = GetModuleInformationByName(&module_info, driver_name);

        if (!NT_SUCCESS(status) || !module_info.ImageBase || !module_info.ImageSize)
        {
                DEBUG_ERROR("GetModuleInformationByName failed with status %x", status);
                goto end;
        }

        status = StoreModuleExecutableRegionsInBuffer(
            &in_memory_buffer, module_info.ImageBase, module_info.ImageSize, &bytes_written);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("StoreModuleExecutableRegionsInBuffer failed with status %x", status);
                goto end;
        }

        disk_base   = (UINT64)((UINT64)disk_buffer + sizeof(INTEGRITY_CHECK_HEADER) +
                             sizeof(IMAGE_SECTION_HEADER));
        memory_base = (UINT64)((UINT64)in_memory_buffer + sizeof(INTEGRITY_CHECK_HEADER) +
                               sizeof(IMAGE_SECTION_HEADER));

        disk_text_header =
            (PIMAGE_SECTION_HEADER)((UINT64)disk_buffer + sizeof(INTEGRITY_CHECK_HEADER));
        memory_text_header =
            (PIMAGE_SECTION_HEADER)((UINT64)in_memory_buffer + sizeof(INTEGRITY_CHECK_HEADER));

        if (!disk_base || !memory_base || !disk_buffer || !in_memory_buffer)
        {
                DEBUG_ERROR("Buffer(s) are null. An error has occured.");
                goto end;
        }

        if (disk_text_header->SizeOfRawData != memory_text_header->SizeOfRawData)
        {
                /* report or bug check etc. */
                DEBUG_WARNING("Executable section sizes differ between images.");
                goto end;
        }

        status = ComputeHashOfBuffer(
            disk_base, disk_text_header->SizeOfRawData, &disk_text_hash, &disk_text_hash_size);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ComputeHashOfBuffer failed with status %x", status);
                goto end;
        }

        status = ComputeHashOfBuffer(memory_base,
                                     memory_text_header->SizeOfRawData,
                                     &memory_text_hash,
                                     &memory_text_hash_size);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ComputeHashOfBuffer failed with status %x", status);
                goto end;
        }

        if (memory_text_hash_size != disk_text_hash_size)
        {
                DEBUG_WARNING(
                    "Error with the hash algorithm, hash sizes are different. An error has occured.");
                goto end;
        }

        result = RtlCompareMemory(memory_text_hash, disk_text_hash, memory_text_hash_size);

        if (result != memory_text_hash_size)
        {
                /* report etc. bug check etc. */
                DEBUG_WARNING("Text section hashes are different, the section has been modified.");
                goto end;
        }

        DEBUG_INFO("Text sections are valid. Integrity check has been complete.");

end:

        if (section_handle)
                ZwClose(section_handle);

        if (section)
                ZwUnmapViewOfSection(ZwCurrentProcess(), section);

        if (disk_buffer)
                ExFreePoolWithTag(disk_buffer, POOL_TAG_INTEGRITY);

        if (in_memory_buffer)
                ExFreePoolWithTag(in_memory_buffer, POOL_TAG_INTEGRITY);

        if (memory_text_hash)
                ExFreePoolWithTag(memory_text_hash, POOL_TAG_INTEGRITY);

        if (disk_text_hash)
                ExFreePoolWithTag(disk_text_hash, POOL_TAG_INTEGRITY);

        return status;
}

NTSTATUS
RetrieveInMemoryModuleExecutableSections(_Inout_ PIRP Irp)
{
        PAGED_CODE();

        NTSTATUS                 status        = STATUS_UNSUCCESSFUL;
        LPCSTR                   driver_name   = NULL;
        SIZE_T                   bytes_written = NULL;
        PVOID                    buffer        = NULL;
        RTL_MODULE_EXTENDED_INFO module_info   = {0};

        GetDriverName(&driver_name);

        if (!driver_name)
        {
                DEBUG_ERROR("GetDriverName failed with no status");
                return status;
        }

        status = GetModuleInformationByName(&module_info, driver_name);

        if (!NT_SUCCESS(status) || !module_info.ImageBase || !module_info.ImageSize)
        {
                DEBUG_ERROR("GetModuleInformationByName failed with status %x", status);
                return status;
        }

        status = StoreModuleExecutableRegionsInBuffer(
            &buffer, module_info.ImageBase, module_info.ImageSize, &bytes_written);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("StoreModuleExecutableRegionsInBuffe failed with status %x", status);
                return status;
        }

        status = ValidateIrpOutputBuffer(Irp, bytes_written);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ValidateIrpOutputBuffer failed with status %x", status);
                goto end;
        }

        Irp->IoStatus.Information = bytes_written;

        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, buffer, bytes_written);

end:

        if (buffer)
                ExFreePoolWithTag(buffer, POOL_TAG_INTEGRITY);

        return status;
}
#define SMBIOS_TABLE    'RSMB'
#define NULL_TERMINATOR '\0'
/*
 * From line 727 in the SMBIOS Specification:
 *
 *    727 • Each structure shall be terminated by a double-null (0000h), either directly following
 * the 728   formatted area (if no strings are present) or directly following the last string. This
 * includes 729   system- and OEM-specific structures and allows upper-level software to easily
 * traverse the 730   structure table. (See structure-termination examples later in this clause.)
 *
 * TLDR is that if the first two characters proceeding the structure are null terminators, then
 * there are no strings, otherwise to find the end of the string section simply iterate until there
 * is a double null terminator.
 *
 * source: https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_2.7.1.pdf
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

        for (;;)
        {
                if (*current_char_in_strings == NULL_TERMINATOR &&
                    *next_char_in_strings == NULL_TERMINATOR)
                {
                        *CurrentStructure =
                            (PSMBIOS_TABLE_HEADER)((UINT64)next_char_in_strings + 1);
                        return;
                }

                current_char_in_strings++;
                next_char_in_strings++;
        }
}

/*
 * Remember that the string index does not start from the beginning of the struct. For example, lets
 * take RAW_SMBIOS_TABLE_02: the first string is NOT "Type" at index 0, the first string is
 * Manufacturer. So if we want to find the SerialNumber, the string index would be 4, as the
 * previous 3 values (after the header) are all strings. So remember, the index is into the number
 * of strings that exist for the given table, NOT the size of the structure or a values index into
 * the struct.
 *
 * Here we count the number of strings by incrementing the string_count each time we pass a null
 * terminator so we know when we're at the beginning of the target string.
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

        for (;;)
        {
                if (*current_string_char == NULL_TERMINATOR && *next_string_char == NULL_TERMINATOR)
                        return STATUS_NOT_FOUND;

                if (current_string_char_index >= BufferSize)
                        return STATUS_BUFFER_TOO_SMALL;

                if (string_count + 1 == Index)
                {
                        if (*current_string_char == NULL_TERMINATOR)
                                return STATUS_SUCCESS;

                        RtlCopyMemory((UINT64)Buffer + current_string_char_index,
                                      current_string_char,
                                      sizeof(CHAR));

                        current_string_char_index++;
                        goto increment;
                }

                if (*current_string_char == NULL_TERMINATOR)
                {
                        current_string_char_index = 0;
                        string_count++;
                }

        increment:

                current_string_char++;
                next_string_char++;
        }

        return STATUS_NOT_FOUND;
}

/* for generic intel */
// #define SMBIOS_SYSTEM_INFORMATION_TYPE_2_TABLE 2
// #define MOTHERBOARD_SERIAL_CODE_TABLE_INDEX    4

/* for testing purposes in vmware */
// #define VMWARE_SMBIOS_TABLE       1
// #define VMWARE_SMBIOS_TABLE_INDEX 3

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

        status = ExGetSystemFirmwareTable(SMBIOS_TABLE, 0, NULL, 0, &firmware_table_buffer_size);

        /*
         * Because we pass a null buffer here, the NTSTATUS result will be a BUFFER_TOO_SMALL error,
         * so to validate this function call we check the return bytes returned (which indicate
         * required buffer size) is above 0.
         */
        if (firmware_table_buffer_size == NULL)
        {
                DEBUG_ERROR("ExGetSystemFirmwareTable call 1 failed to get required buffer size.");
                return STATUS_BUFFER_TOO_SMALL;
        }

        firmware_table_buffer =
            ExAllocatePool2(POOL_FLAG_NON_PAGED, firmware_table_buffer_size, POOL_TAG_INTEGRITY);

        if (!firmware_table_buffer)
                return STATUS_MEMORY_NOT_ALLOCATED;

        status = ExGetSystemFirmwareTable(
            SMBIOS_TABLE, NULL, firmware_table_buffer, firmware_table_buffer_size, &bytes_returned);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ExGetSystemFirmwareTable call 2 failed with status %x", status);
                goto end;
        }

        smbios_data         = (PRAW_SMBIOS_DATA)firmware_table_buffer;
        smbios_table_header = (PSMBIOS_TABLE_HEADER)(&smbios_data->SMBIOSTableData[0]);

        /*
         * The System Information table is equal to Type == 2 and contains the serial number of the
         * motherboard in the computer among various other things.
         *
         * source: https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_2.7.1.pdf
         * line 823
         */
        while (smbios_table_header->Type != TableIndex)
                GetNextSMBIOSStructureInTable(&smbios_table_header);

        status =
            GetStringAtIndexFromSMBIOSTable(smbios_table_header, TableSubIndex, Buffer, BufferSize);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("GetStringAtIndexFromSMBIOSTable failed with status %x", status);
                goto end;
        }

end:

        if (firmware_table_buffer)
                ExFreePoolWithTag(firmware_table_buffer, POOL_TAG_INTEGRITY);

        return status;
}

/*
 * Because the infrastructure has already been setup to validate modules in the driver, that
 * is how I will validate the usermode modules as well. Another reason is that the win32 api
 * makes it very easy to take a snapshot of the modules and enumerate them with easy to use
 * functions and macros.
 *
 * 1. Take a snapshot of the modules in the process from our dll
 * 2. pass the image base, image size and the image path to our driver via an IRP
 * 3. from our driver, to first verify the in memory module, attach to our protected process
 *    and using the base + size simply use StoreModuleExecutableRegionsInBuffer()
 * 4. Next we use the path to map the image on disk into memory, and pass the image to
 *    StoreModuleExecutableRegionsInBuffer() just as we did before.
 * 5. With the 2 buffers that contain both images executable regions, we hash them and compare
 *    for anomalies.
 *
 * note: Its important to realise that since these are user mode modules, they are often hooked
 * by various legitimate programs - such as discord, nvidia etc. So this needs to be rethinked.
 */
NTSTATUS
ValidateProcessLoadedModule(_Inout_ PIRP Irp)
{
        PAGED_CODE();

        NTSTATUS                         status              = STATUS_UNSUCCESSFUL;
        BOOLEAN                          bstatus             = FALSE;
        PROCESS_MODULE_VALIDATION_RESULT validation_result   = {0};
        PPROCESS_MODULE_INFORMATION      module_info         = NULL;
        PKPROCESS                        process             = NULL;
        KAPC_STATE                       apc_state           = {0};
        PVOID                            in_memory_buffer    = NULL;
        PVOID                            disk_buffer         = NULL;
        PVOID                            in_memory_hash      = NULL;
        PVOID                            disk_hash           = NULL;
        ULONG                            in_memory_hash_size = 0;
        ULONG                            disk_hash_size      = 0;
        SIZE_T                           bytes_written       = 0;
        UNICODE_STRING                   module_path         = {0};
        HANDLE                           section_handle      = NULL;
        PVOID                            section             = NULL;
        ULONG                            section_size        = 0;

        status = ValidateIrpInputBuffer(Irp, sizeof(PROCESS_MODULE_INFORMATION));

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ValidateIrpInputBuffer failed with status %x", status);
                return status;
        }

        module_info = (PPROCESS_MODULE_INFORMATION)Irp->AssociatedIrp.SystemBuffer;

        GetProtectedProcessEProcess(&process);

        /*
         * Attach because the offsets given are from the process' context.
         */
        KeStackAttachProcess(process, &apc_state);

        status = StoreModuleExecutableRegionsInBuffer(
            &in_memory_buffer, module_info->module_base, module_info->module_size, &bytes_written);

        KeUnstackDetachProcess(&apc_state);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("StoreModuleExecutableRegionsInBuffer failed with status %x", status);
                goto end;
        }

        status = ComputeHashOfBuffer(
            in_memory_buffer, bytes_written, &in_memory_hash, &in_memory_hash_size);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ComputeHashOfBuffer failed with status %x", status);
                goto end;
        }

        RtlInitUnicodeString(&module_path, &module_info->module_path);

        status = MapDiskImageIntoVirtualAddressSpace(
            &section_handle, &section, &module_path, &section_size);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("MapDiskImageIntoVirtualAddressSpace failed with status %x", status);
                goto end;
        }

        status = StoreModuleExecutableRegionsInBuffer(
            &disk_buffer, section, section_size, &bytes_written);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("StoreModuleExecutableRegionsInbuffer 2 failed with status %x", status);
                goto end;
        }

        status = ComputeHashOfBuffer(disk_buffer, bytes_written, &disk_hash, &disk_hash_size);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ComputeHashOfBuffer 2 failed with status %x", status);
                goto end;
        }

        if (!in_memory_hash || !disk_hash)
                goto end;

        bstatus = RtlEqualMemory(in_memory_hash, disk_hash, in_memory_hash_size);

        status = ValidateIrpOutputBuffer(Irp, sizeof(PROCESS_MODULE_VALIDATION_RESULT));

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("Failed to validate IRP output buffer");
                goto end;
        }

        /*
         * Because each module is passed per IRP we don't need to send any reports
         * to the queue we can simply pass it back to usermode via the same IRP.
         * We also don't need to send any module information since usermode has everything
         * needed to file the report.
         */
        validation_result.is_module_valid = bstatus;

        Irp->IoStatus.Information = sizeof(PROCESS_MODULE_VALIDATION_RESULT);

        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer,
                      &validation_result,
                      sizeof(PROCESS_MODULE_VALIDATION_RESULT));

end:

        if (section_handle)
                ZwClose(section_handle);

        if (section)
                ZwUnmapViewOfSection(ZwCurrentProcess(), section);

        if (in_memory_buffer)
                ExFreePoolWithTag(in_memory_buffer, POOL_TAG_INTEGRITY);

        if (in_memory_hash)
                ExFreePoolWithTag(in_memory_hash, POOL_TAG_INTEGRITY);

        if (disk_buffer)
                ExFreePoolWithTag(disk_buffer, POOL_TAG_INTEGRITY);

        if (disk_hash)
                ExFreePoolWithTag(disk_hash, POOL_TAG_INTEGRITY);

        return status;
}

/*
 * TODO: Query PhysicalDrive%n to get the serial numbers for all harddrives, can use the command
 * "wmic diskdrive" check in console.
 */
NTSTATUS
GetHardDiskDriveSerialNumber(_Inout_ PVOID ConfigDrive0Serial, _In_ SIZE_T ConfigDrive0MaxSize)
{
        PAGED_CODE();

        NTSTATUS                   status                    = STATUS_UNSUCCESSFUL;
        HANDLE                     handle                    = NULL;
        OBJECT_ATTRIBUTES          attributes                = {0};
        IO_STATUS_BLOCK            status_block              = {0};
        STORAGE_PROPERTY_QUERY     storage_property          = {0};
        STORAGE_DESCRIPTOR_HEADER  storage_descriptor_header = {0};
        PSTORAGE_DEVICE_DESCRIPTOR device_descriptor         = NULL;
        UNICODE_STRING             physical_drive_path       = {0};
        PCHAR                      serial_number             = NULL;
        SIZE_T                     serial_length             = 0;

        RtlInitUnicodeString(&physical_drive_path, L"\\DosDevices\\PhysicalDrive0");

        /*
         * No need to use the flag OBJ_FORCE_ACCESS_CHECK since we arent passing a handle given
         * to us from usermode.
         */
        InitializeObjectAttributes(&attributes,
                                   &physical_drive_path,
                                   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                   NULL,
                                   NULL);

        status = ZwOpenFile(&handle, GENERIC_READ, &attributes, &status_block, NULL, NULL);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ZwOpenFile on PhysicalDrive0 failed with status %x", status);
                goto end;
        }

        storage_property.PropertyId = StorageDeviceProperty;
        storage_property.QueryType  = PropertyStandardQuery;

        status = ZwDeviceIoControlFile(handle,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &status_block,
                                       IOCTL_STORAGE_QUERY_PROPERTY,
                                       &storage_property,
                                       sizeof(STORAGE_PROPERTY_QUERY),
                                       &storage_descriptor_header,
                                       sizeof(STORAGE_DESCRIPTOR_HEADER));

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ZwDeviceIoControlFile first call failed with status %x", status);
                goto end;
        }

        device_descriptor = ExAllocatePool2(
            POOL_FLAG_NON_PAGED, storage_descriptor_header.Size, POOL_TAG_INTEGRITY);

        if (!device_descriptor)
        {
                status = STATUS_MEMORY_NOT_ALLOCATED;
                goto end;
        }

        status = ZwDeviceIoControlFile(handle,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &status_block,
                                       IOCTL_STORAGE_QUERY_PROPERTY,
                                       &storage_property,
                                       sizeof(STORAGE_PROPERTY_QUERY),
                                       device_descriptor,
                                       storage_descriptor_header.Size);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ZwDeviceIoControlFile second call failed with status %x", status);
                goto end;
        }

        if (device_descriptor->SerialNumberOffset > 0)
        {
                serial_number =
                    (PCHAR)((UINT64)device_descriptor + device_descriptor->SerialNumberOffset);
                serial_length = strnlen_s(serial_number, DEVICE_DRIVE_0_SERIAL_CODE_LENGTH) + 1;

                if (serial_length > ConfigDrive0MaxSize)
                {
                        DEBUG_ERROR(
                            "Serial length is greater then the allocated buffer size for the drives serial number.");
                        status = STATUS_BUFFER_TOO_SMALL;
                        goto end;
                }

                RtlCopyMemory(ConfigDrive0Serial, serial_number, serial_length);
        }

        DEBUG_VERBOSE("Successfully retrieved hard disk serial number.");
end:

        if (handle)
                ZwClose(handle);

        if (device_descriptor)
                ExFreePoolWithTag(device_descriptor, POOL_TAG_INTEGRITY);

        return status;
}

// VOID
// EnumeratePciDevices()
//{
//     NTSTATUS status;
//     PZZWSTR device_interfaces;
//     PWSTR list_base;
//     DEVPROPKEY key = { 0 };
//     UNICODE_STRING symbolic_link = { 0 };
//     WCHAR device_id[ 512 ];
//     PZZWSTR current_string = NULL;
//     SIZE_T string_length = 0;
//
//     /* PCI guid */
//     CONST GUID guid = { 0x5b45201d, 0xf2f2, 0x4f3b, 0x85, 0xbb, 0x30, 0xff, 0x1f, 0x95, 0x35,
//     0x99 };
//
//     status = IoGetDeviceInterfaces(
//         &guid,
//         NULL,
//         NULL,
//         &device_interfaces
//     );
//
//     if ( !NT_SUCCESS( status ) )
//     {
//         DEBUG_LOG( "IoGetDeviceInterfaces failed with status %x", status );
//         return;
//     }
//
//     current_string = device_interfaces;
//
//     while ( *current_string != NULL_TERMINATOR )
//     {
//         string_length = wcslen( current_string );
//
//         symbolic_link.Buffer = current_string;
//         symbolic_link.Length = string_length;
//         symbolic_link.MaximumLength = string_length;
//
//         DEBUG_LOG( "Device Interface: %wZ", symbolic_link );
//
//         current_string += symbolic_link.Length + 1;
//     }
//
//     ExFreePoolWithTag( device_interfaces, NULL );
// }

PVOID
ScanForSignature(_In_ PVOID  BaseAddress,
                 _In_ SIZE_T MaxLength,
                 _In_ LPCSTR Signature,
                 _In_ SIZE_T SignatureLength)
{
        PAGED_CODE();

        CHAR current_char     = 0;
        CHAR current_sig_char = 0;

        for (INT index = 0; index < MaxLength; index++)
        {
                for (INT sig_index = 0; sig_index < SignatureLength + 1; sig_index++)
                {
                        current_char     = *(PCHAR)((UINT64)BaseAddress + index + sig_index);
                        current_sig_char = Signature[sig_index];

                        if (sig_index == SignatureLength)
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
        UINT64 old_irql;

        MeasureInstructionRead(Address);

        old_irql = __readcr8();
        __writecr8(HIGH_LEVEL);

        _disable();

        for (ULONG iteration = 0; iteration < Count; iteration++)
                read_average += MeasureInstructionRead(Address);

        _enable();
        __writecr8(old_irql);

        DEBUG_VERBOSE("EPT Detection - Read Average: %llx", read_average);

        return read_average / Count;
}

#define EPT_CHECK_NUM_ITERATIONS      30
#define EPT_CONTROL_FUNCTIONS_COUNT   4
#define EPT_PROTECTED_FUNCTIONS_COUNT 2
#define EPT_MAX_FUNCTION_NAME_LENGTH  128
#define EPT_EXECUTION_TIME_MULTIPLIER 10

/*
 * Even though we test for the presence of a hypervisor, we should still test for the presence
 * of EPT hooks on key functions as this is a primary method for reversing AC's.
 *
 * Credits to momo5502 for the idea: https://momo5502.com/blog/?p=255
 *
 * [+] EPT: Read average: 14991c28f5c2
 * [+] no EPT: Read average: 28828f5c28
 *
 * On average a read when HyperDbg's !epthook is active is around ~125x longer. Will need to
 * continue testing with other HV's, however it is a good start.
 */
STATIC
NTSTATUS
GetAverageReadTimeAtRoutine(_In_ PVOID RoutineAddress, _Out_ PUINT64 AverageTime)
{
        if (!RoutineAddress || !AverageTime)
                return STATUS_UNSUCCESSFUL;

        *AverageTime = MeasureReads(RoutineAddress, EPT_CHECK_NUM_ITERATIONS);

        return *AverageTime == 0 ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}

/*
 * todo: encrypt both arrays
 *
 * The goal with the control functions is to find a reference time for an average read on a
 * function that is not EPT hooked. To accomplish this I've selected some arbitrary, rarely
 * used functions that shouldn't really ever have an EPT hook active on them. This will give
 * us a baseline that we can then average out to find a relatively accurate average read time.
 *
 * From here, we have an array of protected functions which are commonly hooked via EPT to
 * reverse anti cheats. We then check the read times of these functions and compare them to
 * the average of the read times for the control functions. If the read threshold exceeds a
 * multiple of 10, we can be fairly certain an EPT hook is active.
 *
 * Each time we measure the read we perform 30 iterations to ensure we get a consistent result
 * aswell as disabling interrupts + raising IRQL to ensure the test is as accurate as possible.
 *
 * The following open source Intel VT-X hv's w/ EPT functionality have been tested and detected
 * in a non vm environment:
 *
 * HyperDbg !epthook (https://github.com/HyperDbg/HyperDbg):  detected
 * DdiMon (https://github.com/tandasat/DdiMon):               detected
 */
WCHAR CONTROL_FUNCTIONS[EPT_CONTROL_FUNCTIONS_COUNT][EPT_MAX_FUNCTION_NAME_LENGTH] = {
    L"RtlAssert",
    L"PsAcquireSiloHardReference",
    L"PsDereferencePrimaryToken",
    L"ZwCommitEnlistment"};

WCHAR PROTECTED_FUNCTIONS[EPT_PROTECTED_FUNCTIONS_COUNT][EPT_MAX_FUNCTION_NAME_LENGTH] = {
    L"ExAllocatePoolWithTag", L"MmCopyMemory"};

/*
 * For whatever reason MmGetSystemRoutineAddress only works once, then every call
 * thereafter fails. So will be storing the routine addresses in arrays since they
 * dont change once the kernel is loaded.
 */
UINT64 CONTROL_FUNCTION_ADDRESSES[EPT_CONTROL_FUNCTIONS_COUNT]     = {0};
UINT64 PROTECTED_FUNCTION_ADDRESSES[EPT_PROTECTED_FUNCTIONS_COUNT] = {0};

STATIC
NTSTATUS
InitiateEptFunctionAddressArrays()
{
        PAGED_CODE();

        UNICODE_STRING current_function;

        for (INT index = 0; index < EPT_CONTROL_FUNCTIONS_COUNT; index++)
        {
                RtlInitUnicodeString(&current_function, CONTROL_FUNCTIONS[index]);
                CONTROL_FUNCTION_ADDRESSES[index] = MmGetSystemRoutineAddress(&current_function);

                if (!CONTROL_FUNCTION_ADDRESSES[index])
                        return STATUS_UNSUCCESSFUL;
        }

        for (INT index = 0; index < EPT_PROTECTED_FUNCTIONS_COUNT; index++)
        {
                RtlInitUnicodeString(&current_function, CONTROL_FUNCTIONS[index]);
                PROTECTED_FUNCTION_ADDRESSES[index] = MmGetSystemRoutineAddress(&current_function);

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

        status = InitiateEptFunctionAddressArrays();

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("InitiateEptFunctionAddressArrays failed with status %x", status);
                return status;
        }

        for (INT index = 0; index < EPT_CONTROL_FUNCTIONS_COUNT; index++)
        {
                status = GetAverageReadTimeAtRoutine(CONTROL_FUNCTION_ADDRESSES[index],
                                                     &instruction_time);

                if (!NT_SUCCESS(status))
                {
                        DEBUG_ERROR("DetectEptPresentOnFunction failed with status %x", status);
                        control_fails += 1;
                        continue;
                }

                control_time_sum += instruction_time;
        }

        if (control_time_sum == 0)
                return STATUS_UNSUCCESSFUL;

        control_average = control_time_sum / (EPT_CONTROL_FUNCTIONS_COUNT - control_fails);

        if (control_average == 0)
                return STATUS_ABANDONED;

        for (INT index = 0; index < EPT_PROTECTED_FUNCTIONS_COUNT; index++)
        {
                status = GetAverageReadTimeAtRoutine(PROTECTED_FUNCTION_ADDRESSES[index],
                                                     &instruction_time);

                if (!NT_SUCCESS(status))
                {
                        DEBUG_ERROR("DetectEptPresentOnFunction failed with status %x", status);
                        continue;
                }

                /* [+] EPT hook detected at function: ExAllocatePoolWithTag with execution time of:
                 * 149b7777777 */
                if (control_average * EPT_EXECUTION_TIME_MULTIPLIER < instruction_time)
                {
                        DEBUG_WARNING(
                            "EPT hook detected at function: %llx with execution time of: %llx",
                            PROTECTED_FUNCTION_ADDRESSES[index],
                            instruction_time);

                        /* close game etc. */
                }
                else
                {
                        DEBUG_INFO("No ept hook detected at function: %llx",
                                   PROTECTED_FUNCTION_ADDRESSES[index]);
                }
        }

        return status;
}

STATIC
VOID
FindWinLogonProcess(_In_ PPROCESS_LIST_ENTRY Entry, _In_opt_ PVOID Context)
{
        LPCSTR     process_name = NULL;
        PEPROCESS* process      = (PEPROCESS*)Context;

        if (!Context)
                return;

        process_name = PsGetProcessImageFileName(Entry->process);

        if (!strcmp(process_name, "winlogon.exe"))
        {
                DEBUG_VERBOSE("32 bit WinLogon.exe process found at address: %llx",
                              (UINT64)Entry->process);
                *process = Entry->process;
        }
}

//NTSTATUS
//ValidateSystemModules()
//{
//        NTSTATUS                  status             = STATUS_UNSUCCESSFUL;
//        BOOLEAN                   bstatus            = FALSE;
//        ANSI_STRING               ansi_string        = {0};
//        UNICODE_STRING            path               = {0};
//        ULONG                     section_size       = 0;
//        HANDLE                    section_handle     = NULL;
//        PVOID                     section            = NULL;
//        PVOID                     disk_buffer        = NULL;
//        ULONG                     disk_buffer_size   = 0;
//        PVOID                     disk_hash          = NULL;
//        ULONG                     disk_hash_size     = 0;
//        UINT64                    disk_text_base     = 0;
//        UINT64                    memory_text_base   = 0;
//        ULONG                     memory_text_size   = 0;
//        PVOID                     memory_hash        = NULL;
//        ULONG                     memory_hash_size   = 0;
//        PVOID                     memory_buffer      = NULL;
//        ULONG                     memory_buffer_size = 0;
//        ULONG                     result             = 0;
//        PEPROCESS                 process            = NULL;
//        KAPC_STATE                apc_state          = {0};
//        SYSTEM_MODULES            modules            = {0};
//        PRTL_MODULE_EXTENDED_INFO module_info        = NULL;
//        PIMAGE_SECTION_HEADER     disk_text_header   = NULL;
//        PIMAGE_SECTION_HEADER     memory_text_header = NULL;
//
//        DEBUG_VERBOSE("Beginning to validate system modules.");
//
//        status = GetSystemModuleInformation(&modules);
//
//        if (!NT_SUCCESS(status))
//        {
//                DEBUG_ERROR("GetSystemModuleInformation failed with status %s", status);
//                return status;
//        }
//
//        /*
//         * Since ntoskrnl itself is a process, we skip it here - we will validate it elsewhere.
//         */
//        for (INT index = 1; index < modules.module_count; index++)
//        {
//                module_info = (PRTL_MODULE_EXTENDED_INFO)((UINT64)modules.address +
//                                                          index * sizeof(RTL_MODULE_EXTENDED_INFO));
//
//                RtlInitAnsiString(&ansi_string, module_info->FullPathName);
//
//                if (!ansi_string.Buffer)
//                {
//                        DEBUG_ERROR("RtlInitAnsiString failed with status %x", status);
//                        ansi_string.Buffer        = NULL;
//                        ansi_string.Length        = 0;
//                        ansi_string.MaximumLength = 0;
//                        continue;
//                }
//
//                status = RtlAnsiStringToUnicodeString(&path, &ansi_string, TRUE);
//
//                if (!NT_SUCCESS(status))
//                {
//                        DEBUG_ERROR("RtlAnsiStringToUnicodeString failed with status %x", status);
//                        path.Buffer = NULL;
//                        goto free_iteration;
//                }
//
//                status = MapDiskImageIntoVirtualAddressSpace(
//                    &section_handle, &section, &path, &section_size);
//
//                if (!NT_SUCCESS(status))
//                {
//                        DEBUG_ERROR("MapDiskImageIntoVirtualAddressSpace failed with status %x",
//                                    status);
//                        goto free_iteration;
//                }
//
//                status = StoreModuleExecutableRegionsInBuffer(
//                    &disk_buffer, section, section_size, &disk_buffer_size);
//
//                if (!NT_SUCCESS(status))
//                {
//                        DEBUG_ERROR("StoreModuleExecutableRegionsInBuffer failed with status %x",
//                                    status);
//                        goto free_iteration;
//                }
//
//                /*
//                 * For win32k and related modules, because they are 32bit for us to read the memory
//                 * we need to attach to a 32 bit process. A simple check is that the 32 bit image
//                 * base wont be a valid address, while this is hacky it works. Then we simply attach
//                 * to a 32 bit address space, in our case winlogon, which will allow us to perform
//                 * the copy.
//                 */
//                if (!MmIsAddressValid(module_info->ImageBase))
//                {
//                        DEBUG_VERBOSE(
//                            "Win32k related module found, acquiring 32 bit address space...");
//
//                        EnumerateProcessListWithCallbackRoutine(FindWinLogonProcess, &process);
//
//                        if (!process)
//                                goto free_iteration;
//
//                        KeStackAttachProcess(process, &apc_state);
//
//                        status = StoreModuleExecutableRegionsInBuffer(&memory_buffer,
//                                                                      module_info->ImageBase,
//                                                                      module_info->ImageSize,
//                                                                      &memory_buffer_size);
//
//                        KeUnstackDetachProcess(&apc_state);
//                }
//                else
//                {
//                        status = StoreModuleExecutableRegionsInBuffer(&memory_buffer,
//                                                                      module_info->ImageBase,
//                                                                      module_info->ImageSize,
//                                                                      &memory_buffer_size);
//                }
//
//                if (!NT_SUCCESS(status))
//                {
//                        DEBUG_ERROR("StoreModuleExecutableRegionsInbuffer 2 failed with status %x",
//                                    status);
//                        goto free_iteration;
//                }
//
//                disk_text_base = (UINT64)disk_buffer + sizeof(INTEGRITY_CHECK_HEADER) +
//                                 sizeof(IMAGE_SECTION_HEADER);
//
//                memory_text_base = (UINT64)((UINT64)memory_buffer + sizeof(INTEGRITY_CHECK_HEADER) +
//                                            sizeof(IMAGE_SECTION_HEADER));
//
//                disk_text_header =
//                    (PIMAGE_SECTION_HEADER)((UINT64)disk_buffer + sizeof(INTEGRITY_CHECK_HEADER));
//
//                memory_text_header =
//                    (PIMAGE_SECTION_HEADER)((UINT64)memory_buffer + sizeof(INTEGRITY_CHECK_HEADER));
//
//                if (!disk_text_base || !memory_text_base || !disk_buffer || !memory_buffer ||
//                    !MmIsAddressValid(disk_buffer) || !MmIsAddressValid(memory_buffer))
//                {
//                        DEBUG_ERROR("Buffer(s) are null. An error has occured.");
//                        goto free_iteration;
//                }
//
//                if (disk_text_header->SizeOfRawData != memory_text_header->SizeOfRawData)
//                {
//                        DEBUG_WARNING("Executable section sizes differ between images.");
//                        goto free_iteration;
//                }
//
//                status = ComputeHashOfBuffer(
//                    disk_text_base, disk_text_header->SizeOfRawData, &disk_hash, &disk_hash_size);
//
//                if (!NT_SUCCESS(status))
//                {
//                        DEBUG_ERROR("ComputeHashOfBuffer failed with status %s", status);
//                        goto free_iteration;
//                }
//
//                status = ComputeHashOfBuffer(memory_text_base,
//                                             memory_text_header->SizeOfRawData,
//                                             &memory_hash,
//                                             &memory_hash_size);
//
//                if (!NT_SUCCESS(status))
//                {
//                        DEBUG_ERROR("ComputeHashOfBuffer failed with status %x", status);
//                        goto free_iteration;
//                }
//
//                if (!MmIsAddressValid(memory_hash) || !MmIsAddressValid(disk_hash))
//                        goto free_iteration;
//
//                result = RtlCompareMemory(memory_hash, disk_hash, memory_hash_size);
//
//                if (result = memory_text_header->SizeOfRawData)
//                        DEBUG_VERBOSE("Module executable sections are valid for the module: %s",
//                                      module_info->FullPathName);
//                else
//                        DEBUG_WARNING("Module regions are not valid for module: %s",
//                                      module_info->FullPathName);
//
//        free_iteration:
//
//                if (memory_buffer)
//                        ExFreePoolWithTag(memory_buffer, POOL_TAG_INTEGRITY);
//
//                if (memory_hash)
//                        ExFreePoolWithTag(memory_hash, POOL_TAG_INTEGRITY);
//
//                if (disk_buffer)
//                        ExFreePoolWithTag(disk_buffer, POOL_TAG_INTEGRITY);
//
//                if (disk_hash)
//                        ExFreePoolWithTag(disk_hash, POOL_TAG_INTEGRITY);
//
//        free_section:
//
//                if (section_handle)
//                        ZwClose(section_handle);
//
//                if (section)
//                        ZwUnmapViewOfSection(ZwCurrentProcess(), section);
//
//                /*
//                 * Its times like this where you see why allocating all local variables at the
//                 * beginning of the function may not be so ideal...
//                 */
//                if (path.Buffer)
//                {
//                        RtlFreeUnicodeString(&path);
//                        path.Buffer        = NULL;
//                        path.Length        = 0;
//                        path.MaximumLength = 0;
//                }
//
//                ansi_string.Buffer        = NULL;
//                ansi_string.Length        = 0;
//                ansi_string.MaximumLength = 0;
//
//                section_handle = NULL;
//                section        = NULL;
//                memory_buffer  = NULL;
//                memory_hash    = NULL;
//                disk_buffer    = NULL;
//                disk_hash      = NULL;
//        }
//
//        if (modules.address)
//                ExFreePoolWithTag(modules.address, SYSTEM_MODULES_POOL);
//
//        return status;
//}

STATIC
VOID
ValidateSystemModule(_In_ PRTL_MODULE_EXTENDED_INFO Module)
{
        NTSTATUS              status             = STATUS_UNSUCCESSFUL;
        BOOLEAN               bstatus            = FALSE;
        ANSI_STRING           ansi_string        = {0};
        UNICODE_STRING        path               = {0};
        ULONG                 section_size       = 0;
        HANDLE                section_handle     = NULL;
        PVOID                 section            = NULL;
        PVOID                 disk_buffer        = NULL;
        ULONG                 disk_buffer_size   = 0;
        PVOID                 disk_hash          = NULL;
        ULONG                 disk_hash_size     = 0;
        UINT64                disk_text_base     = 0;
        UINT64                memory_text_base   = 0;
        ULONG                 memory_text_size   = 0;
        PVOID                 memory_hash        = NULL;
        ULONG                 memory_hash_size   = 0;
        PVOID                 memory_buffer      = NULL;
        ULONG                 memory_buffer_size = 0;
        ULONG                 result             = 0;
        PEPROCESS             process            = NULL;
        KAPC_STATE            apc_state          = {0};
        PIMAGE_SECTION_HEADER disk_text_header   = NULL;
        PIMAGE_SECTION_HEADER memory_text_header = NULL;

        RtlInitAnsiString(&ansi_string, Module->FullPathName);

        if (!ansi_string.Buffer)
        {
                DEBUG_ERROR("RtlInitAnsiString failed with status %x", status);
                return;
        }

        status = RtlAnsiStringToUnicodeString(&path, &ansi_string, TRUE);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("RtlAnsiStringToUnicodeString failed with status %x", status);
                goto end;
        }

        status =
            MapDiskImageIntoVirtualAddressSpace(&section_handle, &section, &path, &section_size);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("MapDiskImageIntoVirtualAddressSpace failed with status %x", status);
                goto end;
        }

        status = StoreModuleExecutableRegionsInBuffer(
            &disk_buffer, section, section_size, &disk_buffer_size);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("StoreModuleExecutableRegionsInBuffer failed with status %x", status);
                goto end;
        }

        /*
         * For win32k and related modules, because they are 32bit for us to read the
         * memory we need to attach to a 32 bit process. A simple check is that the
         * 32 bit image base wont be a valid address, while this is hacky it works.
         * Then we simply attach to a 32 bit address space, in our case winlogon,
         * which will allow us to perform the copy.
         */
        if (!MmIsAddressValid(Module->ImageBase))
        {
                DEBUG_VERBOSE("Win32k related module found, acquiring 32 bit address space...");

                EnumerateProcessListWithCallbackRoutine(FindWinLogonProcess, &process);

                if (!process)
                        goto end;

                KeStackAttachProcess(process, &apc_state);

                status = StoreModuleExecutableRegionsInBuffer(
                    &memory_buffer, Module->ImageBase, Module->ImageSize, &memory_buffer_size);

                KeUnstackDetachProcess(&apc_state);
        }
        else
        {
                status = StoreModuleExecutableRegionsInBuffer(
                    &memory_buffer, Module->ImageBase, Module->ImageSize, &memory_buffer_size);
        }

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("StoreModuleExecutableRegionsInbuffer 2 failed with status %x", status);
                goto end;
        }

        disk_text_base =
            (UINT64)disk_buffer + sizeof(INTEGRITY_CHECK_HEADER) + sizeof(IMAGE_SECTION_HEADER);

        memory_text_base = (UINT64)((UINT64)memory_buffer + sizeof(INTEGRITY_CHECK_HEADER) +
                                    sizeof(IMAGE_SECTION_HEADER));

        disk_text_header =
            (PIMAGE_SECTION_HEADER)((UINT64)disk_buffer + sizeof(INTEGRITY_CHECK_HEADER));

        memory_text_header =
            (PIMAGE_SECTION_HEADER)((UINT64)memory_buffer + sizeof(INTEGRITY_CHECK_HEADER));

        if (!disk_text_base || !memory_text_base || !disk_buffer || !memory_buffer ||
            !MmIsAddressValid(disk_buffer) || !MmIsAddressValid(memory_buffer))
        {
                DEBUG_ERROR("Buffer(s) are null. An error has occured.");
                goto end;
        }

        if (disk_text_header->SizeOfRawData != memory_text_header->SizeOfRawData)
        {
                DEBUG_WARNING("Executable section sizes differ between images.");
                goto end;
        }

        status = ComputeHashOfBuffer(
            disk_text_base, disk_text_header->SizeOfRawData, &disk_hash, &disk_hash_size);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ComputeHashOfBuffer failed with status %s", status);
                goto end;
        }

        status = ComputeHashOfBuffer(
            memory_text_base, memory_text_header->SizeOfRawData, &memory_hash, &memory_hash_size);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("ComputeHashOfBuffer failed with status %x", status);
                goto end;
        }

        if (!MmIsAddressValid(memory_hash) || !MmIsAddressValid(disk_hash))
                goto end;

        result = RtlCompareMemory(memory_hash, disk_hash, memory_hash_size);

        if (result = memory_text_header->SizeOfRawData)
                DEBUG_VERBOSE(
                    "Thread: %lx: Module executable sections are valid for the module: %s",
                    PsGetCurrentThreadId(),
                    Module->FullPathName);
        else
                DEBUG_WARNING("Thread: %lx: Module regions are not valid for module: %s",
                              PsGetCurrentThreadId(),
                              Module->FullPathName);

end:

        if (memory_buffer)
                ExFreePoolWithTag(memory_buffer, POOL_TAG_INTEGRITY);

        if (memory_hash)
                ExFreePoolWithTag(memory_hash, POOL_TAG_INTEGRITY);

        if (disk_buffer)
                ExFreePoolWithTag(disk_buffer, POOL_TAG_INTEGRITY);

        if (disk_hash)
                ExFreePoolWithTag(disk_hash, POOL_TAG_INTEGRITY);

        if (section_handle)
                ZwClose(section_handle);

        if (section)
                ZwUnmapViewOfSection(ZwCurrentProcess(), section);

        if (path.Buffer)
                RtlFreeUnicodeString(&path);
}

STATIC
VOID
SystemModuleVerificationDispatchFunction(_In_ PDEVICE_OBJECT          DeviceObject,
                                         _In_ PSYS_MODULE_VAL_CONTEXT Context)
{
        InterlockedIncrement(&Context->active_thread_count);

        LONG count = InterlockedExchange(&Context->current_count, Context->current_count);
        LONG max   = count + Context->block_size;

        for (; count < max && count < Context->total_count; count++)
        {
                if (!InterlockedCompareExchange(
                        &Context->dispatcher_info[count].validated, TRUE, FALSE))
                {
                        ValidateSystemModule(&Context->module_info[count]);
                }
        }

        if (count == Context->total_count)
                InterlockedExchange(&Context->complete, TRUE);

        InterlockedExchange(&Context->current_count, count);
        InterlockedDecrement(&Context->active_thread_count);
}

#define VALIDATION_BLOCK_SIZE 25

/*
 * Multithreaded delayed priority work items improve 1% lows by 25% and reduces average PC latency
 * by 10% compared to traditional multithreading. This is important as having high average fps but
 * low 1% lows just leads to stuttery gameplay which in competitive multiplayer games is simply not
 * alright. Overall still room for improvement but from a statistical and feel which the gameplay is
 * much smoother (tested in cs2).
 *
 * A potential idea for further improvement is finding the cores with the least cpu usages and
 * setting the worker threads affinity accordingly.
 */
STATIC
NTSTATUS
InitialiseSystemModuleVerificationContext(PSYS_MODULE_VAL_CONTEXT Context)
{
        NTSTATUS                  status           = STATUS_UNSUCCESSFUL;
        SYSTEM_MODULES            modules          = {0};
        PMODULE_DISPATCHER_HEADER dispatcher_array = NULL;

        status = GetSystemModuleInformation(&modules);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("GetSystemModuleInformation failed with status %x", status);
                return status;
        }

        dispatcher_array = ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                           modules.module_count * sizeof(MODULE_DISPATCHER_HEADER),
                                           POOL_TAG_INTEGRITY);
        if (!dispatcher_array)
        {
                ExFreePoolWithTag(modules.address, SYSTEM_MODULES_POOL);
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        Context->active_thread_count = 0;
        Context->active              = TRUE;
        Context->complete            = FALSE;
        Context->dispatcher_info     = dispatcher_array;
        Context->module_info         = modules.address;
        Context->current_count       = 0;
        Context->total_count         = modules.module_count;
        Context->block_size          = VALIDATION_BLOCK_SIZE;

        return status;
}

VOID
FreeWorkItems(_In_ PSYS_MODULE_VAL_CONTEXT Context)
{
        for (INT index = 0; index < VERIFICATION_THREAD_COUNT; index++)
        {
                if (Context->work_items[index])
                {
                        IoFreeWorkItem(Context->work_items[index]);
                        Context->work_items[index] = 0ull;
                }
        }
}

STATIC
VOID
FreeModuleVerificationItems(_In_ PSYS_MODULE_VAL_CONTEXT Context)
{
        if (!Context->active_thread_count)
        {
                if (Context->module_info)
                        ExFreePoolWithTag(Context->module_info, SYSTEM_MODULES_POOL);
                if (Context->dispatcher_info)
                        ExFreePoolWithTag(Context->dispatcher_info, POOL_TAG_INTEGRITY);
        }
}

NTSTATUS
SystemModuleVerificationDispatcher()
{
        NTSTATUS                status    = STATUS_UNSUCCESSFUL;
        PSYS_MODULE_VAL_CONTEXT context   = NULL;
        PIO_WORKITEM            work_item = NULL;

        GetSystemModuleValidationContext(&context);

        if (context->complete)
        {
                DEBUG_VERBOSE("System modules integrity check complete. Freeing items.");
                context->active = FALSE;
                FreeModuleVerificationItems(context);
                FreeWorkItems(context);
                return STATUS_SUCCESS;
        }

        if (!context->active)
        {
                DEBUG_VERBOSE("Context not active, generating new one");

                status = InitialiseSystemModuleVerificationContext(context);

                if (!NT_SUCCESS(status))
                {
                        DEBUG_ERROR(
                            "InitialiseSystemModuleVerificationContext failed with status %x",
                            status);
                        return status;
                }
        }
        else
        {
                FreeWorkItems(context);
        }

        for (INT index = 0; index < VERIFICATION_THREAD_COUNT; index++)
        {
                work_item = IoAllocateWorkItem(GetDriverDeviceObject());

                if (!work_item)
                        continue;

                IoQueueWorkItem(
                    work_item, SystemModuleVerificationDispatchFunction, DelayedWorkQueue, context);

                context->work_items[index] = work_item;
        }

        DEBUG_VERBOSE("Finished validating modules via dispatcher threads");

        return STATUS_SUCCESS;
}

/*
 * After some further research it appears that performing integrity checks the same way as
 * validating other modules is not as straight forward as there are many (thousands) of hooks that
 * take place in a legitmate ntoskrnl.exe image.
 *
 * Initial ideas are to maybe only validate the text sections of key functions such as MmCopyMemory,
 * though this is quite manual and the potential to miss functions could be common.
 *
 * Need to do some more research & testing in this department.
 */
NTSTATUS
ValidateNtoskrnl()
{
        NTSTATUS                  status             = STATUS_UNSUCCESSFUL;
        SIZE_T                    bytes_written      = 0;
        KAPC_STATE                apc_state          = {0};
        PVOID                     memory_buffer      = NULL;
        ULONG                     memory_buffer_size = 0;
        PRTL_MODULE_EXTENDED_INFO module_info        = NULL;
        SYSTEM_MODULES            modules            = {0};

        status = GetSystemModuleInformation(&modules);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("GetSystemModuleInformation failed with status %x", status);
                return status;
        }

        module_info = (PRTL_MODULE_EXTENDED_INFO)modules.address;

        DEBUG_VERBOSE("Module base: %llx", module_info->ImageBase);

        PVOID buffer =
            ExAllocatePool2(POOL_FLAG_NON_PAGED, module_info->ImageSize, POOL_TAG_INTEGRITY);

        if (!buffer)
                goto end;

        status = MmCopyVirtualMemory(PsInitialSystemProcess,
                                     module_info->ImageBase,
                                     PsGetCurrentProcess(),
                                     buffer,
                                     module_info->ImageSize,
                                     KernelMode,
                                     &bytes_written);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("MmCopyVirtualMemory failed with status %x", status);
                goto end;
        }

        status = StoreModuleExecutableRegionsInBuffer(
            &memory_buffer, buffer, module_info->ImageSize, &memory_buffer_size);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("StoreModuleExecutableRegionsInBuffer failed with status %x", status);
                goto end;
        }

        DEBUG_VERBOSE("buf size: %lx", memory_buffer_size);

end:

        if (buffer)
                ExFreePoolWithTag(buffer, POOL_TAG_INTEGRITY);

        if (modules.address)
                ExFreePoolWithTag(modules.address, SYSTEM_MODULES_POOL);

        return status;
}

NTSTATUS
GetOsVersionInformation(_Out_ PRTL_OSVERSIONINFOW VersionInfo)
{
        NTSTATUS           status = STATUS_ABANDONED;
        RTL_OSVERSIONINFOW info   = {0};

        if (!VersionInfo)
                return STATUS_INVALID_PARAMETER;

        status = RtlGetVersion(&info);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("RtlGetVersion failed with status %x", status);
                return status;
        }

        VersionInfo->dwBuildNumber       = info.dwBuildNumber;
        VersionInfo->dwMajorVersion      = info.dwMajorVersion;
        VersionInfo->dwMinorVersion      = info.dwMinorVersion;
        VersionInfo->dwOSVersionInfoSize = info.dwOSVersionInfoSize;
        VersionInfo->dwPlatformId        = info.dwPlatformId;

        RtlCopyMemory(
            VersionInfo->szCSDVersion, info.szCSDVersion, sizeof(VersionInfo->szCSDVersion));

        return status;
}