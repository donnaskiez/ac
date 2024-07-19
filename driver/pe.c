#include "pe.h"

PNT_HEADER_64
PeGetNtHeaderSafe(_In_ PVOID Image)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)Image;

    if (!MmIsAddressValid(Image))
        return NULL;

    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    return RVA(PNT_HEADER_64, Image, dos->e_lfanew);
}

PNT_HEADER_64
PeGetNtHeader(_In_ PVOID Image)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)Image;

    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    return RVA(PNT_HEADER_64, Image, dos->e_lfanew);
}

PIMAGE_DATA_DIRECTORY
PeGetExportDataDirectory(_In_ PVOID Image)
{
    PNT_HEADER_64 nt = PeGetNtHeader(Image);

    if (IMAGE_DIRECTORY_ENTRY_EXPORT >= nt->OptionalHeader.NumberOfRvaAndSizes)
        return NULL;

    return (PIMAGE_DATA_DIRECTORY)&nt->OptionalHeader
        .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
}

PIMAGE_DATA_DIRECTORY
PeGetExportDataDirectorySafe(_In_ PVOID Image)
{
    PNT_HEADER_64 nt = PeGetNtHeader(Image);

    if (!MmIsAddressValid(Image))
        return NULL;

    if (IMAGE_DIRECTORY_ENTRY_EXPORT >= nt->OptionalHeader.NumberOfRvaAndSizes)
        return NULL;

    return (PIMAGE_DATA_DIRECTORY)&nt->OptionalHeader
        .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
}

PIMAGE_EXPORT_DIRECTORY
PeGetExportDirectory(_In_ PVOID                 Image,
                     _In_ PIMAGE_DATA_DIRECTORY ExportDataDirectory)
{
    if (!ExportDataDirectory->VirtualAddress || !ExportDataDirectory->Size)
        return NULL;

    return RVA(
        PIMAGE_EXPORT_DIRECTORY, Image, ExportDataDirectory->VirtualAddress);
}

PIMAGE_EXPORT_DIRECTORY
PeGetExportDirectorySafe(_In_ PVOID                 Image,
                     _In_ PIMAGE_DATA_DIRECTORY ExportDataDirectory)
{
    if (!MmIsAddressValid(Image))
        return NULL;

    if (!ExportDataDirectory->VirtualAddress || !ExportDataDirectory->Size)
        return NULL;

    return RVA(
        PIMAGE_EXPORT_DIRECTORY, Image, ExportDataDirectory->VirtualAddress);
}

UINT32
GetSectionCount(_In_ PNT_HEADER_64 Header)
{
    return Header->FileHeader.NumberOfSections;
}

UINT32
GetSectionCountSafe(_In_ PNT_HEADER_64 Header)
{
    if (!MmIsAddressValid(Header))
        return NULL;

    return Header->FileHeader.NumberOfSections;
}

PVOID
PeFindExportByName(_In_ PVOID Image, _In_ PCHAR Name)
{
    ANSI_STRING           target   = {0};
    PNT_HEADER_64         nt       = NULL;
    PIMAGE_DATA_DIRECTORY data     = NULL;
    PIMAGE_EXPORT_DIRECTORY export = NULL;

    RtlInitAnsiString(&target, Name);

    nt = PeGetNtHeader(Image);

    if (!nt)
        return NULL;

    data = PeGetExportDataDirectory(Image);

    if (!data)
        return NULL;

    export = PeGetExportDirectory(Image, data);

    if (!export)
        return NULL;

    PUINT32 functions =
        RVA(PUINT32, Image, export->AddressOfFunctions);
    PUINT32 names =
        RVA(PUINT32, Image, export->AddressOfNames);
    PUINT16 ordinals =
        RVA(PUINT16, Image, export->AddressOfNameOrdinals);

    for (UINT32 index = 0; index < export->NumberOfNames; index++) {
        PCHAR export = RVA(PCHAR, Image, names[index]);
        if (!strcmp(Name, export))
            return RVA(
                PVOID, Image, functions[ordinals[index]]);
    }

    return NULL;
}