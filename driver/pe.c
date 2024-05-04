#include "pe.h"

PNT_HEADER_64
PeGetNtHeader(_In_ PVOID Image)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)Image;

    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    return CONVERT_RELATIVE_ADDRESS(PNT_HEADER_64, Image, dos->e_lfanew);
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

PIMAGE_EXPORT_DIRECTORY
PeGetExportDirectory(_In_ PVOID                 Image,
                     _In_ PIMAGE_DATA_DIRECTORY ExportDataDirectory)
{
    if (!ExportDataDirectory->VirtualAddress || !ExportDataDirectory->Size)
        return NULL;

    return CONVERT_RELATIVE_ADDRESS(
        PIMAGE_EXPORT_DIRECTORY, Image, ExportDataDirectory->VirtualAddress);
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
        CONVERT_RELATIVE_ADDRESS(PUINT32, Image, export->AddressOfFunctions);
    PUINT32 names =
        CONVERT_RELATIVE_ADDRESS(PUINT32, Image, export->AddressOfNames);
    PUINT16 ordinals =
        CONVERT_RELATIVE_ADDRESS(PUINT16, Image, export->AddressOfNameOrdinals);

    for (UINT32 index = 0; index < export->NumberOfNames; index++) {
        PCHAR export = CONVERT_RELATIVE_ADDRESS(PCHAR, Image, names[index]);
        if (!strcmp(Name, export))
            return CONVERT_RELATIVE_ADDRESS(
                PVOID, Image, functions[ordinals[index]]);
    }

    return NULL;
}