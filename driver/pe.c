#include "pe.h"

typedef struct IMAGE_NT_HEADER* PIMAGE_NT_HEADER;

PIMAGE_NT_HEADER
PeGetNtHeader(_In_ PVOID Image)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)Image;

    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    return CONVERT_RELATIVE_ADDRESS(PIMAGE_NT_HEADER, Image, dos->e_lfanew);
}

PIMAGE_EXPORT_DIRECTORY
PeGetExportDirectory(_In_ PVOID Image)
{
    PIMAGE_NT_HEADER nt = PeGetNtHeader(Image);
}