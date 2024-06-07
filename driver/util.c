#include "common.h"

LARGE_INTEGER
GenerateRandSeed()
{
    LARGE_INTEGER system_time = {0};
    LARGE_INTEGER up_time     = {0};
    LARGE_INTEGER seed        = {0};

    KeQuerySystemTime(&system_time);
    KeQueryTickCount(&up_time);

    seed.QuadPart = system_time.QuadPart ^ up_time.QuadPart;
    return seed;
}

NTSTATUS
MapAndReadPhysical(_In_ UINT64 PhysicalAddress,
                   _In_ UINT32 ReadLength,
                   _Out_ PVOID OutputBuffer,
                   _In_ UINT32 OutputBufferLength)
{
    PVOID            va = NULL;
    PHYSICAL_ADDRESS pa = {.QuadPart = PhysicalAddress};

    if (ReadLength > OutputBufferLength)
        return STATUS_BUFFER_TOO_SMALL;

    va = MmMapIoSpace(pa, ReadLength, MmNonCached);

    if (!va)
        return STATUS_UNSUCCESSFUL;

    switch (ReadLength) {
    case 1: READ_REGISTER_BUFFER_UCHAR(va, OutputBuffer, 1); break;
    case 2: READ_REGISTER_BUFFER_USHORT(va, OutputBuffer, 1); break;
    case 4: READ_REGISTER_BUFFER_ULONG(va, OutputBuffer, 1); break;
    case 8: READ_REGISTER_BUFFER_ULONG64(va, OutputBuffer, 1); break;
    }

    MmUnmapIoSpace(va, ReadLength);
    return STATUS_SUCCESS;
}

NTSTATUS
UnicodeToCharBufString(_In_ PUNICODE_STRING UnicodeString, _Out_ PCHAR OutBuffer)
{

}