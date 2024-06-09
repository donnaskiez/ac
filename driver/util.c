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
UnicodeToCharBufString(_In_ PUNICODE_STRING UnicodeString,
                       _Out_ PVOID          OutBuffer,
                       _In_ UINT32          OutBufferSize)
{
    ANSI_STRING string = {0};
    NTSTATUS    status = STATUS_UNSUCCESSFUL;

    status = RtlUnicodeStringToAnsiString(&string, UnicodeString, TRUE);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("RtlUnicodeStringToAnsiString: %x", status);
        return status;
    }

    if (string.Length > OutBufferSize) {
        RtlFreeAnsiString(&string);
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(OutBuffer, string.Buffer, string.Length);
    RtlFreeAnsiString(&string);

    return STATUS_SUCCESS;
}

#define BYTES_PER_LINE 16

VOID
DumpBufferToKernelDebugger(_In_ PCHAR Buffer, _In_ UINT32 BufferLength)
{
    UINT32 i = 0;
    UINT32 j = 0;

    for (i = 0; i < BufferLength; i += BYTES_PER_LINE) {
        HEX_DUMP("%08x  ", i);

        for (j = 0; j < BYTES_PER_LINE; ++j) {
            if (i + j < BufferLength) {
                HEX_DUMP("%02x ", (unsigned char)Buffer[i + j]);
            }
            else {
                HEX_DUMP("   ");
            }
        }

        HEX_DUMP("  ");

        for (j = 0; j < BYTES_PER_LINE; ++j) {
            if (i + j < BufferLength) {
                char c = Buffer[i + j];
                if (c >= 32 && c <= 126) {
                    HEX_DUMP("%c", c);
                }
                else {
                    HEX_DUMP(".");
                }
            }
        }

        HEX_DUMP("\n");
    }
}