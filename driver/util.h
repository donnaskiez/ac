#ifndef UTIL_H
#define UTIL_H

#include "common.h"

LARGE_INTEGER
GenerateRandSeed();

NTSTATUS
MapAndReadPhysical(_In_ UINT64 PhysicalAddress,
                   _In_ UINT32 ReadLength,
                   _Out_ PVOID OutputBuffer,
                   _In_ UINT32 OutputBufferLength);

NTSTATUS
UnicodeToCharBufString(_In_ PUNICODE_STRING UnicodeString,
                       _Out_ PVOID          OutBuffer,
                       _In_ UINT32          OutBufferSize);

VOID
DumpBufferToKernelDebugger(_In_ PCHAR Buffer, _In_ UINT32 BufferLength);

#endif