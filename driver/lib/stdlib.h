#ifndef STDLIB_H
#define STDLIB_H

#include "../common.h"

VOID
IntCopyMemory(_In_ PVOID Destination, _In_ PVOID Source, _In_ SIZE_T Length);


SIZE_T
IntStringLength(_In_ PCHAR String, _In_ SIZE_T MaxLength);

SIZE_T
IntCompareMemory(_In_ PVOID Source1, _In_ PVOID Source2, _In_ SIZE_T Length);

PCHAR
IntFindSubstring(_In_ PCHAR String1, _In_ PCHAR String2);

INT32
IntCompareString(_In_ PCHAR String1, _In_ PCHAR String2);

PWCHAR
IntWideStringCopy(_In_ PWCHAR Destination, _In_ PWCHAR Source);

#endif