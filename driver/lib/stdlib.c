#include "stdlib.h"

VOID
IntCopyMemory(_In_ PVOID Destination, _In_ PVOID Source, _In_ SIZE_T Length)
{
    PUCHAR dest = (PUCHAR)Destination;
    PUCHAR src = (PUCHAR)Source;

    for (SIZE_T index = 0; index < Length; index++)
        dest[index] = src[index];
}

SIZE_T
IntStringLength(_In_ PCHAR String, _In_ SIZE_T MaxLength)
{
    SIZE_T length = 0;

    while (length < MaxLength && String[length] != '\0')
        length++;

    return length;
}

SIZE_T
IntCompareMemory(_In_ PVOID Source1, _In_ PVOID Source2, _In_ SIZE_T Length)
{
    PUCHAR src1 = (PUCHAR)Source1;
    PUCHAR src2 = (PUCHAR)Source2;

    for (SIZE_T i = 0; i < Length; i++) {
        if (src1[i] != src2[i])
            return i;
    }

    return Length;
}

PCHAR
IntFindSubstring(_In_ PCHAR String1, _In_ PCHAR String2)
{
    if (*String2 == '\0')
        return String1;

    for (PCHAR s1 = String1; *s1 != '\0'; s1++) {
        PCHAR p1 = s1;
        PCHAR p2 = String2;

        while (*p1 != '\0' && *p2 != '\0' && *p1 == *p2) {
            p1++;
            p2++;
        }

        if (*p2 == '\0')
            return s1;
    }

    return NULL;
}

INT32
IntCompareString(_In_ PCHAR String1, _In_ PCHAR String2)
{
    while (*String1 != '\0' && *String2 != '\0') {
        if (*String1 != *String2)
            return (INT32)(*String1 - *String2);

        String1++;
        String2++;
    }

    return (INT32)(*String1 - *String2);
}

PWCHAR
IntWideStringCopy(_In_ PWCHAR Destination, _In_ PWCHAR Source)
{
    PWCHAR dest = Destination;

    while ((*dest++ = *Source++) != '\0')
        ;

    return Destination;
}