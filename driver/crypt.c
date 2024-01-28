#include "crypt.h"

#include <immintrin.h>

#define TEMP_KEY 0x5a

VOID
CryptEncryptBufferInPlace(_In_ PVOID Buffer, _In_ UINT32 Size)
{
        PCHAR entry = (PCHAR)Buffer;

        for (UINT32 index = 0; index < Size; index++)
        {
                entry[index] ^= TEMP_KEY;
        }
}

VOID
CryptDecryptBufferInPlace(_In_ PVOID Buffer, _In_ UINT32 Size)
{
        CryptEncryptBufferInPlace(Buffer, Size);
}