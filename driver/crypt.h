#ifndef CRYPT_H
#define CRYPT_H

#include "common.h"

VOID
CryptEncryptBufferInPlace(_In_ PVOID Buffer, _In_ UINT32 Size);

VOID
CryptDecryptBufferInPlace(_In_ PVOID Buffer, _In_ UINT32 Size);

#endif