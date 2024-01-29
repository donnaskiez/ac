#ifndef CRYPT_H
#define CRYPT_H

#include "common.h"

VOID
CryptEncryptImportsArray(_In_ PUINT64 Array, _In_ UINT32 Entries);

UINT64
CryptDecryptImportsArrayEntry(_In_ PUINT64 Array, _In_ UINT32 Entries, _In_ UINT32 EntryIndex);

#endif