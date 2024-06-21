#ifndef CRYPT_H
#define CRYPT_H

#include "common.h"



VOID
CryptEncryptImportsArray(_In_ PUINT64 Array, _In_ UINT32 Entries);

UINT64
CryptDecryptImportsArrayEntry(_In_ PUINT64 Array,
                              _In_ UINT32  Entries,
                              _In_ UINT32  EntryIndex);

NTSTATUS
CryptInitialiseProvider();

UINT32
CryptRequestRequiredBufferLength(_In_ UINT32 BufferLength);

NTSTATUS
CryptEncryptBuffer(_In_ PVOID Buffer, _In_ UINT32 BufferLength);

NTSTATUS
CryptInitialiseSessionCryptObjects();

VOID
CryptCloseSessionCryptObjects();

VOID
CryptCloseProvider();

NTSTATUS
TpmExtractEndorsementKey();

UINT64
CryptXorKeyGenerate_uint64();

VOID
CryptEncryptPointer64(_Inout_ PUINT64 Pointer, _In_ UINT64 Key);

VOID
CryptDecryptPointer64(_Inout_ PUINT64 Pointer, _In_ UINT64 Key);

UINT64
CryptDecryptPointerOutOfPlace64(_In_ PUINT64 Pointer, _In_ UINT64 Key);

#endif