#ifndef CRYPT_H
#define CRYPT_H

#include "common.h"

#define XOR_ROTATION_AMT 13

FORCEINLINE
VOID
CryptEncryptPointer64(_Inout_ PUINT64 Pointer, _In_ UINT64 Key)
{
    *Pointer = _rotl64(*Pointer ^ Key, XOR_ROTATION_AMT);
}

FORCEINLINE
VOID
CryptDecryptPointer64(_Inout_ PUINT64 Pointer, _In_ UINT64 Key)
{
    *Pointer = _rotr64(*Pointer, XOR_ROTATION_AMT) ^ Key;
}

FORCEINLINE
UINT64
CryptDecryptPointerOutOfPlace64(_In_ PUINT64 Pointer, _In_ UINT64 Key)
{
    volatile UINT64 temp = *Pointer;
    CryptDecryptPointer64(&temp, Key);
    return temp;
}

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

NTSTATUS
CryptHashBuffer_sha256(_In_ PVOID   Buffer,
                       _In_ ULONG   BufferSize,
                       _Out_ PVOID* HashResult,
                       _Out_ PULONG HashResultSize);

#endif