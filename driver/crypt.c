#include "crypt.h"

#include "imports.h"
#include "session.h"
#include "driver.h"
#include "util.h"

#include "types/tpm20.h"
#include "types/tpmptp.h"

#include <immintrin.h>
#include <bcrypt.h>

#define XOR_KEY_1 0x1122334455667788
#define XOR_KEY_2 0x0011223344556677
#define XOR_KEY_3 0x5566778899AABBCC
#define XOR_KEY_4 0x66778899AABBCCDD

STATIC
__m256i
CryptGenerateSseXorKey()
{
    return _mm256_set_epi64x(XOR_KEY_1, XOR_KEY_2, XOR_KEY_3, XOR_KEY_4);
}

VOID
CryptEncryptImportsArray(_In_ PUINT64 Array, _In_ UINT32 Entries)
{
    UINT32 block_size  = sizeof(__m256i) / sizeof(UINT64);
    UINT32 block_count = Entries / block_size;

    /*
     * Here we break down the import array into blocks of 32 bytes. Each
     * block is loaded into an SSE register, xored with the key, and then
     * copied back into the array.
     */
    for (UINT32 block_index = 0; block_index < block_count; block_index++) {
        __m256i current_block = {0};
        __m256i load_block    = {0};
        __m256i xored_block   = {0};

        RtlCopyMemory(
            &current_block, &Array[block_index * block_size], sizeof(__m256i));

        load_block  = _mm256_loadu_si256(&current_block);
        xored_block = _mm256_xor_si256(load_block, CryptGenerateSseXorKey());

        RtlCopyMemory(
            &Array[block_index * block_size], &xored_block, sizeof(__m256i));
    }
}

STATIC
INLINE
__m256i
CryptDecryptImportBlock(_In_ PUINT64 Array, _In_ UINT32 BlockIndex)
{
    __m256i load_block = {0};
    UINT32  block_size = sizeof(__m256i) / sizeof(UINT64);

    RtlCopyMemory(
        &load_block, &Array[BlockIndex * block_size], sizeof(__m256i));

    return _mm256_xor_si256(load_block, CryptGenerateSseXorKey());
}

FORCEINLINE
INLINE
VOID
CryptFindContainingBlockForArrayIndex(_In_ UINT32   EntryIndex,
                                      _In_ UINT32   BlockSize,
                                      _Out_ PUINT32 ContainingBlockIndex,
                                      _Out_ PUINT32 BlockSubIndex)
{
    UINT32 containing_block = EntryIndex;
    UINT32 block_index      = 0;

    if (EntryIndex < BlockSize) {
        *ContainingBlockIndex = 0;
        *BlockSubIndex        = EntryIndex;
        return;
    }

    if (EntryIndex == BlockSize) {
        *ContainingBlockIndex = 1;
        *BlockSubIndex        = 0;
        return;
    }

    while (containing_block % BlockSize != 0) {
        containing_block--;
        block_index++;
    }

    *ContainingBlockIndex = containing_block / BlockSize;
    *BlockSubIndex        = block_index;
}

UINT64
CryptDecryptImportsArrayEntry(_In_ PUINT64 Array,
                              _In_ UINT32  Entries,
                              _In_ UINT32  EntryIndex)
{
    __m256i original_block         = {0};
    __m128i original_half          = {0};
    UINT32  block_size             = sizeof(__m256i) / sizeof(UINT64);
    UINT32  containing_block_index = 0;
    UINT32  block_sub_index        = 0;
    UINT64  pointer                = 0;

    CryptFindContainingBlockForArrayIndex(
        EntryIndex, block_size, &containing_block_index, &block_sub_index);

    original_block = CryptDecryptImportBlock(Array, containing_block_index);

    if (block_sub_index < 2) {
        original_half = _mm256_extracti128_si256(original_block, 0);

        if (block_sub_index < 1)
            pointer = _mm_extract_epi64(original_half, 0);
        else
            pointer = _mm_extract_epi64(original_half, 1);
    }
    else {
        original_half = _mm256_extracti128_si256(original_block, 1);

        if (block_sub_index == 2)
            pointer = _mm_extract_epi64(original_half, 0);
        else
            pointer = _mm_extract_epi64(original_half, 1);
    }

    return pointer;
}

STATIC
PBCRYPT_KEY_DATA_BLOB_HEADER
CryptBuildBlobForKeyImport(_In_ PACTIVE_SESSION Session)
{
    PBCRYPT_KEY_DATA_BLOB_HEADER blob =
        ExAllocatePool2(POOL_FLAG_NON_PAGED,
                        sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + AES_256_KEY_SIZE,
                        POOL_TAG_CRYPT);

    if (!blob)
        return NULL;

    blob->dwMagic   = BCRYPT_KEY_DATA_BLOB_MAGIC;
    blob->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    blob->cbKeyData = AES_256_KEY_SIZE;

    RtlCopyMemory((UINT64)blob + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER),
                  Session->aes_key,
                  AES_256_KEY_SIZE);

    return blob;
}

#define AES_256_BLOCK_SIZE 16

UINT32
CryptRequestRequiredBufferLength(_In_ UINT32 BufferLength)
{
    // status = BCryptEncrypt(session->key_handle,
    //                        lol,
    //                        BufferLength,
    //                        NULL,
    //                        session->iv,
    //                        sizeof(session->iv),
    //                        NULL,
    //                        0,
    //                        RequiredLength,
    //                        0);

    // if (!NT_SUCCESS(status))
    //     DEBUG_ERROR("CryptRequestRequiredBufferLength -> BCryptEncrypt: %x",
    //                 status);

    return (BufferLength + AES_256_BLOCK_SIZE - 1) / AES_256_BLOCK_SIZE *
           AES_256_BLOCK_SIZE;
}

/* Encrypts in place! */
NTSTATUS
CryptEncryptBuffer(_In_ PVOID Buffer, _In_ UINT32 BufferLength)
{
    NTSTATUS        status                        = STATUS_UNSUCCESSFUL;
    UINT32          data_copied                   = 0;
    PACTIVE_SESSION session                       = GetActiveSession();
    UCHAR           local_iv[sizeof(session->iv)] = {0};
    UINT64          buffer                        = (UINT64)Buffer;
    UINT32          length                        = BufferLength;

    /* The IV is consumed during every encrypt / decrypt procedure, so to ensure
     * we have access to the iv we need to create a local copy.*/
    RtlCopyMemory(local_iv, session->iv, sizeof(session->iv));

    /* We arent encrypting the first 16 bytes */
    buffer = buffer + AES_256_BLOCK_SIZE;
    length = length - AES_256_BLOCK_SIZE;

    status = BCryptEncrypt(session->key_handle,
                           buffer,
                           length,
                           NULL,
                           local_iv,
                           sizeof(local_iv),
                           buffer,
                           length,
                           &data_copied,
                           0);

    if (!NT_SUCCESS(status))
        DEBUG_ERROR("CryptEncryptBuffer -> BCryptEncrypt: %x", status);

    return status;
}

/* Lock is held */
VOID
CryptCloseSessionCryptObjects()
{
    PACTIVE_SESSION session = GetActiveSession();

    if (session->key_handle) {
        BCryptDestroyKey(session->key_handle);
        session->key_handle = NULL;
    }

    if (session->key_object) {
        ExFreePoolWithTag(session->key_object, POOL_TAG_CRYPT);
        session->key_object = NULL;
    }

    session->key_object_length = 0;
}

NTSTATUS
CryptInitialiseSessionCryptObjects()
{
    NTSTATUS                     status      = STATUS_UNSUCCESSFUL;
    UINT32                       data_copied = 0;
    PACTIVE_SESSION              session     = GetActiveSession();
    PBCRYPT_KEY_DATA_BLOB_HEADER blob        = NULL;
    BCRYPT_ALG_HANDLE*           handle      = GetCryptAlgHandle();

    blob = CryptBuildBlobForKeyImport(session);

    if (!blob)
        return STATUS_INSUFFICIENT_RESOURCES;

    status = BCryptGetProperty(*handle,
                               BCRYPT_OBJECT_LENGTH,
                               &session->key_object_length,
                               sizeof(UINT32),
                               &data_copied,
                               0);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("BCryptGetProperty: %x", status);
        goto end;
    }

    session->key_object = ExAllocatePool2(
        POOL_FLAG_NON_PAGED, session->key_object_length, POOL_TAG_CRYPT);

    if (!session->key_object) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }

    DEBUG_INFO("key object: %llx, key_object_length: %lx",
               session->key_object,
               session->key_object_length);

    status =
        BCryptImportKey(*handle,
                        NULL,
                        BCRYPT_KEY_DATA_BLOB,
                        &session->key_handle,
                        session->key_object,
                        session->key_object_length,
                        blob,
                        sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + AES_256_KEY_SIZE,
                        0);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("BCryptImportKey: %x", status);
        ExFreePoolWithTag(session->key_object, POOL_TAG_CRYPT);
        goto end;
    }

end:
    if (blob)
        ExFreePoolWithTag(blob, POOL_TAG_CRYPT);

    return status;
}

NTSTATUS
CryptInitialiseProvider()
{
    NTSTATUS           status = STATUS_UNSUCCESSFUL;
    BCRYPT_ALG_HANDLE* handle = GetCryptAlgHandle();

    status = BCryptOpenAlgorithmProvider(
        handle, BCRYPT_AES_ALGORITHM, NULL, BCRYPT_PROV_DISPATCH);

    if (!NT_SUCCESS(status))
        DEBUG_ERROR("BCryptOpenAlgorithmProvider: %x", status);

    return status;
}

VOID
CryptCloseProvider()
{
    BCRYPT_ALG_HANDLE* handle = GetCryptAlgHandle();
    BCryptCloseAlgorithmProvider(*handle, 0);
}

/*
 * Basic TPM EK Extraction implementation. Various sources were used alongside
 * the various TPM specification manuals.
 *
 * https://github.com/tianocore/edk2
 * https://github.com/microsoft/ms-tpm-20-ref
 * https://github.com/SyncUD/tpm-mmio
 */

#define TPM20_INTEL_BASE_PHYSICAL 0xfed40000
#define TPM20_OBJECT_HANDLE_EK    0x81010001
#define TPM20_PTP_NO_VALID_CHIP   0xFF

STATIC
BOOLEAN
TpmIsPlatformSupported()
{
    PSYSTEM_INFORMATION system = GetDriverConfigSystemInformation();

    if (system->processor == AuthenticAmd) {
        DEBUG_ERROR(
            "TpmPlatformSuport unavailable on process type: AuthenticAmd");
        return FALSE;
    }

    if (system->processor == GenuineIntel)
        return TRUE;

    return FALSE;
}

STATIC
NTSTATUS
TpmCheckPtpRegisterPresence(_In_ PVOID Register, _Out_ PUINT32 Result)
{
    UINT8    value  = 0;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    *Result = FALSE;

    status = MapAndReadPhysical(Register, sizeof(value), &value, sizeof(value));

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("MapAndReadPhysical: %x", status);
        return status;
    }

    if (value != TPM20_PTP_NO_VALID_CHIP)
        *Result = TRUE;

    return status;
}

FORCEINLINE
STATIC
TPM2_PTP_INTERFACE_TYPE
TpmExtractInterfaceTypeFromCapabilityAndId(
    _In_ PTP_CRB_INTERFACE_IDENTIFIER*  Identifier,
    _In_ PTP_FIFO_INTERFACE_CAPABILITY* Capability)
{
    if ((Identifier->Bits.InterfaceType ==
         PTP_INTERFACE_IDENTIFIER_INTERFACE_TYPE_CRB) &&
        (Identifier->Bits.InterfaceVersion ==
         PTP_INTERFACE_IDENTIFIER_INTERFACE_VERSION_CRB) &&
        (Identifier->Bits.CapCRB != 0)) {
        return Tpm2PtpInterfaceCrb;
    }

    if ((Identifier->Bits.InterfaceType ==
         PTP_INTERFACE_IDENTIFIER_INTERFACE_TYPE_FIFO) &&
        (Identifier->Bits.InterfaceVersion ==
         PTP_INTERFACE_IDENTIFIER_INTERFACE_VERSION_FIFO) &&
        (Identifier->Bits.CapFIFO != 0) &&
        (Capability->Bits.InterfaceVersion ==
         INTERFACE_CAPABILITY_INTERFACE_VERSION_PTP)) {
        return Tpm2PtpInterfaceFifo;
    }

    if (Identifier->Bits.InterfaceType ==
        PTP_INTERFACE_IDENTIFIER_INTERFACE_TYPE_TIS) {
        return Tpm2PtpInterfaceTis;
    }

    return Tpm2PtpInterfaceMax;
}

/*
 * Assumes the presence of the register has already been confirmed via
 * TpmCheckPtpRegisterPresence.
 */
STATIC
NTSTATUS
TpmGetPtpInterfaceType(_In_ PVOID                     Register,
                       _Out_ TPM2_PTP_INTERFACE_TYPE* InterfaceType)
{
    NTSTATUS                      status     = STATUS_UNSUCCESSFUL;
    PTP_CRB_INTERFACE_IDENTIFIER  identifier = {0};
    PTP_FIFO_INTERFACE_CAPABILITY capability = {0};

    *InterfaceType = 0;

    status = MapAndReadPhysical(
        (UINT64)(&((PTP_CRB_REGISTERS*)Register)->InterfaceId),
        sizeof(PTP_CRB_INTERFACE_IDENTIFIER),
        &identifier,
        sizeof(PTP_CRB_INTERFACE_IDENTIFIER));

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("MapAndReadPhysical: %x", status);
        return status;
    }

    status = MapAndReadPhysical(
        (UINT64) & ((PTP_FIFO_REGISTERS*)Register)->InterfaceCapability,
        sizeof(PTP_FIFO_INTERFACE_CAPABILITY),
        &capability,
        sizeof(PTP_FIFO_INTERFACE_CAPABILITY));

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("MapAndReadPhysical: %x", status);
        return status;
    }

    *InterfaceType =
        TpmExtractInterfaceTypeFromCapabilityAndId(&identifier, &capability);

    return status;
}



NTSTATUS
TpmExtractEndorsementKey()
{
    NTSTATUS                status   = STATUS_UNSUCCESSFUL;
    BOOLEAN                 presence = FALSE;
    TPM2_PTP_INTERFACE_TYPE type     = {0};

    if (!TpmIsPlatformSupported())
        return STATUS_NOT_SUPPORTED;

    status = TpmCheckPtpRegisterPresence(TPM20_INTEL_BASE_PHYSICAL, &presence);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("TpmCheckPtpRegisterPresence: %x", status);
        return status;
    }

    if (!presence) {
        DEBUG_INFO("TPM2.0 PTP Presence not detected.");
        return STATUS_UNSUCCESSFUL;
    }

    status = TpmGetPtpInterfaceType(TPM20_INTEL_BASE_PHYSICAL, &type);

    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("TpmGetPtpInterfaceType: %x", status);
        return status;
    }

    DEBUG_INFO("TPM2.0 PTP Interface Type: %x", (UINT32)type);
    return status;
}