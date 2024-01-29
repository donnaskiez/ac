#include "crypt.h"

#include <immintrin.h>
#include "imports.h"

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
         * Here we break down the import array into blocks of 32 bytes. Each block is loaded into an
         * SSE register, xored with the key, and then copied back into the array.
         */
        for (UINT32 block_index = 0; block_index < block_count; block_index++)
        {
                __m256i current_block = {0};
                __m256i load_block    = {0};
                __m256i xored_block   = {0};

                RtlCopyMemory(&current_block, &Array[block_index * block_size], sizeof(__m256i));

                load_block  = _mm256_loadu_si256(&current_block);
                xored_block = _mm256_xor_si256(load_block, CryptGenerateSseXorKey());

                RtlCopyMemory(&Array[block_index * block_size], &xored_block, sizeof(__m256i));
        }
}

STATIC
INLINE
__m256i
CryptDecryptImportBlock(_In_ PUINT64 Array, _In_ UINT32 BlockIndex)
{
        __m256i load_block = {0};
        UINT32  block_size = sizeof(__m256i) / sizeof(UINT64);

        RtlCopyMemory(&load_block, &Array[BlockIndex * block_size], sizeof(__m256i));

        return _mm256_xor_si256(load_block, CryptGenerateSseXorKey());
}

STATIC
INLINE
VOID
CryptFindContainingBlockForArrayIndex(_In_ UINT32   EntryIndex,
                                      _In_ UINT32   BlockSize,
                                      _Out_ PUINT32 ContainingBlockIndex,
                                      _Out_ PUINT32 BlockSubIndex)
{
        UINT32 containing_block = EntryIndex;
        UINT32 block_index      = 0;

        if (EntryIndex < BlockSize)
        {
                *ContainingBlockIndex = 0;
                *BlockSubIndex        = EntryIndex;
                return;
        }

        if (EntryIndex == BlockSize)
        {
                *ContainingBlockIndex = 1;
                *BlockSubIndex        = 0;
                return;
        }

        while (containing_block % BlockSize != 0)
        {
                containing_block--;
                block_index++;
        }

        *ContainingBlockIndex = containing_block / BlockSize;
        *BlockSubIndex        = block_index;
}

UINT64
CryptDecryptImportsArrayEntry(_In_ PUINT64 Array, _In_ UINT32 Entries, _In_ UINT32 EntryIndex)
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

        if (block_sub_index < 2)
        {
                original_half = _mm256_extracti128_si256(original_block, 0);

                if (block_sub_index < 1)
                        pointer = _mm_extract_epi64(original_half, 0);
                else
                        pointer = _mm_extract_epi64(original_half, 1);
        }
        else
        {
                original_half = _mm256_extracti128_si256(original_block, 1);

                if (block_sub_index == 2)
                        pointer = _mm_extract_epi64(original_half, 0);
                else
                        pointer = _mm_extract_epi64(original_half, 1);
        }

        return pointer;
}