#include "crypt.h"

#include "../common.h"

#include <bcrypt.h>
#include <iomanip>
#include <iostream>
#include <stdio.h>
#include <winternl.h>

#pragma comment(lib, "bcrypt.lib")

BCRYPT_ALG_HANDLE alg_handle = NULL;
BCRYPT_KEY_HANDLE key_handle = NULL;

namespace crypt {
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)

namespace globals {

#define TEST_AES_KEY_LENGTH 0x32
#define TEST_AES_IV_LENGTH 0x16

const unsigned char TEST_KEY[] = {
    0xAA, 0x50, 0xA7, 0x00, 0x79, 0xF1, 0x6C, 0x2D, 0x6B, 0xAD, 0xAC,
    0x19, 0x18, 0x66, 0xFB, 0xEF, 0xCA, 0x9B, 0x6D, 0x3E, 0xA3, 0x7D,
    0x2D, 0xF6, 0x10, 0x95, 0xB3, 0xB3, 0x8D, 0x34, 0x69, 0xF1};

const unsigned char TEST_IV[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
                                 0x0C, 0x0D, 0x0E, 0x0F};

PBCRYPT_KEY_DATA_BLOB_HEADER blob = nullptr;

static PUCHAR key_object = NULL;
static UINT32 key_object_length = 0;

} // namespace globals

boolean initialise_session_key() {
  globals::blob = reinterpret_cast<PBCRYPT_KEY_DATA_BLOB_HEADER>(
      malloc(sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + sizeof(globals::TEST_KEY)));

  if (!globals::blob)
    return false;

  globals::blob->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
  globals::blob->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
  globals::blob->cbKeyData = sizeof(globals::TEST_KEY);
  memcpy((void *)((UINT64)globals::blob + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER)),
         (void *)globals::TEST_KEY, sizeof(globals::TEST_KEY));

  return true;
}

boolean initialise_provider() {
  UINT32 data_copied = 0;
  NTSTATUS status =
      BCryptOpenAlgorithmProvider(&alg_handle, BCRYPT_AES_ALGORITHM, NULL, 0);

  if (!NT_SUCCESS(status)) {
    LOG_ERROR("BCryptOpenAlgorithmProvider: %x", status);
    return false;
  }

  status = BCryptGetProperty(alg_handle, BCRYPT_OBJECT_LENGTH,
                             (PUCHAR)&globals::key_object_length,
                             sizeof(UINT32), (PULONG)&data_copied, 0);

  if (!NT_SUCCESS(status)) {
    LOG_ERROR("BCryptGetProperty: %x", status);
    return false;
  }

  globals::key_object = (PUCHAR)malloc(globals::key_object_length);

  if (!globals::key_object)
    return false;

  if (!initialise_session_key())
    return false;

  status = BCryptImportKey(
      alg_handle, NULL, BCRYPT_KEY_DATA_BLOB, &key_handle, globals::key_object,
      globals::key_object_length, (PUCHAR)globals::blob,
      sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + sizeof(globals::TEST_KEY), 0);

  if (!NT_SUCCESS(status)) {
    LOG_ERROR("BCryptImportKey: %x", status);
    return false;
  }

  return true;
}

boolean decrypt_packet(void *packet, uint32_t packet_length) {
  ULONG data_copied = 0;
  unsigned char local_iv[sizeof(globals::TEST_IV)] = {0};
  memcpy((void *)local_iv, (void *)globals::TEST_IV, sizeof(globals::TEST_IV));

  void* buffer = (void*)((UINT64)packet + 16);
  uint32_t length = packet_length - 16;

  NTSTATUS status = BCryptDecrypt(
      key_handle, (PUCHAR)buffer, length, NULL, (PUCHAR)local_iv,
      sizeof(globals::TEST_IV), (PUCHAR)buffer, length, &data_copied, 0);

  if (!NT_SUCCESS(status)) {
    LOG_ERROR("BCryptDecrypt: %x", status);
    return false;
  }

  return true;
}

uint32_t get_padded_packet_size(uint32_t original_size) {
  uint32_t remainder = original_size % 16;

  if (remainder != 0) {
    original_size += 16 - remainder;
  }

  return original_size;
}

const unsigned char *get_test_key() { return globals::TEST_KEY; }
const unsigned char *get_test_iv() { return globals::TEST_IV; }
} // namespace crypt
