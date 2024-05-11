#pragma once

#include <cstdint>
#include <windows.h>

namespace crypt {
const unsigned char *get_test_key();
const unsigned char *get_test_iv();
boolean initialise_provider();
boolean decrypt_packet(void *packet, uint32_t packet_length);
uint32_t get_padded_packet_size(uint32_t original_size);
} // namespace crypt