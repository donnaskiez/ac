#pragma once

#include <stdio.h>

#include <mutex>
#include <vector>
#include <optional>
#include <atomic>

#define LOG_INFO(fmt, ...)  printf("[+] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) printf("[-] " fmt "\n", ##__VA_ARGS__)