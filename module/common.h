#pragma once

#include <stdio.h>

#include <atomic>
#include <mutex>
#include <optional>
#include <vector>

#define LOG_INFO(fmt, ...) printf("[+] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) printf("[-] " fmt "\n", ##__VA_ARGS__)