#pragma once

#include <stdio.h>

#include <atomic>
#include <mutex>
#include <optional>
#include <vector>

#define LOG_INFO(fmt, ...) printf("[+] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) printf("[-] " fmt "\n", ##__VA_ARGS__)

#define ABSOLUTE(wait) (wait)
#define RELATIVE(wait) (-(wait))

#define NANOSECONDS(nanos) (((signed __int64)(nanos)) / 100L)
#define MICROSECONDS(micros) (((signed __int64)(micros)) * NANOSECONDS(1000L))
#define MILLISECONDS(milli) (((signed __int64)(milli)) * MICROSECONDS(1000L))
#define SECONDS(seconds) (((signed __int64)(seconds)) * MILLISECONDS(1000L))