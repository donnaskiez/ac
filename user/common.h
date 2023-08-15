#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>

#define LOG_INFO(fmt, ...) printf("[+] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) printf("[-] " fmt "\n", ##__VA_ARGS__)

#endif