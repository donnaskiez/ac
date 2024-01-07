#ifndef DRIVER_H
#define DRIVER_H

#include <ntifs.h>

#define STATIC static
#define VOID void

#define DEBUG_LOG(fmt, ...) ImpDbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[+] " fmt "\n", ##__VA_ARGS__)
#define DEBUG_ERROR(fmt, ...) ImpDbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[-] " fmt "\n", ##__VA_ARGS__)

#endif