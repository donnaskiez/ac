#include <ntifs.h>

#define STATIC static
#define VOID   void

typedef UINT32 uint32_t;
typedef UINT64 uint64_t;
typedef UINT16 uint16_t;

#define DEBUG_LOG(fmt, ...)   ImpDbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[+] " fmt "\n", ##__VA_ARGS__)
#define DEBUG_ERROR(fmt, ...) ImpDbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[-] " fmt "\n", ##__VA_ARGS__)