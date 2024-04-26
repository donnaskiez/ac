#ifndef PE_H
#define PE_H

#include "common.h"

#define IMAGE_DOS_SIGNATURE 0x5a4d     /* MZ   */
#define IMAGE_NT_SIGNATURE  0x00004550 /* PE00 */

PVOID
PeFindExportByName(_In_ PVOID Image, _In_ PCHAR Name);

#endif