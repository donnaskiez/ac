#ifndef DRIVER_H
#define DRIVER_H

#include <ntifs.h>
#include <wdftypes.h>
#include <wdf.h>

UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING( L"\\Device\\DonnaAC" );
UNICODE_STRING DEVICE_SYMBOLIC_LINK = RTL_CONSTANT_STRING( L"\\??\\DonnaAC" );

#endif