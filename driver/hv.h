#ifndef HV_H
#define HV_H

#include <ntifs.h>
#include "common.h"

NTSTATUS
PerformVirtualizationDetection(_Inout_ PIRP Irp);

BOOLEAN
APERFMsrTimingCheck();

extern INT
TestINVDEmulation();

#endif