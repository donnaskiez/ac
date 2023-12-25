#ifndef HV_H
#define HV_H

#include <ntifs.h>
#include "common.h"

typedef struct _HYPERVISOR_DETECTION_REPORT
{
        INT aperf_msr_timing_check;
        INT invd_emulation_check;

} HYPERVISOR_DETECTION_REPORT, *PHYPERVISOR_DETECTION_REPORT;

NTSTATUS
PerformVirtualizationDetection(_Inout_ PIRP Irp);

_IRQL_always_function_max_(HIGH_LEVEL) INT APERFMsrTimingCheck();

extern INT
TestINVDEmulation();

#endif