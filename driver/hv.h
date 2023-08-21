#ifndef HV_H
#define HV_H

#include <ntifs.h>

typedef struct _HYPERVISOR_DETECTION_REPORT
{
	INT aperf_msr_timing_check;
	INT invd_emulation_check;

}HYPERVISOR_DETECTION_REPORT, *PHYPERVISOR_DETECTION_REPORT;

NTSTATUS PerformVirtualizationDetection(
	_In_ PIRP Irp
);

extern INT TestINVDEmulation();

#endif