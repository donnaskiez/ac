#ifndef NMI_H
#define NMI_H

#include <ntifs.h>
#include <intrin.h>

#define REPORT_NMI_CALLBACK_FAILURE 50

NTSTATUS HandleNmiIOCTL(
	_In_ PIRP Irp
);

typedef struct NMI_CALLBACK_FAILURE
{
	INT report_code;
	INT were_nmis_disabled;
	UINT64 kthread_address;
	UINT64 invalid_rip;

}NMI_CALLBACK_FAILURE, *PNMI_CALLBACK_FAILURE;

typedef struct _NMI_CONTEXT
{
	INT nmi_callbacks_run;

}NMI_CONTEXT, * PNMI_CONTEXT;

typedef struct _NMI_CALLBACK_DATA
{
	UINT64		kthread_address;
	UINT64		kprocess_address;
	UINT64		start_address;
	UINT64		stack_limit;
	UINT64		stack_base;
	uintptr_t	stack_frames_offset;
	INT			num_frames_captured;
	UINT64		cr3;

}NMI_CALLBACK_DATA, * PNMI_CALLBACK_DATA;

#endif