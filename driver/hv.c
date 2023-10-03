#include "hv.h"

#include <intrin.h>

#include "common.h"

#define TOTAL_ITERATION_COUNT 20

/*
* TODO: Perform the test in a loop and average the delta out, then compare it 
* to an instruction such as FYL2XP1 (source: secret.club) which has an average
* execution time slightly higher then the CPUID instruction then compare the two.
* If the average time for the CPUID instruction is higher then the average time 
* for the FYL2XP1 instruction it is a dead giveaway we are running on a 
* virtualized system.
* 
* reference: https://secret.club/2020/01/12/battleye-hypervisor-detection.html
*/

STATIC
INT 
APERFMsrTimingCheck()
{
	KAFFINITY new_affinity = { 0 };
	KAFFINITY old_affinity = { 0 };
	ULONG64 old_irql;
	INT cpuid_result[ 4 ];

	/*
	* First thing we do is we lock the current thread to the logical processor
	* its executing on. 
	*/
	new_affinity = ( KAFFINITY )( 1 << KeGetCurrentProcessorNumber() );
	old_affinity = KeSetSystemAffinityThreadEx( new_affinity );

	/*
	* Once we've locked our thread to the current core, we save the old irql
	* and raise to HIGH_LEVEL to ensure the chance our thread is preempted 
	* by a thread with a higher IRQL is extremely low.
	*/
	old_irql = __readcr8();
	__writecr8( HIGH_LEVEL );

	/*
	* Then we also disable interrupts, once again making sure our thread
	* is not preempted.
	*/
	_disable();

	/*
	* Once our thread is ready for the test, we read the APERF from the 
	* MSR register and store it. We then execute a CPUID instruction
	* which we don't really care about and immediately after read the APERF
	* counter once again and store it in a seperate variable.
	*/
	UINT64 aperf_before = __readmsr( IA32_APERF_MSR ) << 32;
	__cpuid( cpuid_result, 1 );
	UINT64 aperf_after = __readmsr( IA32_APERF_MSR ) << 32;

	/*
	* Once we have performed our test, we want to make sure we are not 
	* hogging the cpu time from other threads, so we reverse the initial
	* preparation process. i.e we first enable interrupts, lower our irql
	* to the threads previous irql before it was raised and then restore the
	* threads affinity back to its original affinity.
	*/
	_enable();
	__writecr8( old_irql );
	KeRevertToUserAffinityThreadEx( old_affinity );

	/*
	* Now the only thing left to do is calculate the change. Now, on some VMs 
	* such as VMWARE the aperf value will be 0, meaning the change will be 0.
	* This is a dead giveaway we are executing in a VM. 
	*/
	UINT64 aperf_delta = aperf_after - aperf_before;

	return aperf_delta == 0 ? TRUE : FALSE;
}

NTSTATUS 
PerformVirtualizationDetection(
	_In_ PIRP Irp
)
{
	HYPERVISOR_DETECTION_REPORT report;
	report.aperf_msr_timing_check = APERFMsrTimingCheck();
	report.invd_emulation_check = TestINVDEmulation();

	Irp->IoStatus.Information = sizeof( HYPERVISOR_DETECTION_REPORT );

	RtlCopyMemory(
		Irp->AssociatedIrp.SystemBuffer,
		&report,
		sizeof( HYPERVISOR_DETECTION_REPORT )
	);

	return STATUS_SUCCESS;
}