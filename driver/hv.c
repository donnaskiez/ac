#include "hv.h"

#include <intrin.h>

#include "common.h"

#define TOTAL_ITERATION_COUNT 20

#define IA32_APERF_MSR 0x000000E8

/*
* 1. Bind thread to a single core
* 2. Raise the IRQL to HIGH_LEVEL
* 3. disable interrupts 
*/
VOID APERFMsrTimingCheck()
{
	ULONG64 old_irql;
	INT cpuid_result[ 4 ];

	old_irql = __readcr8();

	__writecr8( HIGH_LEVEL );

	_disable();

	UINT64 aperf_before = __readmsr( IA32_APERF_MSR ) << 32;

	__cpuid( cpuid_result, 1 );

	UINT64 aperf_after = __readmsr( IA32_APERF_MSR ) << 32;

	_enable();

	__writecr8( old_irql );

	UINT64 aperf_delta = aperf_after - aperf_before;

	_enable();

	DEBUG_LOG( "delta: %llx", aperf_delta );

}