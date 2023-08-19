#include "nmi.h"

#include "modules.h"
#include "common.h"

typedef struct _NMI_POOLS
{
	PVOID thread_data_pool;
	PVOID stack_frames;
	PVOID nmi_context;

}NMI_POOLS, * PNMI_POOLS;

PVOID nmi_callback_handle = NULL;

/* Global structure to hold pointers to required memory for the NMI's */
NMI_POOLS nmi_pools = { 0 };

NTSTATUS IsInstructionPointerInInvalidRegion(
	_In_ UINT64 RIP,
	_In_ PSYSTEM_MODULES SystemModules,
	_Out_ PBOOLEAN Result
)
{
	if ( !RIP || !SystemModules || !Result )
		return STATUS_INVALID_PARAMETER;

	/* Note that this does not check for HAL or PatchGuard Execution */
	for ( INT i = 0; i < SystemModules->module_count; i++ )
	{
		PRTL_MODULE_EXTENDED_INFO system_module = ( PRTL_MODULE_EXTENDED_INFO )(
			( uintptr_t )SystemModules->address + i * sizeof( RTL_MODULE_EXTENDED_INFO ) );

		UINT64 base = ( UINT64 )system_module->ImageBase;
		UINT64 end = base + system_module->ImageSize;

		if ( RIP >= base && RIP <= end )
		{
			*Result = TRUE;
			return STATUS_SUCCESS;;
		}
	}

	*Result = FALSE;
	return STATUS_SUCCESS;
}

NTSTATUS AnalyseNmiData(
	_In_ INT NumCores,
	_In_ PSYSTEM_MODULES SystemModules,
	_In_ PIRP Irp
)
{
	if ( !NumCores || !SystemModules )
		return STATUS_INVALID_PARAMETER;

	for ( INT core = 0; core < NumCores; core++ )
	{
		PNMI_CONTEXT context = ( PNMI_CONTEXT )( ( uintptr_t )nmi_pools.nmi_context + core * sizeof( NMI_CONTEXT ) );

		/* Make sure our NMIs were run  */
		if ( !context->nmi_callbacks_run )
		{
			NMI_CALLBACK_FAILURE report;
			report.report_code = REPORT_NMI_CALLBACK_FAILURE;
			report.kthread_address = NULL;
			report.invalid_rip = NULL;
			report.were_nmis_disabled = TRUE;

			Irp->IoStatus.Information = sizeof( NMI_CALLBACK_FAILURE );

			RtlCopyMemory(
				Irp->AssociatedIrp.SystemBuffer,
				&report,
				sizeof( NMI_CALLBACK_FAILURE )
			);

			return STATUS_SUCCESS;
		}

		PNMI_CALLBACK_DATA thread_data = ( PNMI_CALLBACK_DATA )(
			( uintptr_t )nmi_pools.thread_data_pool + core * sizeof( NMI_CALLBACK_DATA ) );

		DEBUG_LOG( "cpu number: %i callback count: %i", core, context->nmi_callbacks_run );

		/* Walk the stack */
		for ( INT frame = 0; frame < thread_data->num_frames_captured; frame++ )
		{
			BOOLEAN flag;
			DWORD64 stack_frame = *( DWORD64* )(
				( ( uintptr_t )nmi_pools.stack_frames + thread_data->stack_frames_offset + frame * sizeof( PVOID ) ) );

			if ( !NT_SUCCESS( IsInstructionPointerInInvalidRegion( stack_frame, SystemModules, &flag ) ) )
			{
				DEBUG_ERROR( "errro checking RIP for current stack address" );
				continue;
			}

			if ( flag == FALSE )
			{
				/*
				* Note: for now, we only handle 1 report at a time so we stop the 
				* analysis once we receive a report since we only send a buffer
				* large enough for 1 report. In the future this should be changed
				* to a buffer that can hold atleast 4 reports (since the chance we
				* get 4 reports with a single NMI would be impossible) so we can 
				* continue parsing the rest of the stack frames after receiving a
				* single report.
				*/

				NMI_CALLBACK_FAILURE report;
				report.report_code = REPORT_NMI_CALLBACK_FAILURE;
				report.kthread_address = thread_data->kthread_address;
				report.invalid_rip = stack_frame;
				report.were_nmis_disabled = FALSE;

				Irp->IoStatus.Information = sizeof( NMI_CALLBACK_FAILURE );

				RtlCopyMemory(
					Irp->AssociatedIrp.SystemBuffer,
					&report,
					sizeof( NMI_CALLBACK_FAILURE )
				);

				return STATUS_SUCCESS;
			}
		}
	}

	return STATUS_SUCCESS;
}

BOOLEAN NmiCallback(
	_In_ PVOID Context,
	_In_ BOOLEAN Handled
)
{
	UNREFERENCED_PARAMETER( Handled );

	ULONG proc_num = KeGetCurrentProcessorNumber();
	PVOID current_thread = KeGetCurrentThread();
	NMI_CALLBACK_DATA thread_data = { 0 };

	/*
	* Cannot allocate pool in this function as it runs at IRQL >= dispatch level
	* so ive just allocated a global pool with size equal to 0x200 * num_procs
	*/
	INT num_frames_captured = RtlCaptureStackBackTrace(
		NULL,
		STACK_FRAME_POOL_SIZE,
		( uintptr_t )nmi_pools.stack_frames + proc_num * STACK_FRAME_POOL_SIZE,
		NULL
	);

	/*
	* This function is run in the context of the interrupted thread hence we can
	* gather any and all information regarding the thread that may be useful for analysis
	*/
	thread_data.kthread_address = ( UINT64 )current_thread;
	thread_data.kprocess_address = ( UINT64 )PsGetCurrentProcess();
	thread_data.stack_base = *( ( UINT64* )( ( uintptr_t )current_thread + KTHREAD_STACK_BASE_OFFSET ) );
	thread_data.stack_limit = *( ( UINT64* )( ( uintptr_t )current_thread + KTHREAD_STACK_LIMIT_OFFSET ) );
	thread_data.start_address = *( ( UINT64* )( ( uintptr_t )current_thread + KTHREAD_START_ADDRESS_OFFSET ) );
	thread_data.cr3 = __readcr3();
	thread_data.stack_frames_offset = proc_num * STACK_FRAME_POOL_SIZE;
	thread_data.num_frames_captured = num_frames_captured;

	RtlCopyMemory(
		( ( uintptr_t )nmi_pools.thread_data_pool ) + proc_num * sizeof( thread_data ),
		&thread_data,
		sizeof( thread_data )
	);

	PNMI_CONTEXT context = ( PNMI_CONTEXT )( ( uintptr_t )Context + proc_num * sizeof( NMI_CONTEXT ) );
	context->nmi_callbacks_run += 1;
	DEBUG_LOG( "num nmis called: %i from addr: %llx", context->nmi_callbacks_run, ( uintptr_t )context );

	return TRUE;
}

NTSTATUS LaunchNonMaskableInterrupt(
	_In_ ULONG NumCores
)
{
	if ( !NumCores )
		return STATUS_INVALID_PARAMETER;

	PKAFFINITY_EX ProcAffinityPool = ExAllocatePool2( POOL_FLAG_NON_PAGED, sizeof( KAFFINITY_EX ), PROC_AFFINITY_POOL );

	if ( !ProcAffinityPool )
		return STATUS_ABANDONED;

	nmi_pools.stack_frames = ExAllocatePool2( POOL_FLAG_NON_PAGED, NumCores * STACK_FRAME_POOL_SIZE, STACK_FRAMES_POOL );

	if ( !nmi_pools.stack_frames )
	{
		ExFreePoolWithTag( ProcAffinityPool, PROC_AFFINITY_POOL );
		return STATUS_ABANDONED;
	}

	nmi_pools.thread_data_pool = ExAllocatePool2( POOL_FLAG_NON_PAGED, NumCores * sizeof( NMI_CALLBACK_DATA ), THREAD_DATA_POOL );

	if ( !nmi_pools.thread_data_pool )
	{
		ExFreePoolWithTag( nmi_pools.stack_frames, STACK_FRAMES_POOL );
		ExFreePoolWithTag( ProcAffinityPool, PROC_AFFINITY_POOL );
		return STATUS_ABANDONED;
	}

	LARGE_INTEGER delay = { 0 };
	delay.QuadPart -= 100 * 10000;

	for ( ULONG core = 0; core < NumCores; core++ )
	{
		KeInitializeAffinityEx( ProcAffinityPool );
		KeAddProcessorAffinityEx( ProcAffinityPool, core );

		DEBUG_LOG( "Sending NMI" );
		HalSendNMI( ProcAffinityPool );

		/*
		* Only a single NMI can be active at any given time, so arbitrarily
		* delay execution  to allow time for the NMI to be processed
		*/
		KeDelayExecutionThread( KernelMode, FALSE, &delay );
	}

	ExFreePoolWithTag( ProcAffinityPool, PROC_AFFINITY_POOL );

	return STATUS_SUCCESS;
}

NTSTATUS HandleNmiIOCTL(
	_In_ PIRP Irp
)
{
	NTSTATUS status = STATUS_SUCCESS;
	SYSTEM_MODULES system_modules = { 0 };
	ULONG num_cores = KeQueryActiveProcessorCountEx( 0 );

	/* Fix annoying visual studio linting error */
	RtlZeroMemory( &system_modules, sizeof( SYSTEM_MODULES ) );
	RtlZeroMemory( &nmi_pools, sizeof( NMI_POOLS ) );

	nmi_pools.nmi_context = ExAllocatePool2( POOL_FLAG_NON_PAGED, num_cores * sizeof( NMI_CONTEXT ), NMI_CONTEXT_POOL );

	if ( !nmi_pools.nmi_context )
	{
		DEBUG_ERROR( "nmi_context ExAllocatePool2 failed" );
		return STATUS_ABANDONED;
	}

	/*
	* We want to register and unregister our callback each time so it becomes harder
	* for people to hook our callback and get up to some funny business
	*/
	nmi_callback_handle = KeRegisterNmiCallback( NmiCallback, nmi_pools.nmi_context );

	if ( !nmi_callback_handle )
	{
		DEBUG_ERROR( "KeRegisterNmiCallback failed" );
		ExFreePoolWithTag( nmi_pools.nmi_context, NMI_CONTEXT_POOL );
		return STATUS_ABANDONED;
	}

	/*
	* We query the system modules each time since they can potentially
	* change at any time
	*/
	status = GetSystemModuleInformation( &system_modules );

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "Error retriving system module information" );
		return status;
	}
	status = LaunchNonMaskableInterrupt( num_cores );

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "Error running NMI callbacks" );
		ExFreePoolWithTag( system_modules.address, SYSTEM_MODULES_POOL );
		return status;
	}
	status = AnalyseNmiData( num_cores, &system_modules, Irp );

	if ( !NT_SUCCESS( status ) )
		DEBUG_ERROR( "Error analysing nmi data" );

	ExFreePoolWithTag( system_modules.address, SYSTEM_MODULES_POOL );
	ExFreePoolWithTag( nmi_pools.stack_frames, STACK_FRAMES_POOL );
	ExFreePoolWithTag( nmi_pools.thread_data_pool, THREAD_DATA_POOL );
	ExFreePoolWithTag( nmi_pools.nmi_context, NMI_CONTEXT_POOL );
	KeDeregisterNmiCallback( nmi_callback_handle );

	return status;
}