#include "ioctl.h"

#include "common.h"

#include "modules.h"
#include "driver.h"
#include "callbacks.h"
#include "pool.h"
#include "integrity.h"
#include "thread.h"
#include "queue.h"

#include "hv.h"

NTSTATUS DeviceControl(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PIRP Irp
)
{
	UNREFERENCED_PARAMETER( DriverObject );

	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION stack_location = IoGetCurrentIrpStackLocation( Irp );
	HANDLE handle;
	PKTHREAD thread;
	BOOLEAN security_flag = FALSE;

	/*
	* The purpose of this is to prevent programs from opening a handle to our driver
	* and trying to fuzz the IOCTL access or codes. This definitely isnt a perfect 
	* solution though... xD
	*/
	ReadProcessInitialisedConfigFlag( &security_flag );

	if ( security_flag == FALSE && 
		stack_location->Parameters.DeviceIoControl.IoControlCode != IOCTL_NOTIFY_DRIVER_ON_PROCESS_LAUNCH )
		goto end;

	switch ( stack_location->Parameters.DeviceIoControl.IoControlCode )
	{
	case IOCCTL_RUN_NMI_CALLBACKS:

		status = HandleNmiIOCTL( Irp );

		if ( !NT_SUCCESS( status ) )
			DEBUG_ERROR( "RunNmiCallbacks failed with status %lx", status );

		break;

	case IOCTL_VALIDATE_DRIVER_OBJECTS:

		/*
		* The reason this function is run in a new thread and not the thread
		* issuing the IOCTL is because ZwOpenDirectoryObject issues a
		* user mode handle if called on the user mode thread calling DeviceIoControl.
		* This is a problem because when we pass said handle to ObReferenceObjectByHandle
		* it will issue a bug check under windows driver verifier.
		*/

		status = PsCreateSystemThread(
			&handle,
			PROCESS_ALL_ACCESS,
			NULL,
			NULL,
			NULL,
			HandleValidateDriversIOCTL,
			Irp
		);

		if ( !NT_SUCCESS( status ) )
		{
			DEBUG_ERROR( "Failed to start thread to validate system drivers" );
			goto end;
		}

		/*
		* Thread objects are a type of dispatcher object, meaning when they are freed
		* its set to the signal state and any waiters will be signalled. This allows
		* us to wait til our threads terminated and the IRP buffer has been either filled
		* or left empty and then from there we can complete the IRP and return.
		*/
		status = ObReferenceObjectByHandle(
			handle,
			THREAD_ALL_ACCESS,
			*PsThreadType,
			KernelMode,
			&thread,
			NULL
		);

		if ( !NT_SUCCESS( status ) )
		{
			DEBUG_ERROR( "ObReferenceObjectbyhandle failed with status %lx", status );
			ZwClose( handle );
			goto end;
		}

		/* KeWaitForSingleObject with infinite time must be called from IRQL <= APC_LEVEL */
		PAGED_CODE();

		KeWaitForSingleObject( thread, Executive, KernelMode, FALSE, NULL );

		ZwClose( handle );
		ObDereferenceObject( thread );

		break;

	case IOCTL_NOTIFY_DRIVER_ON_PROCESS_LAUNCH:;

		status = InitialiseProcessConfigOnProcessLaunch(Irp);

		if ( !NT_SUCCESS( status ) )
		{
			DEBUG_ERROR( "Failed to initialise driver config on proc launch with status %x", status );
			goto end;
		}

		status = InitiateDriverCallbacks();

		if ( !NT_SUCCESS( status ) )
			DEBUG_ERROR( "InitiateDriverCallbacks failed with status %x", status );
		
		break;

	case IOCTL_HANDLE_REPORTS_IN_CALLBACK_QUEUE:

		status = HandlePeriodicGlobalReportQueueQuery(Irp);

		if ( !NT_SUCCESS( status ) )
			DEBUG_ERROR( "Failed to handle period callback report queue" );

		break;

	case IOCTL_PERFORM_VIRTUALIZATION_CHECK:

		status = PerformVirtualizationDetection( Irp );

		if ( !NT_SUCCESS( status ) )
			DEBUG_ERROR( "PerformVirtualizationDetection failed with status %x", status );

		break;

	case IOCTL_ENUMERATE_HANDLE_TABLES:
		
		/* can maybe implement this better so we can extract a status value */
		EnumerateProcessListWithCallbackFunction(
			EnumerateProcessHandles
		);

		break;

	case IOCTL_RETRIEVE_MODULE_EXECUTABLE_REGIONS:

		status = PsCreateSystemThread(
			&handle,
			PROCESS_ALL_ACCESS,
			NULL,
			NULL,
			NULL,
			RetrieveInMemoryModuleExecutableSections,
			Irp
		);

		if ( !NT_SUCCESS( status ) )
		{
			DEBUG_ERROR( "Failed to start system thread to get executable regions" );
			goto end;
		}

		status = ObReferenceObjectByHandle(
			handle,
			THREAD_ALL_ACCESS,
			*PsThreadType,
			KernelMode,
			&thread,
			NULL
		);

		if ( !NT_SUCCESS( status ) )
		{
			DEBUG_ERROR( "ObReferenceObjectbyhandle failed with status %lx", status );
			ZwClose( handle );
			goto end;
		}

		PAGED_CODE();

		KeWaitForSingleObject( thread, Executive, KernelMode, FALSE, NULL );;

		ZwClose( handle );
		ObDereferenceObject( thread );

		if ( !NT_SUCCESS( status ) )
			DEBUG_ERROR( "Failed to retrieve executable regions" );

		break;

	case IOCTL_REQUEST_TOTAL_MODULE_SIZE:

		status = GetDriverImageSize( Irp );

		if ( !NT_SUCCESS( status ) )
			DEBUG_ERROR( "Failed to retrieve driver image size" );

		break;

	case IOCTL_NOTIFY_DRIVER_ON_PROCESS_TERMINATION:

		ClearProcessConfigOnProcessTermination();
		UnregisterCallbacksOnProcessTermination();

		break;

	case IOCTL_SCAN_FOR_UNLINKED_PROCESS:

		status = FindUnlinkedProcesses( Irp );

		if ( !NT_SUCCESS( status ) )
			DEBUG_ERROR( "FindUNlinekdProcesses failed with status %x", status );

		break;

	case IOCTL_VALIDATE_KPRCB_CURRENT_THREAD:

		ValidateKPCRBThreads( Irp );

		break;

	case IOCTL_PERFORM_INTEGRITY_CHECK:

		status = VerifyInMemoryImageVsDiskImage();

		if ( !NT_SUCCESS( status ) )
			DEBUG_ERROR( "VerifyInMemoryImageVsDisk failed with status %x", status );

		break;

	default:
		DEBUG_ERROR( "Invalid IOCTL passed to driver" );
		break;
	}

end:
	Irp->IoStatus.Status = status;
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return status;
}

NTSTATUS DeviceClose(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
)
{
	DEBUG_LOG( "Handle closed to DonnaAC" );

	FreeGlobalReportQueueObjects();
	ClearProcessConfigOnProcessTermination();
	UnregisterCallbacksOnProcessTermination();

	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return Irp->IoStatus.Status;
}

NTSTATUS DeviceCreate(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
)
{
	DEBUG_LOG( "Handle opened to DonnaAC" );
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return Irp->IoStatus.Status;
}