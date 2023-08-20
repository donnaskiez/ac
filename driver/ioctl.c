#include "ioctl.h"

#include "common.h"

#include "nmi.h"
#include "modules.h"
#include "driver.h"

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

		DEBUG_LOG( "irp addr: %p", ( void* )Irp );

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
		DEBUG_LOG( "waiting for thread to finish" );
		KeWaitForSingleObject( thread, Executive, KernelMode, FALSE, NULL );
		DEBUG_LOG( "THREAD FINISHED" );
		ZwClose( handle );
		ObDereferenceObject( thread );

		break;

	case IOCTL_NOTIFY_DRIVER_ON_PROCESS_LAUNCH:;

		PDRIVER_INITIATION_INFORMATION information = ( PDRIVER_INITIATION_INFORMATION )Irp->AssociatedIrp.SystemBuffer;
		UpdateProtectedProcessId( information->protected_process_id );
		break;


	default:
		DEBUG_ERROR( "Invalid IOCTL passed to driver" );
		break;
	}

end:
	DEBUG_LOG( "completing irp request" );
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
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return Irp->IoStatus.Status;
}

NTSTATUS DeviceCreate(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
)
{
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return Irp->IoStatus.Status;
}