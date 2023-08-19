#include "ioctl.h"

#include "common.h"

#include "nmi.h"
#include "modules.h"

NTSTATUS DeviceControl(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PIRP Irp
)
{
	UNREFERENCED_PARAMETER( DriverObject );

	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION stack_location = IoGetCurrentIrpStackLocation( Irp );
	HANDLE handle;

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
			DEBUG_ERROR( "Failed to start thread to validate system drivers" );

		/* 
		* wait on our thread so we dont complete the IRP before we've filled the 
		* buffer with information and prevent any weird IRP multithreaded interactions
		*/
		KeWaitForSingleObject( handle, Executive, KernelMode, FALSE, NULL );

		ZwClose( handle );
		break;

	default:
		DEBUG_ERROR( "Invalid IOCTL passed to driver" );
		break;
	}

	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	Irp->IoStatus.Status = status;
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