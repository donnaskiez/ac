#include "ioctl.h"

#include "modules.h"
#include "driver.h"
#include "callbacks.h"
#include "pool.h"
#include "integrity.h"
#include "thread.h"
#include "queue.h"
#include "hv.h"

#define IOCCTL_RUN_NMI_CALLBACKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VALIDATE_DRIVER_OBJECTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2002, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NOTIFY_DRIVER_ON_PROCESS_LAUNCH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2004, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HANDLE_REPORTS_IN_CALLBACK_QUEUE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2005, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PERFORM_VIRTUALIZATION_CHECK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2006, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUMERATE_HANDLE_TABLES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2007, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RETRIEVE_MODULE_EXECUTABLE_REGIONS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2008, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REQUEST_TOTAL_MODULE_SIZE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2009, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NOTIFY_DRIVER_ON_PROCESS_TERMINATION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2010, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SCAN_FOR_UNLINKED_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2011, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VALIDATE_KPRCB_CURRENT_THREAD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2012, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PERFORM_INTEGRITY_CHECK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2013, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DETECT_ATTACHED_THREADS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2014, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VALIDATE_PROCESS_LOADED_MODULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2015, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REQUEST_HARDWARE_INFORMATION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2016, METHOD_BUFFERED, FILE_ANY_ACCESS)

NTSTATUS 
DeviceControl(
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

		status = QueryActiveApcContextsForCompletion();

			if ( !NT_SUCCESS( status ) )
				DEBUG_ERROR( "QueryActiveApcContextsForCompletion filed with status %x", status );

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
			EnumerateProcessHandles,
			NULL
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

	case IOCTL_DETECT_ATTACHED_THREADS:

		DetectThreadsAttachedToProtectedProcess();

		break;

	case IOCTL_VALIDATE_PROCESS_LOADED_MODULE:

		status = ValidateProcessLoadedModule( Irp );

		if ( !NT_SUCCESS( status ) )
			DEBUG_ERROR( "ValidateProcessLoadedModule failed with status %x", status );

		break;

	case IOCTL_REQUEST_HARDWARE_INFORMATION:;

		PSYSTEM_INFORMATION system_information = NULL;
		GetDriverConfigSystemInformation( &system_information );

		if ( system_information == NULL )
		{
			DEBUG_ERROR( "GetDriverConfigSystemInformation failed" );
			goto end;
		}

		Irp->IoStatus.Information = sizeof( SYSTEM_INFORMATION );

		RtlCopyMemory(
			Irp->AssociatedIrp.SystemBuffer,
			system_information,
			sizeof( SYSTEM_INFORMATION )
		);

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

NTSTATUS 
DeviceClose(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
)
{
	DEBUG_LOG( "Handle closed to DonnaAC" );

	/*
	* For now its fine, but this will need to be moved to our process load callbacks
	* since right now anyone can open a handle to our driver and then close it lol
	*/
	FreeGlobalReportQueueObjects();
	ClearProcessConfigOnProcessTermination();
	UnregisterCallbacksOnProcessTermination();

	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return Irp->IoStatus.Status;
}

NTSTATUS 
DeviceCreate(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
)
{
	DEBUG_LOG( "Handle opened to DonnaAC" );
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return Irp->IoStatus.Status;
}