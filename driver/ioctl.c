#include "ioctl.h"

#include "modules.h"
#include "driver.h"
#include "callbacks.h"
#include "pool.h"
#include "integrity.h"
#include "thread.h"
#include "queue.h"
#include "hv.h"

STATIC 
NTSTATUS 
DispatchApcOperation(
	_In_ PAPC_OPERATION_ID Operation);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, DispatchApcOperation)
#pragma alloc_text(PAGE, DeviceControl)
#pragma alloc_text(PAGE, DeviceClose)
#pragma alloc_text(PAGE, DeviceCreate)
#endif

#define IOCCTL_RUN_NMI_CALLBACKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VALIDATE_DRIVER_OBJECTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20002, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NOTIFY_DRIVER_ON_PROCESS_LAUNCH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20004, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HANDLE_REPORTS_IN_CALLBACK_QUEUE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20005, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PERFORM_VIRTUALIZATION_CHECK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20006, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUMERATE_HANDLE_TABLES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20007, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RETRIEVE_MODULE_EXECUTABLE_REGIONS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20008, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REQUEST_TOTAL_MODULE_SIZE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20009, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NOTIFY_DRIVER_ON_PROCESS_TERMINATION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20010, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SCAN_FOR_UNLINKED_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20011, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VALIDATE_KPRCB_CURRENT_THREAD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20012, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PERFORM_INTEGRITY_CHECK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20013, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DETECT_ATTACHED_THREADS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20014, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VALIDATE_PROCESS_LOADED_MODULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20015, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REQUEST_HARDWARE_INFORMATION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20016, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INITIATE_APC_OPERATION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20017, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CHECK_FOR_EPT_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x20018, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define APC_OPERATION_STACKWALK 0x1

STATIC
NTSTATUS
DispatchApcOperation(
	_In_ PAPC_OPERATION_ID Operation
)
{
	PAGED_CODE();

	NTSTATUS status;

	switch (Operation->operation_id)
	{
	case APC_OPERATION_STACKWALK:

		DEBUG_LOG("Initiating APC stackwalk operation with operation id %i", Operation->operation_id);

		status = ValidateThreadsViaKernelApc();

		if (!NT_SUCCESS(status))
			DEBUG_ERROR("ValidateThreadsViaKernelApc failed with status %x", status);

		return status;

	default:
		DEBUG_ERROR("Invalid operation ID passed");
		return STATUS_INVALID_PARAMETER;
	}

	return status;
}

//_Dispatch_type_(IRP_MJ_SYSTEM_CONTROL)
NTSTATUS
DeviceControl(
	_In_ PDRIVER_OBJECT DriverObject,
	_Inout_ PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DriverObject);
	PAGED_CODE();

	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION stack_location = IoGetCurrentIrpStackLocation(Irp);
	HANDLE handle;
	PKTHREAD thread = NULL;
	BOOLEAN security_flag = FALSE;

	DEBUG_LOG("IOCTL Code: %lx", stack_location->Parameters.DeviceIoControl.IoControlCode);
	goto end;
	/*
	* LMAO 
	*/
	//ReadProcessInitialisedConfigFlag(&security_flag);

	//if (security_flag == FALSE &&
	//	stack_location->Parameters.DeviceIoControl.IoControlCode != IOCTL_NOTIFY_DRIVER_ON_PROCESS_LAUNCH)
	//{
	//	status = STATUS_ACCESS_DENIED;
	//	goto end;
	//}

	switch (stack_location->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCCTL_RUN_NMI_CALLBACKS:

		status = HandleNmiIOCTL(Irp);

		if (!NT_SUCCESS(status))
			DEBUG_ERROR("RunNmiCallbacks failed with status %lx", status);

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

		if (!NT_SUCCESS(status))
		{
			DEBUG_ERROR("Failed to start thread to validate system drivers");
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

		if (!NT_SUCCESS(status))
		{
			DEBUG_ERROR("ObReferenceObjectbyhandle failed with status %lx", status);
			ZwClose(handle);
			goto end;
		}

		KeWaitForSingleObject(thread, Executive, KernelMode, FALSE, NULL);

		ZwClose(handle);
		ObDereferenceObject(thread);

		break;

	case IOCTL_NOTIFY_DRIVER_ON_PROCESS_LAUNCH:;

		status = ProcLoadInitialiseProcessConfig(Irp);

		if (!NT_SUCCESS(status))
		{
			DEBUG_ERROR("Failed to initialise driver config on proc launch with status %x", status);
			goto end;
		}

		status = ProcLoadEnableObCallbacks();

		if (!NT_SUCCESS(status))
			DEBUG_ERROR("InitiateDriverCallbacks failed with status %x", status);

		break;

	case IOCTL_HANDLE_REPORTS_IN_CALLBACK_QUEUE:

		status = QueryActiveApcContextsForCompletion();

		if (!NT_SUCCESS(status))
			DEBUG_ERROR("QueryActiveApcContextsForCompletion filed with status %x", status);

		status = HandlePeriodicGlobalReportQueueQuery(Irp);

		if (!NT_SUCCESS(status))
			DEBUG_ERROR("Failed to handle period callback report queue");

		break;

	case IOCTL_PERFORM_VIRTUALIZATION_CHECK:

		status = PerformVirtualizationDetection(Irp);

		if (!NT_SUCCESS(status))
			DEBUG_ERROR("PerformVirtualizationDetection failed with status %x", status);

		break;

	case IOCTL_ENUMERATE_HANDLE_TABLES:

		/* can maybe implement this better so we can extract a status value */
		EnumerateProcessListWithCallbackRoutine(
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

		if (!NT_SUCCESS(status))
		{
			DEBUG_ERROR("Failed to start system thread to get executable regions");
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

		if (!NT_SUCCESS(status))
		{
			DEBUG_ERROR("ObReferenceObjectbyhandle failed with status %lx", status);
			ZwClose(handle);
			goto end;
		}

		KeWaitForSingleObject(thread, Executive, KernelMode, FALSE, NULL);;

		ZwClose(handle);
		ObDereferenceObject(thread);

		if (!NT_SUCCESS(status))
			DEBUG_ERROR("Failed to retrieve executable regions");

		break;

	case IOCTL_REQUEST_TOTAL_MODULE_SIZE:

		status = GetDriverImageSize(Irp);

		if (!NT_SUCCESS(status))
			DEBUG_ERROR("Failed to retrieve driver image size");

		break;

	case IOCTL_NOTIFY_DRIVER_ON_PROCESS_TERMINATION:

		ProcCloseClearProcessConfiguration();
		ProcCloseDisableObCallbacks();

		break;

	case IOCTL_SCAN_FOR_UNLINKED_PROCESS:

		status = FindUnlinkedProcesses(Irp);

		if (!NT_SUCCESS(status))
			DEBUG_ERROR("FindUNlinekdProcesses failed with status %x", status);

		break;

	case IOCTL_VALIDATE_KPRCB_CURRENT_THREAD:

		ValidateKPCRBThreads(Irp);

		break;

	case IOCTL_PERFORM_INTEGRITY_CHECK:

		status = VerifyInMemoryImageVsDiskImage();

		if (!NT_SUCCESS(status))
			DEBUG_ERROR("VerifyInMemoryImageVsDisk failed with status %x", status);

		break;

	case IOCTL_DETECT_ATTACHED_THREADS:

		DetectThreadsAttachedToProtectedProcess();

		break;

	case IOCTL_VALIDATE_PROCESS_LOADED_MODULE:

		status = ValidateProcessLoadedModule(Irp);

		if (!NT_SUCCESS(status))
			DEBUG_ERROR("ValidateProcessLoadedModule failed with status %x", status);

		break;

	case IOCTL_REQUEST_HARDWARE_INFORMATION:;

		PSYSTEM_INFORMATION system_information = NULL;
		GetDriverConfigSystemInformation(&system_information);

		if (system_information == NULL)
		{
			DEBUG_ERROR("GetDriverConfigSystemInformation failed");
			goto end;
		}

		Irp->IoStatus.Information = sizeof(SYSTEM_INFORMATION);

		RtlCopyMemory(
			Irp->AssociatedIrp.SystemBuffer,
			system_information,
			sizeof(SYSTEM_INFORMATION)
		);

		break;

	case IOCTL_INITIATE_APC_OPERATION:;

		PAPC_OPERATION_ID operation = (PAPC_OPERATION_ID)Irp->AssociatedIrp.SystemBuffer;

		status = DispatchApcOperation(operation);

		if (!NT_SUCCESS(status))
			DEBUG_ERROR("DispatchApcOperation failed with status %x", status);

		break;

	case IOCTL_CHECK_FOR_EPT_HOOK:

		status = DetectEptHooksInKeyFunctions();

		if (!NT_SUCCESS(status))
			DEBUG_ERROR("DetectEpthooksInKeyFunctions failed with status %x", status);

		break;

	default:
		DEBUG_ERROR("Invalid IOCTL passed to driver: %lx", stack_location->Parameters.DeviceIoControl.IoControlCode);
		status = STATUS_INVALID_PARAMETER;
		break;
	}

end:
	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

_Dispatch_type_(IRP_MJ_CLOSE)
NTSTATUS
DeviceClose(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(DeviceObject);

	DEBUG_LOG("Handle closed to DonnaAC");

	/*
	* For now its fine, but this will need to be moved to our process load callbacks
	* since right now anyone can open a handle to our driver and then close it lol
	*/

	/* we also lose reports here, so sohuld pass em into the irp before freeing */
	FreeGlobalReportQueueObjects();
	ProcCloseClearProcessConfiguration();
	ProcCloseDisableObCallbacks();

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

_Dispatch_type_(IRP_MJ_CREATE)
NTSTATUS
DeviceCreate(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
)
{
	PAGED_CODE();

	DEBUG_LOG("Handle opened to DonnaAC");
	ValidateSystemModules();

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}