#ifndef MODULES_H
#define MODULES_H

#include <ntifs.h>
#include <intrin.h>

#define REPORT_MODULE_VALIDATION_FAILURE 60
#define MODULE_VALIDATION_FAILURE_MAX_REPORT_COUNT 20

#define MODULE_REPORT_DRIVER_NAME_BUFFER_SIZE 128

#define REASON_NO_BACKING_MODULE 1
#define REASON_INVALID_IOCTL_DISPATCH 2

typedef struct _MODULE_VALIDATION_FAILURE_HEADER
{
	INT module_count;

}MODULE_VALIDATION_FAILURE_HEADER, *PMODULE_VALIDATION_FAILURE_HEADER;

typedef struct _MODULE_VALIDATION_FAILURE
{
	INT report_code;
	INT report_type;
	UINT64 driver_base_address;
	UINT64 driver_size;
	CHAR driver_name[ 128 ];

}MODULE_VALIDATION_FAILURE, *PMODULE_VALIDATION_FAILURE;

typedef struct _INVALID_DRIVER
{
	struct _INVALID_DRIVER* next;
	INT reason;
	PDRIVER_OBJECT driver;

}INVALID_DRIVER, * PINVALID_DRIVER;

typedef struct _INVALID_DRIVERS_HEAD
{
	PINVALID_DRIVER first_entry;
	INT count;		//keeps track of the number of drivers in the list

}INVALID_DRIVERS_HEAD, * PINVALID_DRIVERS_HEAD;

/* system modules information */

typedef struct _SYSTEM_MODULES
{
	PVOID address;
	INT module_count;

}SYSTEM_MODULES, * PSYSTEM_MODULES;

NTSTATUS GetSystemModuleInformation(
	_Out_ PSYSTEM_MODULES ModuleInformation
);

NTSTATUS HandleValidateDriversIOCTL(
	_In_ PIRP Irp
);

#endif
