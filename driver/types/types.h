#ifndef TYPES_H
#define TYPES_H

#include "../common.h"

#define REPORT_NMI_CALLBACK_FAILURE 50
#define REPORT_MODULE_VALIDATION_FAILURE 60
#define REPORT_ILLEGAL_HANDLE_OPERATION 70
#define REPORT_INVALID_PROCESS_ALLOCATION 80
#define REPORT_HIDDEN_SYSTEM_THREAD 90
#define REPORT_ILLEGAL_ATTACH_PROCESS 100
#define REPORT_APC_STACKWALK 110
#define REPORT_DPC_STACKWALK 120
#define REPORT_DATA_TABLE_ROUTINE 130
#define REPORT_INVALID_PROCESS_MODULE 140

typedef enum _TABLE_ID
{
        HalDispatch = 0,
        HalPrivateDispatch
} TABLE_ID;

typedef struct _HYPERVISOR_DETECTION_REPORT
{
        INT aperf_msr_timing_check;
        INT invd_emulation_check;

} HYPERVISOR_DETECTION_REPORT, *PHYPERVISOR_DETECTION_REPORT;

#define APC_STACKWALK_BUFFER_SIZE 500

typedef struct _APC_STACKWALK_REPORT
{
        INT    report_code;
        UINT64 kthread_address;
        UINT64 invalid_rip;
        CHAR   driver[APC_STACKWALK_BUFFER_SIZE];

} APC_STACKWALK_REPORT, *PAPC_STACKWALK_REPORT;

typedef struct _DPC_STACKWALK_REPORT
{
        UINT32 report_code;
        UINT64 kthread_address;
        UINT64 invalid_rip;
        CHAR   driver[APC_STACKWALK_BUFFER_SIZE];

} DPC_STACKWALK_REPORT, *PDPC_STACKWALK_REPORT;

typedef struct _MODULE_VALIDATION_FAILURE
{
        INT    report_code;
        INT    report_type;
        UINT64 driver_base_address;
        UINT64 driver_size;
        CHAR   driver_name[128];

} MODULE_VALIDATION_FAILURE, *PMODULE_VALIDATION_FAILURE;

#define DATA_TABLE_ROUTINE_BUF_SIZE 256

typedef struct _DATA_TABLE_ROUTINE_REPORT
{
        UINT32   report_code;
        TABLE_ID id;
        UINT64   address;
        CHAR     routine[DATA_TABLE_ROUTINE_BUF_SIZE];

} DATA_TABLE_ROUTINE_REPORT, *PDATA_TABLE_ROUTINE_REPORT;

typedef struct _NMI_CALLBACK_FAILURE
{
        INT    report_code;
        INT    were_nmis_disabled;
        UINT64 kthread_address;
        UINT64 invalid_rip;

} NMI_CALLBACK_FAILURE, *PNMI_CALLBACK_FAILURE;

#define REPORT_INVALID_PROCESS_BUFFER_SIZE 500

typedef struct _INVALID_PROCESS_ALLOCATION_REPORT
{
        INT  report_code;
        CHAR process[REPORT_INVALID_PROCESS_BUFFER_SIZE];

} INVALID_PROCESS_ALLOCATION_REPORT, *PINVALID_PROCESS_ALLOCATION_REPORT;

typedef struct _HIDDEN_SYSTEM_THREAD_REPORT
{
        INT    report_code;
        INT    found_in_kthreadlist;
        INT    found_in_pspcidtable;
        UINT64 thread_address;
        LONG   thread_id;
        CHAR   thread[500];

} HIDDEN_SYSTEM_THREAD_REPORT, *PHIDDEN_SYSTEM_THREAD_REPORT;

typedef struct _ATTACH_PROCESS_REPORT
{
        INT    report_code;
        UINT32 thread_id;
        UINT64 thread_address;

} ATTACH_PROCESS_REPORT, *PATTACH_PROCESS_REPORT;

typedef struct _KPRCB_THREAD_VALIDATION_CTX
{
        UINT64  thread;
        BOOLEAN thread_found_in_pspcidtable;
        // BOOLEAN thread_found_in_kthreadlist;
        BOOLEAN finished;

} KPRCB_THREAD_VALIDATION_CTX, *PKPRCB_THREAD_VALIDATION_CTX;

#define HANDLE_REPORT_PROCESS_NAME_MAX_LENGTH 64

typedef struct _OPEN_HANDLE_FAILURE_REPORT
{
        INT  report_code;
        INT  is_kernel_handle;
        LONG process_id;
        LONG thread_id;
        LONG access;
        CHAR process_name[HANDLE_REPORT_PROCESS_NAME_MAX_LENGTH];

} OPEN_HANDLE_FAILURE_REPORT, *POPEN_HANDLE_FAILURE_REPORT;

#define MODULE_PATH_LEN 256

typedef struct _PROCESS_MODULE_VALIDATION_REPORT
{
        INT    report_code;
        UINT64 image_base;
        UINT32 image_size;
        WCHAR  module_path[MODULE_PATH_LEN];

} PROCESS_MODULE_VALIDATION_REPORT, *PPROCESS_MODULE_VALIDATION_REPORT;

#endif