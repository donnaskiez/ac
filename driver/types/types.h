#ifndef TYPES_H
#define TYPES_H

#include "../common.h"

#define REPORT_NMI_CALLBACK_FAILURE       50
#define REPORT_MODULE_VALIDATION_FAILURE  60
#define REPORT_ILLEGAL_HANDLE_OPERATION   70
#define REPORT_INVALID_PROCESS_ALLOCATION 80
#define REPORT_HIDDEN_SYSTEM_THREAD       90
#define REPORT_ILLEGAL_ATTACH_PROCESS     100
#define REPORT_APC_STACKWALK              110
#define REPORT_DPC_STACKWALK              120
#define REPORT_DATA_TABLE_ROUTINE         130
#define REPORT_INVALID_PROCESS_MODULE     140
#define REPORT_PATCHED_SYSTEM_MODULE      150
#define REPORT_SELF_DRIVER_PATCHED        160
#define REPORT_BLACKLISTED_PCIE_DEVICE    170
#define REPORT_EPT_HOOK                   180

#define REPORT_SUBTYPE_NO_BACKING_MODULE      0x0
#define REPORT_SUBTYPE_INVALID_DISPATCH       0x1
#define REPORT_SUBTYPE_EXCEPTION_THROWING_RET 0x2

#define PACKET_TYPE_REPORT    0x0
#define PACKET_TYPE_HEARTBEAT 0x1

#define PACKET_MAGIC_NUMBER 0x1337

#define INIT_REPORT_PACKET(report, code, subcode)                          \
    {                                                                      \
        (report)->header.packet_header.packet_type  = PACKET_TYPE_REPORT;  \
        (report)->header.packet_header.magic_number = PACKET_MAGIC_NUMBER; \
        (report)->header.report_code                = code;                \
        (report)->header.report_sub_type            = subcode;             \
    }

#define INIT_HEARTBEAT_PACKET(packet)                                        \
    {                                                                        \
        (packet)->header.packet_header.packet_type  = PACKET_TYPE_HEARTBEAT; \
        (packet)->header.packet_header.magic_number = PACKET_MAGIC_NUMBER;   \
    }

/* TODO: the naming here is fucking terrible need to clean everything up */
/* infact lots of the mess in the header files needs to be cleaned up */

/* use a UINT16 rather then enum to explicitly state the size */
typedef struct _PACKET_HEADER {
    UINT32 packet_type;
    UINT32 magic_number;

} PACKET_HEADER, *PPACKET_HEADER;

/* unencrypted header structures, should always == AES block size i.e 16 */
typedef struct _REPORT_PACKET_HEADER {
    PACKET_HEADER packet_header;
    UINT32        report_code;
    UINT32        report_sub_type;

} REPORT_PACKET_HEADER, *PREPORT_PACKET_HEADER;

typedef struct _HEARTBEAT_PACKET_HEADER {
    PACKET_HEADER packet_header;
    UINT32        unused[2];
} HEARTBEAT_PACKET_HEADER, *PHEARTBEAT_PACKET_HEADER;

#define AES_256_BLOCK_SIZE 16

static_assert(sizeof(HEARTBEAT_PACKET_HEADER) == AES_256_BLOCK_SIZE,
              "invalid heartbeat header size");
static_assert(sizeof(REPORT_PACKET_HEADER) == AES_256_BLOCK_SIZE,
              "invalid report header size");

typedef enum _TABLE_ID {
    HalDispatch = 0,
    HalPrivateDispatch,
    Win32kBase_gDxgInterface
} TABLE_ID;

typedef struct _HYPERVISOR_DETECTION_REPORT {
    REPORT_PACKET_HEADER header;
    UINT8                aperf_msr_timing_check;
    UINT8                invd_emulation_check;

} HYPERVISOR_DETECTION_REPORT, *PHYPERVISOR_DETECTION_REPORT;

#define APC_STACKWALK_BUFFER_SIZE 500

typedef struct _APC_STACKWALK_REPORT {
    REPORT_PACKET_HEADER header;
    UINT64               kthread_address;
    UINT64               invalid_rip;
    CHAR                 driver[APC_STACKWALK_BUFFER_SIZE];

} APC_STACKWALK_REPORT, *PAPC_STACKWALK_REPORT;

typedef struct _DPC_STACKWALK_REPORT {
    REPORT_PACKET_HEADER header;
    UINT64               kthread_address;
    UINT64               invalid_rip;
    CHAR                 driver[APC_STACKWALK_BUFFER_SIZE];

} DPC_STACKWALK_REPORT, *PDPC_STACKWALK_REPORT;

typedef struct _MODULE_VALIDATION_FAILURE {
    REPORT_PACKET_HEADER header;
    UINT64               driver_base_address;
    UINT64               driver_size;
    CHAR                 driver_name[128];

} MODULE_VALIDATION_FAILURE, *PMODULE_VALIDATION_FAILURE;

#define DATA_TABLE_ROUTINE_BUF_SIZE 256

typedef struct _DATA_TABLE_ROUTINE_REPORT {
    REPORT_PACKET_HEADER header;
    TABLE_ID             table_id;
    UINT64               address;
    UINT32               index;
    CHAR                 routine[DATA_TABLE_ROUTINE_BUF_SIZE];

} DATA_TABLE_ROUTINE_REPORT, *PDATA_TABLE_ROUTINE_REPORT;

typedef struct _NMI_CALLBACK_FAILURE {
    REPORT_PACKET_HEADER header;
    UINT8                were_nmis_disabled;
    UINT64               kthread_address;
    UINT64               invalid_rip;

} NMI_CALLBACK_FAILURE, *PNMI_CALLBACK_FAILURE;

#define REPORT_INVALID_PROCESS_BUFFER_SIZE 500

typedef struct _INVALID_PROCESS_ALLOCATION_REPORT {
    REPORT_PACKET_HEADER header;
    CHAR                 process[REPORT_INVALID_PROCESS_BUFFER_SIZE];

} INVALID_PROCESS_ALLOCATION_REPORT, *PINVALID_PROCESS_ALLOCATION_REPORT;

typedef struct _HIDDEN_SYSTEM_THREAD_REPORT {
    REPORT_PACKET_HEADER header;
    UINT8                found_in_kthreadlist;
    UINT8                found_in_pspcidtable;
    UINT64               thread_address;
    UINT32               thread_id;
    CHAR                 thread[500];

} HIDDEN_SYSTEM_THREAD_REPORT, *PHIDDEN_SYSTEM_THREAD_REPORT;

typedef struct _ATTACH_PROCESS_REPORT {
    REPORT_PACKET_HEADER header;
    UINT32               thread_id;
    UINT64               thread_address;

} ATTACH_PROCESS_REPORT, *PATTACH_PROCESS_REPORT;

typedef struct _KPRCB_THREAD_VALIDATION_CTX {
    REPORT_PACKET_HEADER header;
    UINT64               thread;
    BOOLEAN              thread_found_in_pspcidtable;
    // BOOLEAN thread_found_in_kthreadlist;
    BOOLEAN finished;

} KPRCB_THREAD_VALIDATION_CTX, *PKPRCB_THREAD_VALIDATION_CTX;

#define HANDLE_REPORT_PROCESS_NAME_MAX_LENGTH 64

typedef struct _OPEN_HANDLE_FAILURE_REPORT {
    REPORT_PACKET_HEADER header;
    UINT32               is_kernel_handle;
    UINT32               process_id;
    UINT32               thread_id;
    UINT32               access;
    CHAR                 process_name[HANDLE_REPORT_PROCESS_NAME_MAX_LENGTH];

} OPEN_HANDLE_FAILURE_REPORT, *POPEN_HANDLE_FAILURE_REPORT;

#define MODULE_PATH_LEN 256

typedef struct _PROCESS_MODULE_VALIDATION_REPORT {
    REPORT_PACKET_HEADER header;
    UINT64               image_base;
    UINT32               image_size;
    WCHAR                module_path[MODULE_PATH_LEN];

} PROCESS_MODULE_VALIDATION_REPORT, *PPROCESS_MODULE_VALIDATION_REPORT;

typedef struct _HEARTBEAT_PACKET {
    HEARTBEAT_PACKET_HEADER header;
    UINT32                  heartbeat_count;
    UINT32                  total_reports_completed;
    UINT32                  total_irps_completed;
    UINT32                  total_heartbeats_completed;

} HEARTBEAT_PACKET, *PHEARTBEAT_PACKET;

typedef struct _SYSTEM_MODULE_INTEGRITY_CHECK_REPORT {
    REPORT_PACKET_HEADER header;
    UINT64               image_base;
    UINT32               image_size;
    CHAR                 path_name[0x100];

} SYSTEM_MODULE_INTEGRITY_CHECK_REPORT, *PSYSTEM_MODULE_INTEGRITY_CHECK_REPORT;

typedef struct _EPT_HOOK_REPORT {
    REPORT_PACKET_HEADER header;
    UINT64               control_average;
    UINT64               read_average;
    CHAR                 function_name[128];
} EPT_HOOK_REPORT, *PEPT_HOOK_REPORT;

typedef struct _DRIVER_SELF_INTEGRITY_CHECK_REPORT {
    REPORT_PACKET_HEADER header;
    UINT64               image_base;
    UINT32               image_size;
    CHAR                 path_name[0x100];

} DRIVER_SELF_INTEGRITY_CHECK_REPORT, *PDRIVER_SELF_INTEGRITY_CHECK_REPORT;

typedef struct _BLACKLISTED_PCIE_DEVICE_REPORT {
    REPORT_PACKET_HEADER header;
    UINT64               device_object;
    UINT16               device_id;
    UINT16               vendor_id;

} BLACKLISTED_PCIE_DEVICE_REPORT, *PBLACKLISTED_PCIE_DEVICE_REPORT;

#endif