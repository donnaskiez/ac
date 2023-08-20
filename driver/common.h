#ifndef COMMON_H
#define COMMON_H

#include <ntifs.h>
#include <wdftypes.h>
#include <wdf.h>

#define DEBUG_LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[+] " fmt "\n", ##__VA_ARGS__)
#define DEBUG_ERROR(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[-] " fmt "\n", ##__VA_ARGS__)

#define NMI_CONTEXT_POOL '7331'
#define STACK_FRAMES_POOL 'loop'
#define INVALID_DRIVER_LIST_HEAD_POOL 'rwar'
#define INVALID_DRIVER_LIST_ENTRY_POOL 'gaah'
#define SYSTEM_MODULES_POOL 'halb'
#define THREAD_DATA_POOL 'doof'
#define PROC_AFFINITY_POOL 'eeee'
#define TEMP_BUFFER_POOL 'ffff'

#define ERROR -1
#define STACK_FRAME_POOL_SIZE 0x200
#define NUMBER_HASH_BUCKETS 37

#define KTHREAD_STACK_BASE_OFFSET 0x030
#define KTHREAD_STACK_LIMIT_OFFSET 0x038
#define KTHREAD_START_ADDRESS_OFFSET 0x450

typedef struct _KAFFINITY_EX
{
	USHORT Count;
	USHORT Size;
	ULONG Reserved;
	ULONGLONG Bitmap[ 20 ];

} KAFFINITY_EX, * PKAFFINITY_EX;

typedef struct _OBJECT_DIRECTORY_ENTRY
{
	struct _OBJECT_DIRECTORY_ENTRY* ChainLink;
	PVOID Object;
	ULONG HashValue;

} OBJECT_DIRECTORY_ENTRY, * POBJECT_DIRECTORY_ENTRY;

typedef struct _OBJECT_DIRECTORY
{
	POBJECT_DIRECTORY_ENTRY HashBuckets[ NUMBER_HASH_BUCKETS ];
	EX_PUSH_LOCK Lock;
	struct _DEVICE_MAP* DeviceMap;
	ULONG SessionId;
	PVOID NamespaceEntry;
	ULONG Flags;

} OBJECT_DIRECTORY, * POBJECT_DIRECTORY;

typedef struct _DEVICE_MAP
{
	struct _OBJECT_DIRECTORY* DosDevicesDirectory;
	struct _OBJECT_DIRECTORY* GlobalDosDevicesDirectory;
	ULONG ReferenceCount;
	ULONG DriveMap;
	UCHAR DriveType[ 32 ];

} DEVICE_MAP, * PDEVICE_MAP;

typedef struct _RTL_MODULE_EXTENDED_INFO
{
	PVOID ImageBase;
	ULONG ImageSize;
	USHORT FileNameOffset;
	CHAR FullPathName[ 0x100 ];

} RTL_MODULE_EXTENDED_INFO, * PRTL_MODULE_EXTENDED_INFO;

/* undocumented functions */

EXTERN_C VOID KeInitializeAffinityEx(
	PKAFFINITY_EX affinity
);

EXTERN_C VOID KeAddProcessorAffinityEx(
	PKAFFINITY_EX affinity,
	INT num
);

EXTERN_C VOID HalSendNMI(
	PKAFFINITY_EX affinity
);

NTSTATUS
RtlQueryModuleInformation(
	ULONG* InformationLength,
	ULONG SizePerModule,
	PVOID InformationBuffer );

/*
Thread Information Block: (GS register)

	SEH frame:						0x00
	Stack Base:						0x08
	Stack Limit:					0x10
	SubSystemTib:					0x18
	Fiber Data:						0x20
	Arbitrary Data:					0x28
	TEB:							0x30
	Environment Pointer:			0x38
	Process ID:						0x40
	Current Thread ID:				0x48
	Active RPC Handle:				0x50
	Thread Local Storage Array:		0x58
	PEB:							0x60
	Last error number:				0x68
	Count Owned Critical Sections:  0x6C
	CSR Client Thread:				0x70
	Win32 Thread Information:		0x78
	...
*/

#pragma once

#include <ntifs.h>
#include <wdftypes.h>

typedef struct _OBJECT_TYPE
{
    LIST_ENTRY TypeList;
    UNICODE_STRING Name;
    PVOID DefaultObject;
    UCHAR Index;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    PVOID TypeInfo; //_OBJECT_TYPE_INITIALIZER
    EX_PUSH_LOCK TypeLock;
    ULONG Key;
    LIST_ENTRY CallbackList;

} OBJECT_TYPE, * POBJECT_TYPE;

typedef struct _PEB_LDR_DATA {
    BYTE Reserved1[ 8 ];
    PVOID Reserved2[ 3 ];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[ 2 ];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[ 2 ];
    PVOID DllBase;
    PVOID Reserved3[ 2 ];
    UNICODE_STRING FullDllName;
    BYTE Reserved4[ 8 ];
    PVOID Reserved5[ 3 ];
#pragma warning(push)
#pragma warning(disable: 4201) // we'll always use the Microsoft compiler
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    } DUMMYUNIONNAME;
#pragma warning(pop)
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BYTE                          Reserved1[ 2 ];
    BYTE                          BeingDebugged;
    BYTE                          Reserved2[ 1 ];
    PVOID                         Reserved3[ 2 ];
    PPEB_LDR_DATA                 Ldr;
    PVOID                         ProcessParameters;
    PVOID                         Reserved4[ 3 ];
    PVOID                         AtlThunkSListPtr;
    PVOID                         Reserved5;
    ULONG                         Reserved6;
    PVOID                         Reserved7;
    ULONG                         Reserved8;
    ULONG                         AtlThunkSListPtr32;
    PVOID                         Reserved9[ 45 ];
    BYTE                          Reserved10[ 96 ];
    PVOID                         PostProcessInitRoutine;
    BYTE                          Reserved11[ 128 ];
    PVOID                         Reserved12[ 1 ];
    ULONG                         SessionId;
} PEB, * PPEB;

typedef struct _PEB32 {
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    ULONG Mutant;
    ULONG ImageBaseAddress;
    ULONG Ldr;
    ULONG ProcessParameters;
    ULONG SubSystemData;
    ULONG ProcessHeap;
    ULONG FastPebLock;
    ULONG AtlThunkSListPtr;
    ULONG IFEOKey;
    ULONG CrossProcessFlags;
    ULONG UserSharedInfoPtr;
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    ULONG ApiSetMap;
} PEB32, * PPEB32;

typedef struct _PEB_LDR_DATA32 {
    ULONG Length;
    UCHAR Initialized;
    ULONG SsHandle;
    LIST_ENTRY32 InLoadOrderModuleList;
    LIST_ENTRY32 InMemoryOrderModuleList;
    LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32 {
    LIST_ENTRY32 InLoadOrderLinks;
    LIST_ENTRY32 InMemoryOrderLinks;
    LIST_ENTRY32 InInitializationOrderLinks;
    ULONG DllBase;
    ULONG EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING32 FullDllName;
    UNICODE_STRING32 BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY32 HashLinks;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

typedef struct _HANDLE_TABLE_ENTRY_INFO
{
    ULONG AuditMask;
    ULONG MaxRelativeAccessMask;

} HANDLE_TABLE_ENTRY_INFO, * PHANDLE_TABLE_ENTRY_INFO;

typedef union _EXHANDLE
{
    struct
    {
        int TagBits : 2;
        int Index : 30;
    } u;
    void* GenericHandleOverlay;
    ULONG_PTR Value;
} EXHANDLE, * PEXHANDLE;

#pragma warning(disable : 4214 4201)

#pragma pack(push, 1)
typedef struct _POOL_HEADER // Size=16
{
    union
    {
        struct
        {
            unsigned long PreviousSize : 8; // Size=4 Offset=0 BitOffset=0 BitCount=8
            unsigned long PoolIndex : 8; // Size=4 Offset=0 BitOffset=8 BitCount=8
            unsigned long BlockSize : 8; // Size=4 Offset=0 BitOffset=16 BitCount=8
            unsigned long PoolType : 8; // Size=4 Offset=0 BitOffset=24 BitCount=8
        };
        unsigned long Ulong1; // Size=4 Offset=0
    };
    unsigned long PoolTag; // Size=4 Offset=4
    union
    {
        struct _EPROCESS* ProcessBilled; // Size=8 Offset=8
        struct
        {
            unsigned short AllocatorBackTraceIndex; // Size=2 Offset=8
            unsigned short PoolTagHash; // Size=2 Offset=10
        };
    };
} POOL_HEADER, * PPOOL_HEADER;
#pragma pack(pop)

typedef struct _HANDLE_TABLE_ENTRY // Size=16
{
    union
    {
        ULONG_PTR VolatileLowValue; // Size=8 Offset=0
        ULONG_PTR LowValue; // Size=8 Offset=0
        struct _HANDLE_TABLE_ENTRY_INFO* InfoTable; // Size=8 Offset=0
        struct
        {
            ULONG_PTR Unlocked : 1; // Size=8 Offset=0 BitOffset=0 BitCount=1
            ULONG_PTR RefCnt : 16; // Size=8 Offset=0 BitOffset=1 BitCount=16
            ULONG_PTR Attributes : 3; // Size=8 Offset=0 BitOffset=17 BitCount=3
            ULONG_PTR ObjectPointerBits : 44; // Size=8 Offset=0 BitOffset=20 BitCount=44
        };
    };
    union
    {
        ULONG_PTR HighValue; // Size=8 Offset=8
        struct _HANDLE_TABLE_ENTRY* NextFreeHandleEntry; // Size=8 Offset=8
        union _EXHANDLE LeafHandleValue; // Size=8 Offset=8
        struct
        {
            ULONG GrantedAccessBits : 25; // Size=4 Offset=8 BitOffset=0 BitCount=25
            ULONG NoRightsUpgrade : 1; // Size=4 Offset=8 BitOffset=25 BitCount=1
            ULONG Spare : 6; // Size=4 Offset=8 BitOffset=26 BitCount=6
        };
    };
    ULONG TypeInfo; // Size=4 Offset=12
} HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;

typedef struct _HANDLE_TABLE_FREE_LIST
{
    EX_PUSH_LOCK FreeListLock;
    PHANDLE_TABLE_ENTRY FirstFreeHandleEntry;
    PHANDLE_TABLE_ENTRY LastFreeHandleEntry;
    LONG HandleCount;
    ULONG HighWaterMark;
} HANDLE_TABLE_FREE_LIST, * PHANDLE_TABLE_FREE_LIST;

typedef struct _HANDLE_TRACE_DB_ENTRY
{
    CLIENT_ID ClientId;
    PVOID Handle;
    ULONG Type;
    PVOID StackTrace[ 16 ];

} HANDLE_TRACE_DB_ENTRY, * PHANDLE_TRACE_DB_ENTRY;



typedef struct _HANDLE_TRACE_DEBUG_INFO
{
    LONG RefCount;
    ULONG TableSize;
    ULONG BitMaskFlags;
    FAST_MUTEX CloseCompactionLock;
    ULONG CurrentStackIndex;
    HANDLE_TRACE_DB_ENTRY TraceDb[ 1 ];

} HANDLE_TRACE_DEBUG_INFO, * PHANDLE_TRACE_DEBUG_INFO;

typedef struct _HANDLE_TABLE
{
    ULONG NextHandleNeedingPool;
    LONG ExtraInfoPages;
    ULONGLONG TableCode;
    PEPROCESS QuotaProcess;
    LIST_ENTRY HandleTableList;
    ULONG UniqueProcessId;
    union {
        ULONG Flags;
        struct {
            UCHAR StrictFIFO : 1;
            UCHAR EnableHandleExceptions : 1;
            UCHAR Rundown : 1;
            UCHAR Duplicated : 1;
            UCHAR RaiseUMExceptionOnInvalidHandleClose : 1;
        };
    };
    EX_PUSH_LOCK HandleContentionEvent;
    EX_PUSH_LOCK HandleTableLock;
    union {
        HANDLE_TABLE_FREE_LIST FreeLists[ 1 ];
        UCHAR ActualEntry[ 32 ];
    };

    struct _HANDLE_TRACE_DEBUG_INFO* DebugInfo;

} HANDLE_TABLE, * PHANDLE_TABLE;

typedef BOOLEAN( *EX_ENUMERATE_HANDLE_ROUTINE )(
    IN PHANDLE_TABLE_ENTRY HandleTableEntry,
    IN HANDLE Handle,
    IN PVOID EnumParameter
    );

typedef struct _OBJECT_CREATE_INFORMATION
{
    ULONG Attributes;
    PVOID RootDirectory;
    CHAR ProbeMode;
    ULONG PagedPoolCharge;
    ULONG NonPagedPoolCharge;
    ULONG SecurityDescriptorCharge;
    PVOID SecurityDescriptor;
    struct _SECURITY_QUALITY_OF_SERVICE* SecurityQos;
    struct _SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;

} OBJECT_CREATE_INFORMATION, * POBJECT_CREATE_INFORMATION;

typedef struct _OBJECT_HEADER
{
    LONGLONG PointerCount;
    union {
        LONGLONG HandleCount;
        PVOID NextToFree;
    };
    EX_PUSH_LOCK Lock;
    UCHAR TypeIndex;
    union {
        UCHAR TraceFlags;
        struct {
            UCHAR DbgRefTrace : 1;
            UCHAR DbgTracePermanent : 1;
        };
    };
    UCHAR InfoMask;
    union {
        UCHAR Flags;
        struct {
            UCHAR NewObject : 1;
            UCHAR KernelObject : 1;
            UCHAR KernelOnlyAccess : 1;
            UCHAR ExclusiveObject : 1;
            UCHAR PermanentObject : 1;
            UCHAR DefaultSecurityQuota : 1;
            UCHAR SingleHandleEntry : 1;
            UCHAR DeletedInline : 1;
        };
    };
    ULONG Reserved;
    union {
        POBJECT_CREATE_INFORMATION ObjectCreateInfo;
        PVOID QuotaBlockCharged;
    };
    PVOID SecurityDescriptor;
    QUAD Body;
} OBJECT_HEADER, * POBJECT_HEADER;

NTKERNELAPI
BOOLEAN
ExEnumHandleTable(
    __in PHANDLE_TABLE HandleTable,
    __in EX_ENUMERATE_HANDLE_ROUTINE EnumHandleProcedure,
    __in PVOID EnumParameter,
    __out_opt PHANDLE Handle
);

NTKERNELAPI
POBJECT_TYPE
NTAPI
ObGetObjectType(
    _In_ PVOID Object
);

typedef struct _EX_PUSH_LOCK_WAIT_BLOCK* PEX_PUSH_LOCK_WAIT_BLOCK;

NTKERNELAPI
VOID
FASTCALL
ExfUnblockPushLock(
    _Inout_ PEX_PUSH_LOCK PushLock,
    _Inout_opt_ PEX_PUSH_LOCK_WAIT_BLOCK WaitBlock
);

LPCSTR
NTSYSAPI
NTAPI
PsGetProcessImageFileName(
    PEPROCESS Process
);

#endif
