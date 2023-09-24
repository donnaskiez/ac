#ifndef COMMON_H
#define COMMON_H

#include <ntifs.h>
#include <wdftypes.h>

#define DEBUG_LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[+] " fmt "\n", ##__VA_ARGS__)
#define DEBUG_ERROR(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[-] " fmt "\n", ##__VA_ARGS__)

#define NMI_CONTEXT_POOL '7331'
#define STACK_FRAMES_POOL 'loop'
#define INVALID_DRIVER_LIST_HEAD_POOL 'rwar'
#define INVALID_DRIVER_LIST_ENTRY_POOL 'gaah'
#define POOL_TAG_APC 'apcc'
#define SYSTEM_MODULES_POOL 'halb'
#define THREAD_DATA_POOL 'doof'
#define PROC_AFFINITY_POOL 'eeee'
#define TEMP_BUFFER_POOL 'ffff'
#define DRIVER_PATH_POOL_TAG 'path'
#define POOL_TAG_INTEGRITY 'intg'
#define POOL_TAG_MODULE_MEMORY_BUF 'lolo'
#define POOL_TAG_MODULE_MEMORY_BUF_2 'leeo'
#define POOL_TAG_HASH_OBJECT 'hobj'
#define POOL_TAG_RESULTING_HASH 'hash'
#define POOL_TAG_SAVE_EX_REGIONS 'sexc'
#define POOL_DUMP_BLOCK_TAG 'dump'
#define POOL_DEBUGGER_DATA_TAG 'data'
#define PROCESS_ADDRESS_LIST_TAG 'addr'
#define ANALYSE_PROCESS_TAG 'anls'
#define INVALID_PROCESS_REPORT_TAG 'invd'
#define QUEUE_POOL_TAG 'qqqq'
#define REPORT_QUEUE_TEMP_BUFFER_TAG 'temp'
#define REPORT_POOL_TAG 'repo'
#define MODULES_REPORT_POOL_TAG 'modu'

#define ERROR -1
#define STACK_FRAME_POOL_SIZE 0x200
#define NUMBER_HASH_BUCKETS 37

#define KTHREAD_STACK_BASE_OFFSET 0x030
#define KTHREAD_STACK_LIMIT_OFFSET 0x038
#define KTHREAD_THREADLIST_OFFSET 0x2f8
#define KTHREAD_APC_STATE_OFFSET 0x258
#define KTHREAD_START_ADDRESS_OFFSET 0x450

#define EPROCESS_PEAK_VIRTUAL_SIZE_OFFSET 0x490
#define EPROCESS_VAD_ROOT_OFFSET 0x7d8
#define EPROCESS_OBJECT_TABLE_OFFSET 0x570
#define EPROCESS_IMAGE_NAME_OFFSET 0x5a8
#define EPROCESS_PEB_OFFSET 0x550

#define KPROCESS_THREADLIST_OFFSET 0x030
#define KPROCESS_DIRECTORY_TABLE_BASE_OFFSET 0x028

#define OBJECT_HEADER_SIZE 0x30
#define OBJECT_HEADER_TYPE_INDEX_OFFSET 0x018 

#define POOL_HEADER_BLOCK_SIZE_OFFSET 0x02
#define POOL_HEADER_TAG_OFFSET 0x04

#define KPROCESS_OFFSET_FROM_POOL_HEADER_SIZE_1 0x70
#define KPROCESS_OFFSET_FROM_POOL_HEADER_SIZE_2 0x80
#define KPROCESS_OFFSET_FROM_POOL_HEADER_SIZE_3 0x30
#define EPROCESS_SIZE 0xa40

#define KPCRB_CURRENT_THREAD 0x8

#define IA32_GS_BASE 0xc0000101
#define KPRCB_OFFSET_FROM_GS_BASE 0x180

#define MODULE_VALIDATION_FAILURE_MAX_REPORT_COUNT 20
#define REPORT_NMI_CALLBACK_FAILURE 50
#define REPORT_MODULE_VALIDATION_FAILURE 60
#define REPORT_ILLEGAL_HANDLE_OPERATION 70
#define REPORT_INVALID_PROCESS_ALLOCATION 80
#define REPORT_HIDDEN_SYSTEM_THREAD 90
#define REPORT_ILLEGAL_ATTACH_PROCESS 100

/*
 * Generic macros that allow you to quickly determine whether
 *  or not a page table entry is present or may forward to a
 *  large page of data, rather than another page table (applies
 *  only to PDPTEs and PDEs)
 *
 * Some nice macros courtesy of:
 * https://www.unknowncheats.me/forum/general-programming-and-reversing/523359-introduction-physical-memory.html
 */
#define IS_LARGE_PAGE(x)    ( (BOOLEAN)((x >> 7) & 1) )
#define IS_PAGE_PRESENT(x)  ( (BOOLEAN)(x & 1) )

#define PAGE_1GB_SHIFT      30
#define PAGE_1GB_OFFSET(x)  ( x & (~(MAXUINT64 << PAGE_1GB_SHIFT)) )

#define PAGE_2MB_SHIFT      21
#define PAGE_2MB_OFFSET(x)  ( x & (~(MAXUINT64 << PAGE_2MB_SHIFT)) )

#define PAGE_4KB_SHIFT      12
#define PAGE_4KB_OFFSET(x)  ( x & (~(MAXUINT64 << PAGE_4KB_SHIFT)) )

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

#define IMAGE_SCN_MEM_EXECUTE 0x20000000

#define IMAGE_SIZEOF_SHORT_NAME 8

typedef struct _IMAGE_SECTION_HEADER {
    unsigned char    Name[ IMAGE_SIZEOF_SHORT_NAME ];
    union {
        unsigned long PhysicalAddress;
        unsigned long VirtualSize;
    } Misc;
    unsigned long VirtualAddress;
    unsigned long SizeOfRawData;
    unsigned long PointerToRawData;
    unsigned long PointerToRelocations;
    unsigned long PointerToLinenumbers;
    unsigned short NumberOfRelocations;
    unsigned short NumberOfLinenumbers;
    unsigned long Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    unsigned short    Machine;
    unsigned short    NumberOfSections;
    unsigned long   TimeDateStamp;
    unsigned long   PointerToSymbolTable;
    unsigned long   NumberOfSymbols;
    unsigned short    SizeOfOptionalHeader;
    unsigned short    Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    unsigned long   VirtualAddress;
    unsigned long   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    unsigned short        Magic;
    unsigned char        MajorLinkerVersion;
    unsigned char        MinorLinkerVersion;
    unsigned long       SizeOfCode;
    unsigned long       SizeOfInitializedData;
    unsigned long       SizeOfUninitializedData;
    unsigned long       AddressOfEntryPoint;
    unsigned long       BaseOfCode;
    ULONGLONG   ImageBase;
    unsigned long       SectionAlignment;
    unsigned long       FileAlignment;
    unsigned short        MajorOperatingSystemVersion;
    unsigned short        MinorOperatingSystemVersion;
    unsigned short        MajorImageVersion;
    unsigned short        MinorImageVersion;
    unsigned short        MajorSubsystemVersion;
    unsigned short        MinorSubsystemVersion;
    unsigned long       Win32VersionValue;
    unsigned long       SizeOfImage;
    unsigned long       SizeOfHeaders;
    unsigned long       CheckSum;
    unsigned short        Subsystem;
    unsigned short        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    unsigned long       LoaderFlags;
    unsigned long       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[ IMAGE_NUMBEROF_DIRECTORY_ENTRIES ];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    unsigned short   e_magic;                     // Magic number
    unsigned short   e_cblp;                      // Bytes on last page of file
    unsigned short   e_cp;                        // Pages in file
    unsigned short   e_crlc;                      // Relocations
    unsigned short   e_cparhdr;                   // Size of header in paragraphs
    unsigned short   e_minalloc;                  // Minimum extra paragraphs needed
    unsigned short   e_maxalloc;                  // Maximum extra paragraphs needed
    unsigned short   e_ss;                        // Initial (relative) SS value
    unsigned short   e_sp;                        // Initial SP value
    unsigned short   e_csum;                      // Checksum
    unsigned short   e_ip;                        // Initial IP value
    unsigned short   e_cs;                        // Initial (relative) CS value
    unsigned short   e_lfarlc;                    // File address of relocation table
    unsigned short   e_ovno;                      // Overlay number
    unsigned short   e_res[ 4 ];                    // Reserved words
    unsigned short   e_oemid;                     // OEM identifier (for e_oeminfo)
    unsigned short   e_oeminfo;                   // OEM information; e_oemid specific
    unsigned short   e_res2[ 10 ];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _LOCAL_NT_HEADER {
    unsigned long Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} LOCAL_NT_HEADER, * PLOCAL_NT_HEADER;

#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( LOCAL_NT_HEADER, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

/* creds: https://www.unknowncheats.me/forum/2602838-post2.html */

typedef struct _DBGKD_DEBUG_DATA_HEADER64
{
    LIST_ENTRY64 List;
    ULONG        OwnerTag;
    ULONG        Size;
} DBGKD_DEBUG_DATA_HEADER64, * PDBGKD_DEBUG_DATA_HEADER64;

typedef struct _KDDEBUGGER_DATA64
{
    DBGKD_DEBUG_DATA_HEADER64 Header;
    ULONG64   KernBase;
    ULONG64   BreakpointWithStatus;
    ULONG64   SavedContext;
    USHORT    ThCallbackStack;
    USHORT    NextCallback;
    USHORT    FramePointer;
    USHORT    PaeEnabled;
    ULONG64   KiCallUserMode;
    ULONG64   KeUserCallbackDispatcher;
    ULONG64   PsLoadedModuleList;
    ULONG64   PsActiveProcessHead;
    ULONG64   PspCidTable;
    ULONG64   ExpSystemResourcesList;
    ULONG64   ExpPagedPoolDescriptor;
    ULONG64   ExpNumberOfPagedPools;
    ULONG64   KeTimeIncrement;
    ULONG64   KeBugCheckCallbackListHead;
    ULONG64   KiBugcheckData;
    ULONG64   IopErrorLogListHead;
    ULONG64   ObpRootDirectoryObject;
    ULONG64   ObpTypeObjectType;
    ULONG64   MmSystemCacheStart;
    ULONG64   MmSystemCacheEnd;
    ULONG64   MmSystemCacheWs;
    ULONG64   MmPfnDatabase;
    ULONG64   MmSystemPtesStart;
    ULONG64   MmSystemPtesEnd;
    ULONG64   MmSubsectionBase;
    ULONG64   MmNumberOfPagingFiles;
    ULONG64   MmLowestPhysicalPage;
    ULONG64   MmHighestPhysicalPage;
    ULONG64   MmNumberOfPhysicalPages;
    ULONG64   MmMaximumNonPagedPoolInBytes;
    ULONG64   MmNonPagedSystemStart;
    ULONG64   MmNonPagedPoolStart;
    ULONG64   MmNonPagedPoolEnd;
    ULONG64   MmPagedPoolStart;
    ULONG64   MmPagedPoolEnd;
    ULONG64   MmPagedPoolInformation;
    ULONG64   MmPageSize;
    ULONG64   MmSizeOfPagedPoolInBytes;
    ULONG64   MmTotalCommitLimit;
    ULONG64   MmTotalCommittedPages;
    ULONG64   MmSharedCommit;
    ULONG64   MmDriverCommit;
    ULONG64   MmProcessCommit;
    ULONG64   MmPagedPoolCommit;
    ULONG64   MmExtendedCommit;
    ULONG64   MmZeroedPageListHead;
    ULONG64   MmFreePageListHead;
    ULONG64   MmStandbyPageListHead;
    ULONG64   MmModifiedPageListHead;
    ULONG64   MmModifiedNoWritePageListHead;
    ULONG64   MmAvailablePages;
    ULONG64   MmResidentAvailablePages;
    ULONG64   PoolTrackTable;
    ULONG64   NonPagedPoolDescriptor;
    ULONG64   MmHighestUserAddress;
    ULONG64   MmSystemRangeStart;
    ULONG64   MmUserProbeAddress;
    ULONG64   KdPrintCircularBuffer;
    ULONG64   KdPrintCircularBufferEnd;
    ULONG64   KdPrintWritePointer;
    ULONG64   KdPrintRolloverCount;
    ULONG64   MmLoadedUserImageList;
    ULONG64   NtBuildLab;
    ULONG64   KiNormalSystemCall;
    ULONG64   KiProcessorBlock;
    ULONG64   MmUnloadedDrivers;
    ULONG64   MmLastUnloadedDriver;
    ULONG64   MmTriageActionTaken;
    ULONG64   MmSpecialPoolTag;
    ULONG64   KernelVerifier;
    ULONG64   MmVerifierData;
    ULONG64   MmAllocatedNonPagedPool;
    ULONG64   MmPeakCommitment;
    ULONG64   MmTotalCommitLimitMaximum;
    ULONG64   CmNtCSDVersion;
    ULONG64   MmPhysicalMemoryBlock;
    ULONG64   MmSessionBase;
    ULONG64   MmSessionSize;
    ULONG64   MmSystemParentTablePage;
    ULONG64   MmVirtualTranslationBase;
    USHORT    OffsetKThreadNextProcessor;
    USHORT    OffsetKThreadTeb;
    USHORT    OffsetKThreadKernelStack;
    USHORT    OffsetKThreadInitialStack;
    USHORT    OffsetKThreadApcProcess;
    USHORT    OffsetKThreadState;
    USHORT    OffsetKThreadBStore;
    USHORT    OffsetKThreadBStoreLimit;
    USHORT    SizeEProcess;
    USHORT    OffsetEprocessPeb;
    USHORT    OffsetEprocessParentCID;
    USHORT    OffsetEprocessDirectoryTableBase;
    USHORT    SizePrcb;
    USHORT    OffsetPrcbDpcRoutine;
    USHORT    OffsetPrcbCurrentThread;
    USHORT    OffsetPrcbMhz;
    USHORT    OffsetPrcbCpuType;
    USHORT    OffsetPrcbVendorString;
    USHORT    OffsetPrcbProcStateContext;
    USHORT    OffsetPrcbNumber;
    USHORT    SizeEThread;
    ULONG64   KdPrintCircularBufferPtr;
    ULONG64   KdPrintBufferSize;
    ULONG64   KeLoaderBlock;
    USHORT    SizePcr;
    USHORT    OffsetPcrSelfPcr;
    USHORT    OffsetPcrCurrentPrcb;
    USHORT    OffsetPcrContainedPrcb;
    USHORT    OffsetPcrInitialBStore;
    USHORT    OffsetPcrBStoreLimit;
    USHORT    OffsetPcrInitialStack;
    USHORT    OffsetPcrStackLimit;
    USHORT    OffsetPrcbPcrPage;
    USHORT    OffsetPrcbProcStateSpecialReg;
    USHORT    GdtR0Code;
    USHORT    GdtR0Data;
    USHORT    GdtR0Pcr;
    USHORT    GdtR3Code;
    USHORT    GdtR3Data;
    USHORT    GdtR3Teb;
    USHORT    GdtLdt;
    USHORT    GdtTss;
    USHORT    Gdt64R3CmCode;
    USHORT    Gdt64R3CmTeb;
    ULONG64   IopNumTriageDumpDataBlocks;
    ULONG64   IopTriageDumpDataBlocks;
} KDDEBUGGER_DATA64, * PKDDEBUGGER_DATA64;

typedef struct _KDDEBUGGER_DATA_ADDITION64
{
    ULONG64   VfCrashDataBlock;
    ULONG64   MmBadPagesDetected;
    ULONG64   MmZeroedPageSingleBitErrorsDetected;
    ULONG64   EtwpDebuggerData;
    USHORT    OffsetPrcbContext;
    USHORT    OffsetPrcbMaxBreakpoints;
    USHORT    OffsetPrcbMaxWatchpoints;
    ULONG     OffsetKThreadStackLimit;
    ULONG     OffsetKThreadStackBase;
    ULONG     OffsetKThreadQueueListEntry;
    ULONG     OffsetEThreadIrpList;
    USHORT    OffsetPrcbIdleThread;
    USHORT    OffsetPrcbNormalDpcState;
    USHORT    OffsetPrcbDpcStack;
    USHORT    OffsetPrcbIsrStack;
    USHORT    SizeKDPC_STACK_FRAME;
    USHORT    OffsetKPriQueueThreadListHead;
    USHORT    OffsetKThreadWaitReason;
    USHORT    Padding;
    ULONG64   PteBase;
    ULONG64   RetpolineStubFunctionTable;
    ULONG     RetpolineStubFunctionTableSize;
    ULONG     RetpolineStubOffset;
    ULONG     RetpolineStubSize;
}KDDEBUGGER_DATA_ADDITION64, * PKDDEBUGGER_DATA_ADDITION64;


typedef struct _DUMP_HEADER
{
    ULONG Signature;
    ULONG ValidDump;
    ULONG MajorVersion;
    ULONG MinorVersion;
    ULONG_PTR DirectoryTableBase;
    ULONG_PTR PfnDataBase;
    PLIST_ENTRY PsLoadedModuleList;
    PLIST_ENTRY PsActiveProcessHead;
    ULONG MachineImageType;
    ULONG NumberProcessors;
    ULONG BugCheckCode;
    ULONG_PTR BugCheckParameter1;
    ULONG_PTR BugCheckParameter2;
    ULONG_PTR BugCheckParameter3;
    ULONG_PTR BugCheckParameter4;
    CHAR VersionUser[ 32 ];
    struct _KDDEBUGGER_DATA64* KdDebuggerDataBlock;
} DUMP_HEADER, * PDUMP_HEADER;

typedef union _DIRECTORY_TABLE_BASE
{
    struct
    {
        UINT64 Ignored0 : 3;            /* 2:0   */
        UINT64 PageWriteThrough : 1;    /* 3     */
        UINT64 PageCacheDisable : 1;    /* 4     */
        UINT64 _Ignored1 : 7;           /* 11:5  */
        UINT64 PhysicalAddress : 36;    /* 47:12 */
        UINT64 _Reserved0 : 16;         /* 63:48 */

    } Bits;

    UINT64 BitAddress;

} CR3, DIR_TABLE_BASE;

typedef union _VIRTUAL_MEMORY_ADDRESS
{
    struct
    {
        UINT64 PageIndex : 12;  /* 0:11  */
        UINT64 PtIndex : 9;	/* 12:20 */
        UINT64 PdIndex : 9;	/* 21:29 */
        UINT64 PdptIndex : 9;   /* 30:38 */
        UINT64 Pml4Index : 9;   /* 39:47 */
        UINT64 Unused : 16;	/* 48:63 */

    } Bits;

    UINT64 BitAddress;

} VIRTUAL_ADDRESS, * PVIRTUAL_ADDRESS;

typedef union _PML4_ENTRY
{
    struct
    {
        UINT64 Present : 1;    /* 0     */
        UINT64 ReadWrite : 1;    /* 1     */
        UINT64 UserSupervisor : 1;    /* 2     */
        UINT64 PageWriteThrough : 1;    /* 3     */
        UINT64 PageCacheDisable : 1;    /* 4     */
        UINT64 Accessed : 1;    /* 5     */
        UINT64 _Ignored0 : 1;    /* 6     */
        UINT64 _Reserved0 : 1;    /* 7     */
        UINT64 _Ignored1 : 4;    /* 11:8  */
        UINT64 PhysicalAddress : 40;   /* 51:12 */
        UINT64 _Ignored2 : 11;   /* 62:52 */
        UINT64 ExecuteDisable : 1;    /* 63    */
    } Bits;
    UINT64 BitAddress;
} PML4E;

typedef union _PDPT_ENTRY
{
    struct
    {
        UINT64 Present : 1;    /* 0     */
        UINT64 ReadWrite : 1;    /* 1     */
        UINT64 UserSupervisor : 1;    /* 2     */
        UINT64 PageWriteThrough : 1;    /* 3     */
        UINT64 PageCacheDisable : 1;    /* 4     */
        UINT64 Accessed : 1;    /* 5     */
        UINT64 _Ignored0 : 1;    /* 6     */
        UINT64 PageSize : 1;    /* 7     */
        UINT64 _Ignored1 : 4;    /* 11:8  */
        UINT64 PhysicalAddress : 40;   /* 51:12 */
        UINT64 _Ignored2 : 11;   /* 62:52 */
        UINT64 ExecuteDisable : 1;    /* 63    */
    } Bits;
    UINT64 BitAddress;
} PDPTE;

typedef union _PD_ENTRY
{
    struct
    {
        UINT64 Present : 1;    /* 0     */
        UINT64 ReadWrite : 1;    /* 1     */
        UINT64 UserSupervisor : 1;    /* 2     */
        UINT64 PageWriteThrough : 1;    /* 3     */
        UINT64 PageCacheDisable : 1;    /* 4     */
        UINT64 Accessed : 1;    /* 5     */
        UINT64 _Ignored0 : 1;    /* 6     */
        UINT64 PageSize : 1;    /* 7     */
        UINT64 _Ignored1 : 4;    /* 11:8  */
        UINT64 PhysicalAddress : 38;   /* 49:12 */
        UINT64 _Reserved0 : 2;    /* 51:50 */
        UINT64 _Ignored2 : 11;   /* 62:52 */
        UINT64 ExecuteDisable : 1;    /* 63    */
    } Bits;
    UINT64 BitAddress;
} PDE;

typedef union _PT_ENTRY
{
    struct
    {
        UINT64 Present : 1;    /* 0     */
        UINT64 ReadWrite : 1;    /* 1     */
        UINT64 UserSupervisor : 1;    /* 2     */
        UINT64 PageWriteThrough : 1;    /* 3     */
        UINT64 PageCacheDisable : 1;    /* 4     */
        UINT64 Accessed : 1;    /* 5     */
        UINT64 Dirty : 1;    /* 6     */
        UINT64 PageAttributeTable : 1;    /* 7     */
        UINT64 Global : 1;    /* 8     */
        UINT64 _Ignored0 : 3;    /* 11:9  */
        UINT64 PhysicalAddress : 38;   /* 49:12 */
        UINT64 _Reserved0 : 2;    /* 51:50 */
        UINT64 _Ignored1 : 7;    /* 58:52 */
        UINT64 ProtectionKey : 4;    /* 62:59 */
        UINT64 ExecuteDisable : 1;    /* 63    */
    } Bits;
    UINT64 BitAddress;
} PTE;

typedef union _PDPT_ENTRY_LARGE
{
    struct
    {
        UINT64 Present : 1;    /* 0     */
        UINT64 ReadWrite : 1;    /* 1     */
        UINT64 UserSupervisor : 1;    /* 2     */
        UINT64 PageWriteThrough : 1;    /* 3     */
        UINT64 PageCacheDisable : 1;    /* 4     */
        UINT64 Accessed : 1;    /* 5     */
        UINT64 Dirty : 1;    /* 6     */
        UINT64 PageSize : 1;    /* 7     */
        UINT64 Global : 1;    /* 8     */
        UINT64 _Ignored0 : 3;    /* 11:9  */
        UINT64 PageAttributeTable : 1;    /* 12    */
        UINT64 _Reserved0 : 17;   /* 29:13 */
        UINT64 PhysicalAddress : 22;   /* 51:30 */
        UINT64 _Ignored1 : 7;    /* 58:52 */
        UINT64 ProtectionKey : 4;    /* 62:59 */
        UINT64 ExecuteDisable : 1;    /* 63    */
    } Bits;
    UINT64 BitAddress;
} PDPTE_LARGE;

typedef union _PD_ENTRY_LARGE
{
    struct
    {
        UINT64 Present : 1;    /* 0     */
        UINT64 ReadWrite : 1;    /* 1     */
        UINT64 UserSupervisor : 1;    /* 2     */
        UINT64 PageWriteThrough : 1;    /* 3     */
        UINT64 PageCacheDisable : 1;    /* 4     */
        UINT64 Accessed : 1;    /* 5     */
        UINT64 Dirty : 1;    /* 6     */
        UINT64 PageSize : 1;    /* 7     */
        UINT64 Global : 1;    /* 8     */
        UINT64 _Ignored0 : 3;    /* 11:9  */
        UINT64 PageAttributeTalbe : 1;    /* 12    */
        UINT64 _Reserved0 : 8;    /* 20:13 */
        UINT64 PhysicalAddress : 29;   /* 49:21 */
        UINT64 _Reserved1 : 2;    /* 51:50 */
        UINT64 _Ignored1 : 7;    /* 58:52 */
        UINT64 ProtectionKey : 4;    /* 62:59 */
        UINT64 ExecuteDisable : 1;    /* 63    */
    } Bits;
    UINT64 BitAddress;
} PDE_LARGE;

//typedef struct _KAPC_STATE
//{
//    LIST_ENTRY ApcListHead[ MaximumMode ];
//    struct _KPROCESS* Process;
//    union {
//        UCHAR InProgressFlags;
//        struct
//        {
//            BOOLEAN KernelApcInProgress : 1;
//            BOOLEAN SpecialApcInProgress : 1;
//        };
//    };
//
//    BOOLEAN KernelApcPending;
//    union {
//        BOOLEAN UserApcPendingAll;
//        struct
//        {
//            BOOLEAN SpecialUserApcPending : 1;
//            BOOLEAN UserApcPending : 1;
//        };
//    };
//} KAPC_STATE, * PKAPC_STATE, * PRKAPC_STATE;

typedef struct _RAW_SMBIOS_DATA
{
    BYTE    Used20CallingMethod;
    BYTE    SMBIOSMajorVersion;
    BYTE    SMBIOSMinorVersion;
    BYTE    DmiRevision;
    UINT32   Length;
    BYTE    SMBIOSTableData[];
} RAW_SMBIOS_DATA, * PRAW_SMBIOS_DATA;

typedef struct _SMBIOS_TABLE_HEADER
{
    UCHAR Type;
    UCHAR Length;
    USHORT Handle;
    PCHAR TableData;

} SMBIOS_TABLE_HEADER, *PSMBIOS_TABLE_HEADER;

typedef struct _RAW_SMBIOS_TABLE_01
{
    UCHAR Type;
    UCHAR Length;
    USHORT Handle;
    UCHAR Manufacturer;
    UCHAR ProductName;
    UCHAR Version;
    UCHAR SerialNumber;
    UCHAR UUID[ 16 ];
    UCHAR WakeUpType;
    UCHAR SKUNumber;
    UCHAR Family;

} RAW_SMBIOS_TABLE_01, *PRAW_SMBIOS_TABLE_01;

typedef struct _RAW_SMBIOS_TABLE_02 {
    UCHAR   Type;
    UCHAR   Length;
    USHORT  Handle;
    BYTE    Manufacturer;
    BYTE    Product;
    BYTE    Version;
    BYTE    SerialNumber;
    BYTE    AssetTag;
    BYTE    FeatureFlags;
    BYTE    LocationInChassis;
    UINT16    ChassisHandle;
    BYTE    BoardType;
    BYTE    NumberOfContainedObjectHandles;
    BYTE    ContainedObjectHandles[ 256 ];

}RAW_SMBIOS_TABLE_02, *PRAW_SMBIOS_TABLE_02;

typedef struct _RTL_RELATIVE_NAME {
    UNICODE_STRING RelativeName;
    HANDLE         ContainingDirectory;
    void* CurDirRef;
} RTL_RELATIVE_NAME, * PRTL_RELATIVE_NAME;

typedef struct _STORAGE_DESCRIPTOR_HEADER {
    ULONG  Version;
    ULONG  Size;
} STORAGE_DESCRIPTOR_HEADER, * PSTORAGE_DESCRIPTOR_HEADER;

typedef enum _STORAGE_BUS_TYPE {
    BusTypeUnknown = 0x00,
    BusTypeScsi,
    BusTypeAtapi,
    BusTypeAta,
    BusType1394,
    BusTypeSsa,
    BusTypeFibre,
    BusTypeUsb,
    BusTypeRAID,
    BusTypeMaxReserved = 0x7F
} STORAGE_BUS_TYPE, * PSTORAGE_BUS_TYPE;

typedef enum _STORAGE_SET_TYPE {
    PropertyStandardSet = 0,          // Sets the descriptor
    PropertyExistsSet,                // Used to test whether the descriptor is supported
    PropertySetMaxDefined             // use to validate the value
} STORAGE_SET_TYPE, * PSTORAGE_SET_TYPE;

//
// define some initial property id's
//

typedef enum _STORAGE_QUERY_TYPE {
    PropertyStandardQuery = 0,          // Retrieves the descriptor
    PropertyExistsQuery,                // Used to test whether the descriptor is supported
    PropertyMaskQuery,                  // Used to retrieve a mask of writeable fields in the descriptor
    PropertyQueryMaxDefined     // use to validate the value
} STORAGE_QUERY_TYPE, * PSTORAGE_QUERY_TYPE;

typedef enum _STORAGE_PROPERTY_ID {
    StorageDeviceProperty = 0,
    StorageAdapterProperty,
    StorageDeviceIdProperty,
    StorageDeviceUniqueIdProperty,                  // See storduid.h for details
    StorageDeviceWriteCacheProperty,
    StorageMiniportProperty,
    StorageAccessAlignmentProperty,
    StorageDeviceSeekPenaltyProperty,
    StorageDeviceTrimProperty,
    StorageDeviceWriteAggregationProperty,
    StorageDeviceDeviceTelemetryProperty,
    StorageDeviceLBProvisioningProperty,
    StorageDevicePowerProperty,
    StorageDeviceCopyOffloadProperty,
    StorageDeviceResiliencyProperty,
    StorageDeviceMediumProductType,
    StorageAdapterRpmbProperty,
    StorageAdapterCryptoProperty,
    StorageDeviceIoCapabilityProperty = 48,
    StorageAdapterProtocolSpecificProperty,
    StorageDeviceProtocolSpecificProperty,
    StorageAdapterTemperatureProperty,
    StorageDeviceTemperatureProperty,
    StorageAdapterPhysicalTopologyProperty,
    StorageDevicePhysicalTopologyProperty,
    StorageDeviceAttributesProperty,
    StorageDeviceManagementStatus,
    StorageAdapterSerialNumberProperty,
    StorageDeviceLocationProperty,
    StorageDeviceNumaProperty,
    StorageDeviceZonedDeviceProperty,
    StorageDeviceUnsafeShutdownCount,
    StorageDeviceEnduranceProperty,
    StorageDeviceLedStateProperty,
    StorageDeviceSelfEncryptionProperty = 64,
    StorageFruIdProperty,
} STORAGE_PROPERTY_ID, * PSTORAGE_PROPERTY_ID;

typedef struct _STORAGE_PROPERTY_QUERY {
    STORAGE_PROPERTY_ID  PropertyId;
    STORAGE_QUERY_TYPE  QueryType;
    UCHAR  AdditionalParameters[ 1 ];
} STORAGE_PROPERTY_QUERY, * PSTORAGE_PROPERTY_QUERY;

typedef struct _STORAGE_DEVICE_DESCRIPTOR {
    ULONG  Version;
    ULONG  Size;
    UCHAR  DeviceType;
    UCHAR  DeviceTypeModifier;
    BOOLEAN  RemovableMedia;
    BOOLEAN  CommandQueueing;
    ULONG  VendorIdOffset;
    ULONG  ProductIdOffset;
    ULONG  ProductRevisionOffset;
    ULONG  SerialNumberOffset;
    STORAGE_BUS_TYPE  BusType;
    ULONG  RawPropertiesLength;
    UCHAR  RawDeviceProperties[ 1 ];
} STORAGE_DEVICE_DESCRIPTOR, * PSTORAGE_DEVICE_DESCRIPTOR;

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
    PVOID InformationBuffer
);

NTSTATUS
NTAPI
NtSetInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _In_ PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength
);

NTSYSAPI
ULONG
NTAPI
KeCapturePersistentThreadState(
    __in PCONTEXT Context,
    __in_opt PKTHREAD Thread,
    __in ULONG BugCheckCode,
    __in ULONG_PTR BugCheckParameter1,
    __in ULONG_PTR BugCheckParameter2,
    __in ULONG_PTR BugCheckParameter3,
    __in ULONG_PTR BugCheckParameter4,
    __in PDUMP_HEADER DumpHeader
);

BOOLEAN NTAPI RtlDosPathNameToRelativeNtPathName_U(
    _In_       PCWSTR DosFileName,
    _Out_      PUNICODE_STRING NtFileName,
    _Out_opt_  PWSTR* FilePath,
    _Out_opt_  PRTL_RELATIVE_NAME RelativeName
);

typedef
_Function_class_( KNORMAL_ROUTINE )
_IRQL_requires_( PASSIVE_LEVEL )
_IRQL_requires_same_
VOID
NTAPI
KNORMAL_ROUTINE(
    _In_opt_ PVOID NormalContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
);
typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;

typedef
_Function_class_( KRUNDOWN_ROUTINE )
_IRQL_requires_( PASSIVE_LEVEL )
_IRQL_requires_same_
VOID
NTAPI
KRUNDOWN_ROUTINE(
    _In_ PRKAPC Apc
);
typedef KRUNDOWN_ROUTINE* PKRUNDOWN_ROUTINE;

typedef
_Function_class_( KKERNEL_ROUTINE )
_IRQL_requires_( APC_LEVEL )
_IRQL_requires_same_
VOID
NTAPI
KKERNEL_ROUTINE(
    _In_ PRKAPC Apc,
    _Inout_ _Deref_pre_maybenull_ PKNORMAL_ROUTINE* NormalRoutine,
    _Inout_ _Deref_pre_maybenull_ PVOID* NormalContext,
    _Inout_ _Deref_pre_maybenull_ PVOID* SystemArgument1,
    _Inout_ _Deref_pre_maybenull_ PVOID* SystemArgument2
);
typedef KKERNEL_ROUTINE* PKKERNEL_ROUTINE;

typedef enum _KAPC_ENVIRONMENT
{
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT, * PKAPC_ENVIRONMENT;

NTKERNELAPI
VOID
NTAPI
KeInitializeApc(
    _Out_ PRKAPC Apc,
    _In_ PRKTHREAD Thread,
    _In_ KAPC_ENVIRONMENT Environment,
    _In_ PKKERNEL_ROUTINE KernelRoutine,
    _In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
    _In_opt_ PKNORMAL_ROUTINE NormalRoutine,
    _In_ KPROCESSOR_MODE Mode,
    _In_opt_ PVOID NormalContext
);

NTKERNELAPI
BOOLEAN
NTAPI
KeInsertQueueApc(
    _Inout_ PRKAPC Apc,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2,
    _In_ KPRIORITY Increment
);

C_ASSERT( FIELD_OFFSET( DUMP_HEADER, Signature ) == 0 );
C_ASSERT( FIELD_OFFSET( DUMP_HEADER, ValidDump ) == 4 );
C_ASSERT( FIELD_OFFSET( DUMP_HEADER, MajorVersion ) == 8 );
C_ASSERT( FIELD_OFFSET( DUMP_HEADER, MinorVersion ) == 0xc );
C_ASSERT( FIELD_OFFSET( DUMP_HEADER, DirectoryTableBase ) == 0x10 );
C_ASSERT( FIELD_OFFSET( DUMP_HEADER, PfnDataBase ) == 0x18 );
C_ASSERT( FIELD_OFFSET( DUMP_HEADER, PsLoadedModuleList ) == 0x20 );
C_ASSERT( FIELD_OFFSET( DUMP_HEADER, PsActiveProcessHead ) == 0x28 );
C_ASSERT( FIELD_OFFSET( DUMP_HEADER, MachineImageType ) == 0x30 );
C_ASSERT( FIELD_OFFSET( DUMP_HEADER, NumberProcessors ) == 0x34 );
C_ASSERT( FIELD_OFFSET( DUMP_HEADER, BugCheckCode ) == 0x38 );
C_ASSERT( FIELD_OFFSET( DUMP_HEADER, BugCheckParameter1 ) == 0x40 );
C_ASSERT( FIELD_OFFSET( DUMP_HEADER, BugCheckParameter2 ) == 0x48 );
C_ASSERT( FIELD_OFFSET( DUMP_HEADER, BugCheckParameter3 ) == 0x50 );
C_ASSERT( FIELD_OFFSET( DUMP_HEADER, BugCheckParameter4 ) == 0x58 );
C_ASSERT( FIELD_OFFSET( DUMP_HEADER, KdDebuggerDataBlock ) == 0x80 );

#ifndef _WIN64
#define KDDEBUGGER_DATA_OFFSET 0x1068
#else
#define KDDEBUGGER_DATA_OFFSET 0x2080
#endif 

#ifndef _WIN64
#define DUMP_BLOCK_SIZE 0x20000
#else
#define DUMP_BLOCK_SIZE 0x40000
#endif 

#endif
