#ifndef POOL_H
#define POOL_H

#include <ntifs.h>

#define POOL_DUMP_BLOCK_TAG 'dump'
#define POOL_DEBUGGER_DATA_TAG 'data'

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

VOID ScanNonPagedPoolForProcessTags();

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

/*
 * Generic macros that allow you to quickly determine whether
 *  or not a page table entry is present or may forward to a
 *  large page of data, rather than another page table (applies
 *  only to PDPTEs and PDEs)
 */
#define IS_LARGE_PAGE(x)    ( (BOOLEAN)((x >> 7) & 1) )
#define IS_PAGE_PRESENT(x)  ( (BOOLEAN)(x & 1) )

#define PAGE_1GB_SHIFT      30
#define PAGE_1GB_OFFSET(x)  ( x & (~(MAXUINT64 << PAGE_1GB_SHIFT)) )

#define PAGE_2MB_SHIFT      21
#define PAGE_2MB_OFFSET(x)  ( x & (~(MAXUINT64 << PAGE_2MB_SHIFT)) )

#define PAGE_4KB_SHIFT      12
#define PAGE_4KB_OFFSET(x)  ( x & (~(MAXUINT64 << PAGE_4KB_SHIFT)) )

#endif