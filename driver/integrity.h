#ifndef INTEGRITY_H
#define INTEGRITY_H

#include <ntifs.h>

#define POOL_TAG_INTEGRITY 'intg'

NTSTATUS CopyDriverExecutableRegions(
	_In_ PIRP Irp
);

NTSTATUS GetDriverImageSize(
	_In_ PIRP Irp
);

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

#endif

