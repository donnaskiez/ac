#include "pool.h"

#include "callbacks.h"
#include "crypt.h"
#include "ia32.h"
#include "imports.h"
#include "lib/stdlib.h"

#include <intrin.h>

#define PML4_ENTRY_COUNT 512
#define PDPT_ENTRY_COUNT 512
#define PD_ENTRY_COUNT   512
#define PT_ENTRY_COUNT   512

#define LARGE_PAGE_2MB_ENTRIES 0x200
#define LARGE_PAGE_1GB_ENTRIES 0x40000

#define IS_VALID_PAGE(pt, idx) ((pt)[(index)].Present)
#define IS_LARGE_PAGE(pt)      ((pt).LargePage)

STATIC PVOID local_page_copy_buf = NULL;

/*
 * Using MmGetPhysicalMemoryRangesEx2(), we can get a block of structures that
 * describe the physical memory layout. With each physical page base we are
 * going to enumerate, we want to make sure it lies within an appropriate region
 * of physical memory, so this function is to check for exactly that.
 */
STATIC
BOOLEAN
PoolpIsAddressInPhysicalRange(
    _In_ UINT64 PhysicalAddress,
    _In_ PPHYSICAL_MEMORY_RANGE PhysicalMemoryRanges)
{
    ULONG index = 0;
    UINT64 start = 0;
    UINT64 end = 0;

    while (PhysicalMemoryRanges[index].NumberOfBytes.QuadPart) {
        start = PhysicalMemoryRanges[index].BaseAddress.QuadPart;
        end = start + PhysicalMemoryRanges[index].NumberOfBytes.QuadPart;

        if (PhysicalAddress >= start && PhysicalAddress <= end)
            return TRUE;

        index++;
    }

    return FALSE;
}

STATIC
BOOLEAN
PoolpScanLargePage(
    _In_ UINT64 PageBase,
    _In_ UINT32 PageSize,
    _In_ PAGE_CALLBACK Callback,
    _In_opt_ PVOID Context)
{
    UINT64 page = 0;
    BOOLEAN stop = FALSE;

    if (!PageBase || !ImpMmIsAddressValid(PageBase))
        return FALSE;

    for (UINT32 page_index = 0; page_index < PageSize; page_index++) {
        page = PageBase + (page_index * PAGE_SIZE);

        if (Callback(page, PAGE_SIZE, Context))
            return TRUE;
    }

    return FALSE;
}

STATIC
BOOLEAN
PoolpScanPageTable(
    _In_ PTE_64 Pte, _In_ PAGE_CALLBACK Callback, _In_opt_ PVOID Context)
{
    UINT64 page = 0;
    PHYSICAL_ADDRESS pa = {0};
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    MM_COPY_ADDRESS addr = {0};
    UINT32 bytes = 0;

    pa.QuadPart = Pte.PageFrameNumber << PAGE_4KB_SHIFT;
    page = MmGetVirtualForPhysical(pa);

    if (!page || !ImpMmIsAddressValid(page)) {
        addr.PhysicalAddress = pa;
        status = MmCopyMemory(
            local_page_copy_buf,
            addr,
            PAGE_SIZE,
            MM_COPY_MEMORY_PHYSICAL,
            &bytes);

        if (!NT_SUCCESS(status))
            return FALSE;

        DEBUG_VERBOSE(
            "valid mm page: %llx, pa: %llx, copied: %lx",
            local_page_copy_buf,
            pa.QuadPart,
            bytes);
        return Callback(local_page_copy_buf, PAGE_SIZE, Context);
    }

    return Callback(page, PAGE_SIZE, Context);
}

STATIC
BOOLEAN
PoolpScanPageDirectory(
    _In_ PDE_64 Pde, _In_ PAGE_CALLBACK Callback, _In_opt_ PVOID Context)
{
    PTE_64* pt = NULL;
    PDE_2MB_64 pdel = {0};
    PHYSICAL_ADDRESS pa = {0};

    if (IS_LARGE_PAGE(Pde)) {
        pdel.AsUInt = Pde.AsUInt;
        pa.QuadPart = pdel.PageFrameNumber << PAGE_2MB_SHIFT;

        return PoolpScanLargePage(
            ImpMmGetVirtualForPhysical(pa),
            LARGE_PAGE_2MB_ENTRIES,
            Callback,
            Context);
    }

    pa.QuadPart = Pde.PageFrameNumber << PAGE_4KB_SHIFT;
    pt = ImpMmGetVirtualForPhysical(pa);

    if (!pt || !ImpMmIsAddressValid(pt))
        return FALSE;

    for (UINT32 index = 0; index < PT_ENTRY_COUNT; index++) {
        if (!IS_VALID_PAGE(pt, index))
            continue;

        // DEBUG_VERBOSE(
        //     "------> pt va: %llx, pte: %llx, index: %lx",
        //     pt,
        //     pt[index],
        //     index);

        if (PoolpScanPageTable(pt[index], Callback, Context))
            return TRUE;
    }

    return FALSE;
}

STATIC
BOOLEAN
PoolpScanPageDirectoryPointerTable(
    _In_ PDPTE_64 Pdpte, _In_ PAGE_CALLBACK Callback, _In_opt_ PVOID Context)
{
    PDE_64* pd = NULL;
    PDPTE_1GB_64 pdptel = {0};
    PHYSICAL_ADDRESS pa = {0};

    if (IS_LARGE_PAGE(Pdpte)) {
        pdptel.AsUInt = Pdpte.AsUInt;
        pa.QuadPart = pdptel.PageFrameNumber << PAGE_1GB_SHIFT;

        return PoolpScanLargePage(
            ImpMmGetVirtualForPhysical(pa),
            LARGE_PAGE_1GB_ENTRIES,
            Callback,
            Context);
    }

    pa.QuadPart = Pdpte.PageFrameNumber << PAGE_4KB_SHIFT;
    pd = ImpMmGetVirtualForPhysical(pa);

    if (!pd || !ImpMmIsAddressValid(pd))
        return FALSE;

    for (UINT32 index = 0; index < PD_ENTRY_COUNT; index++) {
        if (!IS_VALID_PAGE(pd, index))
            continue;

        // DEBUG_VERBOSE(
        //     "----> pd va: %llx, pde: %llx, index: %lx",
        //     pd,
        //     pd[index],
        //     index);

        if (PoolpScanPageDirectory(pd[index], Callback, Context))
            return TRUE;
    }

    return FALSE;
}

STATIC
BOOLEAN
PoolpScanPageMapLevel4(
    _In_ PML4E_64 Pml4e, _In_ PAGE_CALLBACK Callback, _In_opt_ PVOID Context)
{
    BOOLEAN stop = FALSE;
    PDPTE_64* pdpt = NULL;
    PHYSICAL_ADDRESS pa = {0};

    pa.QuadPart = Pml4e.PageFrameNumber << PAGE_4KB_SHIFT;
    pdpt = ImpMmGetVirtualForPhysical(pa);

    if (!pdpt || !ImpMmIsAddressValid(pdpt))
        return FALSE;

    for (UINT32 index = 0; index < PDPT_ENTRY_COUNT; index++) {
        if (!IS_VALID_PAGE(pdpt, index))
            continue;

        // DEBUG_VERBOSE(
        //     "--> pdpt va: %llx, pdpte: %llx, index: %lx",
        //     pdpt,
        //     pdpt[index],
        //     index);

        if (PoolpScanPageDirectoryPointerTable(pdpt[index], Callback, Context))
            return TRUE;
    }

    return FALSE;
}

NTSTATUS
PoolScanSystemSpace(_In_ PAGE_CALLBACK Callback, _In_opt_ PVOID Context)
{
    NT_ASSERT(Callback != NULL);

    CR3 cr3 = {0};
    PML4E_64* pml4 = NULL;
    PHYSICAL_ADDRESS pa = {0};

    if (!Callback)
        return STATUS_INVALID_PARAMETER;

    cr3.AsUInt = __readcr3();
    pa.QuadPart = cr3.AddressOfPageDirectory << PAGE_4KB_SHIFT;
    pml4 = ImpMmGetVirtualForPhysical(pa);

    // DEBUG_VERBOSE("system cr3: %llx", cr3.AsUInt);

    if (!pml4 || !ImpMmIsAddressValid(pml4))
        return STATUS_UNSUCCESSFUL;

    for (UINT32 index = 490; index < PML4_ENTRY_COUNT; index++) {
        if (!IS_VALID_PAGE(pml4, index))
            continue;

        // DEBUG_VERBOSE(
        //     "pml4 va: %llx, pml4e: %llx, index: %lx",
        //     pml4,
        //     pml4[index],
        //     index);

        if (PoolpScanPageMapLevel4(pml4[index], Callback, Context))
            break;
    }

    return STATUS_SUCCESS;
}

/* Credits to Samuel Tulach c:
 * https://tulach.cc/detecting-manually-mapped-drivers/ */

// #36aae000 4d 5a 90
#define GADGET_BYTE_ONE   0x4D // 0xFF
#define GADGET_BYTE_TWO   0x5A // 0x25
#define GADGET_BYTE_THREE 0x90 // 0x25

STATIC
BOOLEAN
PoolScanForManualMappedDriverCallback(
    _In_ UINT64 Page, _In_ UINT32 PageSize, _In_opt_ PVOID Context)
{
    PCHAR byte = (PCHAR)Page;

    // DEBUG_VERBOSE("--------> page: %llx", Page);

    for (UINT32 index = 0; index < PageSize - 1; index++) {
        if (byte[index] == GADGET_BYTE_ONE &&
            byte[index + 1] == GADGET_BYTE_TWO &&
            byte[index + 2] == GADGET_BYTE_THREE) {
            DEBUG_VERBOSE("FOUND!");
        }
    }

    return FALSE;
}

NTSTATUS
PoolScanForManualMappedDrivers()
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DEBUG_VERBOSE("scanning for gadget");
    local_page_copy_buf =
        ImpExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, POOL_TAG_INTEGRITY);
    PoolScanSystemSpace(PoolScanForManualMappedDriverCallback, NULL);
    DEBUG_VERBOSE("fnished scanning");
    ImpExFreePoolWithTag(local_page_copy_buf, POOL_TAG_INTEGRITY);
}
