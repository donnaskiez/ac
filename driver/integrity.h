#ifndef INTEGRITY_H
#define INTEGRITY_H

#include <ntifs.h>
#include "common.h"

NTSTATUS CopyDriverExecutableRegions(
	_In_ PIRP Irp
);

NTSTATUS GetDriverImageSize(
	_In_ PIRP Irp
);

NTSTATUS VerifyInMemoryImageVsDiskImage(
    //_In_ PIRP Irp
);

NTSTATUS RetrieveInMemoryModuleExecutableSections(
    _In_ PIRP Irp
);

#endif
