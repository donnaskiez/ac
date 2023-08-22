#ifndef INTEGRITY_H
#define INTEGRITY_H

#include <ntifs.h>

#define POOL_TAG_INTEGRITY 'intg'

NTSTATUS CopyDriverExecutableRegions(
	_In_ PIRP Irp
);

#endif