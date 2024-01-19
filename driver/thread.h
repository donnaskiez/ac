#ifndef THREAD_H
#define THREAD_H

#include <ntifs.h>

#include "common.h"
#include "callbacks.h"

BOOLEAN
ValidateThreadsPspCidTableEntry(_In_ PETHREAD Thread);

VOID
DetectThreadsAttachedToProtectedProcess();

#endif