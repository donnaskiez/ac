#pragma once

#include "common.h"

#include <Windows.h>

namespace module {
void run(HINSTANCE hinstDLL);
void terminate();
} // namespace module