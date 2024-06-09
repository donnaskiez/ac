#pragma once

#include "common.h"

#include <Windows.h>

namespace module {
void run(HINSTANCE hinstDLL);
void terminate();

struct module_information {
  void *base_address;
  uint32_t size;
  char path[MAX_PATH];
};

bool get_module_information(module_information *info);
} // namespace module