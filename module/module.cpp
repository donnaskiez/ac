#include "module.h"

#include <Windows.h>

#include "client/message_queue.h"
#include "dispatcher/dispatcher.h"

#include "crypt/crypt.h"
#include <Psapi.h>

bool module::get_module_information(module_information *out) {
  BOOL ret = FALSE;
  HMODULE module = {0};
  MODULEINFO info = {0};

  ret = GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)get_module_information, &module);

  if (!ret)
    return false;

  ret = GetModuleInformation(GetCurrentProcess(), module, (LPMODULEINFO)&info,
                             sizeof(info));

  if (!ret)
    return false;

  if (!GetModuleFileNameA(module, out->path, MAX_PATH))
    return false;

  out->base_address = info.lpBaseOfDll;
  out->size = info.SizeOfImage;

  LOG_INFO("base: %llx", out->base_address);
  LOG_INFO("size: %lx", out->size);
  LOG_INFO("path: %s", out->path);

  return true;
}

void module::run(HINSTANCE hinstDLL) {
  AllocConsole();
  FILE *file = NULL;
  freopen_s(&file, "CONOUT$", "w", stdout);
  freopen_s(&file, "CONIN$", "r", stdin);

  LPTSTR pipe_name = (LPTSTR)L"\\\\.\\pipe\\DonnaACPipe";
  LPCWSTR driver_name = L"\\\\.\\DonnaAC";

  module::module_information info = {0};
  if (!module::get_module_information(&info)) {
    LOG_ERROR("get_module_information: %x", GetLastError());
    fclose(stdout);
    fclose(stdin);
    FreeConsole();
    FreeLibraryAndExitThread(hinstDLL, 0);
    return;
  }

  client::message_queue queue(pipe_name);
  dispatcher::dispatcher dispatch(driver_name, queue, &info);
  dispatch.run();

  fclose(stdout);
  fclose(stdin);
  FreeConsole();

  FreeLibraryAndExitThread(hinstDLL, 0);
}

void module::terminate() {}