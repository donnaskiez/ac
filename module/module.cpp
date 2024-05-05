#include "module.h"

#include <Windows.h>

#include "client/message_queue.h"
#include "dispatcher/dispatcher.h"

void module::run(HINSTANCE hinstDLL) {
  AllocConsole();
  FILE *file;
  freopen_s(&file, "CONOUT$", "w", stdout);
  freopen_s(&file, "CONIN$", "r", stdin);

  LPTSTR pipe_name = (LPTSTR)L"\\\\.\\pipe\\DonnaACPipe";
  LPCWSTR driver_name = L"\\\\.\\DonnaAC";

  client::message_queue queue(pipe_name);
  dispatcher::dispatcher dispatch(driver_name, queue);
  dispatch.run();

  fclose(stdout);
  fclose(stdin);
  FreeConsole();

  FreeLibraryAndExitThread(hinstDLL, 0);
}

void module::terminate() {}