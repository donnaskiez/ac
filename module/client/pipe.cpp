#include "pipe.h"

#include "../common.h"

#include <intrin.h>

client::pipe::pipe(LPTSTR PipeName) {
  this->pipe_name = PipeName;
  this->pipe_handle =
      CreateFile(this->pipe_name, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                 OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);

  if (this->pipe_handle == INVALID_HANDLE_VALUE) {
    LOG_ERROR("CreateFile failed with status 0x%x", GetLastError());
    return;
  }
}

void client::pipe::write_pipe(PVOID Buffer, SIZE_T Size) {
  DWORD bytes_written = 0;

  WriteFile(this->pipe_handle, Buffer, Size, &bytes_written, NULL);

  if (bytes_written == 0) {
    LOG_ERROR("WriteFile failed with status code 0x%x", GetLastError());
    return;
  }
}

void client::pipe::read_pipe(PVOID Buffer, SIZE_T Size) {
  BOOL status = FALSE;
  DWORD bytes_read = 0;

  status = ReadFile(this->pipe_handle, Buffer, Size, &bytes_read, NULL);

  if (status == NULL) {
    LOG_ERROR("ReadFile failed with status code 0x%x", GetLastError());
    return;
  }
}
