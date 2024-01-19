#pragma once

#include <Windows.h>

#define MESSAGE_TYPE_CLIENT_REPORT  1
#define MESSAGE_TYPE_CLIENT_SEND    2
#define MESSAGE_TYPE_CLIENT_REQUEST 3

#define MOTHERBOARD_SERIAL_CODE_LENGTH    64
#define DEVICE_DRIVE_0_SERIAL_CODE_LENGTH 64

namespace client {
class pipe
{
        HANDLE pipe_handle;
        LPTSTR pipe_name;

    public:
        pipe(LPTSTR PipeName);

        void write_pipe(PVOID Buffer, SIZE_T Size);
        void read_pipe(PVOID Buffer, SIZE_T Size);
};

namespace headers {
typedef enum _ENVIRONMENT_TYPE
{
        NativeWindows = 0,
        Vmware,
        VirtualBox

} ENVIRONMENT_TYPE;

typedef enum _PROCESSOR_TYPE
{
        Unknown = 0,
        GenuineIntel,
        AuthenticAmd

} PROCESSOR_TYPE;

#define VENDOR_STRING_MAX_LENGTH 256
struct SYSTEM_INFORMATION
{
        CHAR               motherboard_serial[MOTHERBOARD_SERIAL_CODE_LENGTH];
        CHAR               drive_0_serial[DEVICE_DRIVE_0_SERIAL_CODE_LENGTH];
        CHAR               vendor[VENDOR_STRING_MAX_LENGTH];
        BOOLEAN            virtualised_environment;
        ENVIRONMENT_TYPE   environment;
        PROCESSOR_TYPE     processor;
        RTL_OSVERSIONINFOW os_information;
};

}
}