#ifndef PIPE_H
#define PIPE_H

#include <Windows.h>

#define MESSAGE_TYPE_CLIENT_REPORT  1
#define MESSAGE_TYPE_CLIENT_SEND    2
#define MESSAGE_TYPE_CLIENT_REQUEST 3

#define MOTHERBOARD_SERIAL_CODE_LENGTH    64
#define DEVICE_DRIVE_0_SERIAL_CODE_LENGTH 64

namespace global {
class Pipe
{
        HANDLE pipe_handle;
        LPTSTR pipe_name;

    public:
        Pipe(LPTSTR PipeName);

        void WriteToPipe(PVOID Buffer, SIZE_T Size);
        void ReadPipe(PVOID Buffer, SIZE_T Size);
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

struct PIPE_PACKET_HEADER
{
        INT    message_type;
        UINT64 steam64_id;
};

struct PIPE_PACKET_REQUEST_EXTENSION_HEADER
{
        INT request_id;
};

struct CLIENT_SEND_PACKET_HEADER
{
        INT  request_id;
        LONG packet_size;
};

}
}

#endif