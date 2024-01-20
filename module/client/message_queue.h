#ifndef REPORT_H
#define REPORT_H

#include <Windows.h>

#include "../dispatcher/threadpool.h"

#include "../common.h"

#include "pipe.h"

#define REPORT_BUFFER_SIZE 8192
#define SEND_BUFFER_SIZE 8192

#define MAX_SIGNATURE_SIZE 256

#define MESSAGE_TYPE_CLIENT_REPORT 1
#define MESSAGE_TYPE_CLIENT_SEND 2
#define MESSAGE_TYPE_CLIENT_REQUEST 3

namespace client {

class message_queue {
  struct MESSAGE_PACKET_HEADER {
    int message_type;
    int request_id;
    unsigned __int64 steam64_id;
  };

  std::unique_ptr<client::pipe> pipe_interface;
  std::mutex lock;

  byte report_buffer[REPORT_BUFFER_SIZE];

public:
  message_queue(LPTSTR PipeName);
  void enqueue_message(void *Buffer, size_t Size);
  void dequeue_message(void *Buffer, size_t Size);
};

} // namespace client

#endif
