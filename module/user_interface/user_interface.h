#pragma once

#include "../common.h"

#include "../client/message_queue.h"

namespace user_interface {
class user_interface {
  client::message_queue &message_queue;

public:
  user_interface(client::message_queue &queue);
};
} // namespace user_interface