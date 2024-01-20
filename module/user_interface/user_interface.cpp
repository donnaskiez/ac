#include "user_interface.h"

user_interface::user_interface::user_interface(client::message_queue &queue)
    : message_queue(queue) {
  LOG_INFO("Initialise user_interface.");
}