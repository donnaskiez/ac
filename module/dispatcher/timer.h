#pragma once

#include <Windows.h>

#include <array>
#include <functional>
#include <mutex>
#include <optional>
#include <vector>

/*
 * array of handles which we pass to WaitForMultipleEvents
 *
 * needa do this rather then use the dedicated apc routien pointer in set timer
 * cos u cant just take a pointer to a member function for some reason lol like
 * tf
 *
 * this returns an index into the array
 *
 * setup a vector containing the job routine for the associated handle, then
 * call that job.
 *
 * If we activate another handle in the handles array, the next time the current
 * event is signalled and we are invoked, only then should we insert new
 * requests. This means we should implement some queue where new timer objects
 * are inserted into the queue, then when the current even is invoked, we can
 * recall WaitForMultipleObjects with the updated array count.
 */
namespace dispatcher {

constexpr int HANDLE_AVAILABLE = 0;
constexpr int HANDLE_NOT_AVAILABLE = 1;

class timer {

  struct callback {
    bool in_use;
    std::function<void()> callback_routine;
    LARGE_INTEGER due_time;
    unsigned long period;
  };

  std::optional<int> find_free_handle_index();
  void close_handle_entry(HANDLE handle);
  void dispatch_callback_for_index(unsigned long index);
  HANDLE create_timer_object();
  bool set_timer_object(HANDLE handle, LARGE_INTEGER *due_time,
                        unsigned long period);
  void set_callback_inactive(int index);

public:
  std::mutex lock;
  std::array<HANDLE, MAXIMUM_WAIT_OBJECTS> handles;
  std::array<callback, MAXIMUM_WAIT_OBJECTS> callbacks;

  int active_callbacks;

  timer();
  ~timer();

  bool insert_callback(std::function<void()> routine, int due_time_seconds,
                       int period_seconds);
  void run_timer_thread();
};
} // namespace dispatcher