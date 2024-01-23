#pragma once

#include <Windows.h>

#include <array>
#include <functional>
#include <mutex>
#include <optional>
#include <vector>
#include <unordered_map>
#include <queue>

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

    callback(std::function<void()> routine, int due_time_seconds,
             int period_seconds);
  };

  std::optional<HANDLE *> find_free_handle();
  void close_handle_entry(HANDLE handle);
  void dispatch_callback_for_index(unsigned long index);
  HANDLE create_timer_object();
  bool set_timer_object(HANDLE handle, LARGE_INTEGER *due_time,
                        unsigned long period);
  void query_removal_queue();
  void insert_handle(HANDLE handle);

public:
  std::mutex lock;
  std::array<HANDLE, MAXIMUM_WAIT_OBJECTS> handles;
  std::unordered_map<HANDLE, callback> callbacks;
  std::queue<HANDLE> callbacks_to_remove;

  int active_callbacks;

  timer();
  ~timer();

  std::optional<HANDLE> insert_callback(std::function<void()> routine, int due_time_seconds,
                       int period_seconds);
  void remove_callback(HANDLE handle);
  void run_timer_thread();
};
} // namespace dispatcher