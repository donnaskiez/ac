#pragma once

#include <Windows.h>

#include <array>
#include <functional>
#include <mutex>
#include <optional>
#include <queue>
#include <unordered_map>
#include <vector>

/*
 * array of handles which we pass to WaitForMultipleEvents
 *
 * needa do this rather then use the dedicated apc routien pointer in set timer
 * cos u cant just take a pointer to a member function for some reason lol like
 * tf
 *
 * map maps a handle to a callback object, this object contains various
 * information bust most important the callback routine. When the event is
 * signaled, it returns a handle, use that handle to index the map and run the
 * callback routine. This has to be done as the handles needs to be in a
 * contiguous array, so we can use an array of callback objects.
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

  std::optional<HANDLE> insert_callback(std::function<void()> routine,
                                        int due_time_seconds,
                                        int period_seconds);
  void remove_callback(HANDLE handle);
  void run_timer_thread();
};
} // namespace dispatcher