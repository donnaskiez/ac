#include "timer.h"

#include "../common.h"
#include "../helper.h"

dispatcher::timer::timer() { LOG_INFO("constructor"); }

dispatcher::timer::~timer() {}

HANDLE dispatcher::timer::create_timer_object() {
  return CreateWaitableTimer(nullptr, false, nullptr);
}

bool dispatcher::timer::set_timer_object(HANDLE handle, LARGE_INTEGER *due_time,
                                         unsigned long period) {
  return SetWaitableTimer(handle, due_time, period, nullptr, nullptr, false) > 0
             ? true
             : false;
}

bool dispatcher::timer::insert_callback(std::function<void()> routine,
                                        int due_time_seconds,
                                        int period_seconds) {
  std::lock_guard<std::mutex> lock(this->lock);
  std::optional<int> index = this->find_free_handle_index();
  if (!index.has_value()) {
    LOG_ERROR("No free event handles available. Unable to create timer.");
    return false;
  }

  HANDLE handle = create_timer_object();
  if (!handle) {
    LOG_ERROR("CreateWaitableTimer failed with status %x", GetLastError());
    set_callback_inactive(index.value());
    return false;
  }

  callback *cb = &this->callbacks[index.value()];
  cb->callback_routine = routine;
  cb->due_time.QuadPart = helper::seconds_to_nanoseconds(due_time_seconds);
  cb->period = helper::seconds_to_milliseconds(period_seconds);

  this->handles[index.value()] = handle;
  if (!set_timer_object(handle, &cb->due_time, cb->period)) {
    LOG_ERROR("SetWaitableTimer failed with status %x", GetLastError());
    close_handle_entry(handle);
    set_callback_inactive(index.value());
  }

  this->active_callbacks++;
  return true;
}

/* assumes lock is held by caller */
std::optional<int> dispatcher::timer::find_free_handle_index() {
  for (int index = 0; index < MAXIMUM_WAIT_OBJECTS; index++) {
    if (callbacks[index].in_use == false) {
      callbacks[index].in_use = true;
      return index;
    }
  }
  return {};
}

void dispatcher::timer::close_handle_entry(HANDLE handle) {
  for (auto &entry : handles) {
    if (entry == handle) {
      entry = INVALID_HANDLE_VALUE;
      CloseHandle(entry);
    }
  }
}

void dispatcher::timer::set_callback_inactive(int index) {
  this->callbacks[index].in_use = false;
}

void dispatcher::timer::dispatch_callback_for_index(unsigned long index) {
  this->callbacks[index].callback_routine();
}

void dispatcher::timer::run_timer_thread() {
  while (true) {
    unsigned long index = WaitForMultipleObjects(
        this->active_callbacks, reinterpret_cast<HANDLE *>(&handles), false,
        INFINITE);
    this->dispatch_callback_for_index(index);
  }
}