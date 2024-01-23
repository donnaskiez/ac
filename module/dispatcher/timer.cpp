#include "timer.h"

#include "../common.h"
#include "../helper.h"

dispatcher::timer::timer() {
  this->active_callbacks = 0;
  for (auto &entry : handles) {
    entry = INVALID_HANDLE_VALUE;
  }
}

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

dispatcher::timer::callback::callback(std::function<void()> routine,
                                      int due_time_seconds,
                                      int period_seconds) {
  this->callback_routine = routine;
  this->due_time.QuadPart = helper::seconds_to_nanoseconds(due_time_seconds);
  this->period = helper::seconds_to_milliseconds(period_seconds);
}

std::optional<HANDLE>
dispatcher::timer::insert_callback(std::function<void()> routine,
                                   int due_time_seconds, int period_seconds) {
  std::lock_guard<std::mutex> lock(this->lock);
  std::optional<HANDLE *> handle = this->find_free_handle();
  if (!handle.has_value()) {
    LOG_ERROR("No free event handles available. Unable to create timer.");
    return {};
  }

  *handle.value() = create_timer_object();
  if (*handle.value() == NULL) {
    LOG_ERROR("CreateWaitableTimer failed with status %x", GetLastError());
    return {};
  }

  callback cb(routine, due_time_seconds, period_seconds);
  if (!set_timer_object(*handle.value(), &cb.due_time, cb.period)) {
    LOG_ERROR("SetWaitableTimer failed with status %x", GetLastError());
  }

  std::pair<HANDLE, callback> entry(*handle.value(), cb);
  this->callbacks.insert(entry);
  this->insert_handle(*handle.value());
  this->active_callbacks++;
  return *handle.value();
}

/* assumes lock is held by caller */
std::optional<HANDLE *> dispatcher::timer::find_free_handle() {
  for (int index = 0; index < MAXIMUM_WAIT_OBJECTS; index++) {
    if (handles[index] == INVALID_HANDLE_VALUE)
      return &handles[index];
  }
  return {};
}

/* assumes lock is held */
void dispatcher::timer::insert_handle(HANDLE handle) {
  for (HANDLE entry : this->handles) {
    if (entry == INVALID_HANDLE_VALUE) {
      entry = handle;
      return;
    }
  }
}

/* assumes lock is held */
void dispatcher::timer::close_handle_entry(HANDLE handle) {
  this->callbacks.erase(handle);
  for (int entry = 0; entry < MAXIMUM_WAIT_OBJECTS; entry++) {
    if (this->handles[entry] == handle) {
      CloseHandle(handle);
      this->handles[entry] = INVALID_HANDLE_VALUE;
      /* ordering doesnt matter, aslong as the valid handles are at the front of
       * the array and are contiguous */
      std::sort(this->handles.begin(), this->handles.end());
      this->active_callbacks--;
      return;
    }
  }
}

void dispatcher::timer::dispatch_callback_for_index(unsigned long index) {
  std::unordered_map<HANDLE, callback>::const_iterator it =
      this->callbacks.find(handles[index]);
  if (it == this->callbacks.end())
    return;
  it->second.callback_routine();
}

/* assumes lock is held */
void dispatcher::timer::query_removal_queue() {
  if (callbacks_to_remove.empty())
    return;
  while (!callbacks_to_remove.empty()) {
    HANDLE entry = callbacks_to_remove.front();
    this->close_handle_entry(entry);
    this->callbacks_to_remove.pop();
  }
}

void dispatcher::timer::run_timer_thread() {
  while (true) {
    unsigned long index = WaitForMultipleObjects(
        this->active_callbacks, reinterpret_cast<HANDLE *>(&handles), false,
        INFINITE);
    {
      std::lock_guard<std::mutex> lock(this->lock);
      this->dispatch_callback_for_index(index);
      this->query_removal_queue();
    }
  }
}

/*
 * If we remove a callback whilst the main loop is sleeping, it means the
 * information passed to KeWaitForMultipleObjects will be wrong, hence we need
 * to wait until our thread is run by the scheduler, perform the operation for
 * the alerted handle and THEN remove any entries from the removal queue. Then
 * once we recall KeWaitForMultipleObjects the new handle array will be valid.
 */
void dispatcher::timer::remove_callback(HANDLE handle) {
  std::lock_guard<std::mutex> lock(this->lock);
  this->callbacks_to_remove.push(handle);
}