#pragma once

#include "kernel_interface/kernel_interface.h"

namespace helper {
void generate_rand_seed();
int generate_rand_int(int max);
void sleep_thread(int seconds);
kernel_interface::report_id get_kernel_report_type(void *buffer);
int get_report_id_from_buffer(void *buffer);
void print_kernel_report(void *buffer);
unsigned __int64 seconds_to_nanoseconds(int seconds);
unsigned __int32 seconds_to_milliseconds(int seconds);
} // namespace helper