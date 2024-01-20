#include "helper.h"

#include <chrono>
#include <random>

void helper::generate_rand_seed() { srand(time(nullptr)); }

int helper::generate_rand_int(int max) { return rand() % max; }

void helper::sleep_thread(int seconds) {
  std::this_thread::sleep_for(std::chrono::seconds(seconds));
}
