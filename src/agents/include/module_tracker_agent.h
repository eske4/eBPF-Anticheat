#pragma once
#include "module_handler.h"
#include <queue>

class module_tracker_agent {
private:
  void on_event_cb(module_event &e);

  module_handler handler;
  std::queue<module_event> event_queue; // thread-safe queue
  std::mutex queue_mutex;

public:
  module_tracker_agent();
  ~module_tracker_agent();
  std::optional<module_event> get_next_event();
  void printEventData(const module_event &e);
};
