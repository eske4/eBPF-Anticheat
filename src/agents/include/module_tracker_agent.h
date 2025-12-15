#pragma once
#include "module_tracker_handler.h"
#include <mutex>
#include <optional>
#include <queue>

class module_tracker_agent {
private:
  module_tracker_agent(const module_tracker_agent &) = delete;
  module_tracker_agent &operator=(const module_tracker_agent &) = delete;
  module_tracker_agent(module_tracker_agent &&) = delete;
  module_tracker_agent &operator=(module_tracker_agent &&) = delete;

  void on_event_cb(const module_event &e);

  module_tracker_handler handler;
  std::queue<module_event> event_queue;
  std::mutex queue_mutex;

public:
  module_tracker_agent();
  ~module_tracker_agent();
  std::optional<module_event> get_next_event();
  void printEventData(const module_event &e);
};
