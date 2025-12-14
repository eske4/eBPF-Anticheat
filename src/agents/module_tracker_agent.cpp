#include "module_tracker_agent.h"
#include "data_types.h"

module_tracker_agent::module_tracker_agent()
    : handler([this](module_event e) { on_event_cb(e); }) {
  handler.LoadAndAttachAll();
}

module_tracker_agent::~module_tracker_agent() { handler.DetachAndUnloadAll(); }

std::optional<module_event> module_tracker_agent::get_next_event() {
  std::lock_guard<std::mutex> lock(queue_mutex);
  if (event_queue.empty())
    return std::nullopt;
  module_event e = event_queue.front();
  event_queue.pop();
  return e;
}

void module_tracker_agent::on_event_cb(module_event e) {
  std::lock_guard<std::mutex> lock(queue_mutex);
  event_queue.push(e);
}
