#pragma once
#include "mem_access_handler.h"
#include "mem_data.h"
#include <mutex>
#include <queue>

class mem_access_agent {
private:
  mem_access_handler handler;
  pid_t protected_pid;

  void on_event_cb(const mem_event &e);

  std::queue<mem_event> event_queue;
  std::mutex queue_mutex;

public:
  mem_access_agent(pid_t protected_pid);
  ~mem_access_agent();

  mem_access_agent(const mem_access_agent &) = delete;
  mem_access_agent &operator=(const mem_access_agent &) = delete;
  mem_access_agent(const mem_access_agent &&) = delete;
  mem_access_agent &operator=(const mem_access_agent &&) = delete;

  void set_protected_pid(pid_t protected_pid);
  int get_pid_id();
  std::optional<mem_event> get_next_event();
  void printEventData(const mem_event &e);
  void writeEventDataToCSV(const mem_event &e);

  void set_block_access(bool block);
};
