#pragma once
#include "module_tracker.skel.h"
#include <memory>

class module_handler {
public:
  // Default constructor
  module_handler() = default;

  // Destructor
  ~module_handler();

  int LoadAndAttachAll();
  void DetachAndUnloadAll();

  // Copy constructor
  module_handler(const module_handler &other) = delete;

  // Move constructor
  module_handler(module_handler &&other) noexcept = default;

  // Copy assignment operator
  module_handler &operator=(const module_handler &other) = delete;

  // Move assignment operator
  module_handler &operator=(module_handler &&other) noexcept = default;

protected:
  // Protected member functions

  // Protected member variables

private:
  std::unique_ptr<struct module_tracker, decltype(&module_tracker__destroy)>
      skel_obj{nullptr, module_tracker__destroy};
  // Private member functions

  // Private member variables
};
