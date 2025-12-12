#pragma once
#include "ptrace_handler.h"

class ptrace_agent
{
private:
    ptrace_handler handler;
public:
    ptrace_agent(pid_t protected_pid);
    ~ptrace_agent();
};

