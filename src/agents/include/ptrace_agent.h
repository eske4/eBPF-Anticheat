#pragma once
#include "ptrace_handler.h"

class ptrace_agent
{
private:
    struct ptrace_handler handler;
public:
    ptrace_agent(/* args */);
    ~ptrace_agent();
    void print_ptrace();
};

