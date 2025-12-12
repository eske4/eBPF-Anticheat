#include "ptrace_agent.h"
#include <cstdio>

constexpr auto on_event = [](ptrace_event e)
{ 
    printf("ptrace called by %s (PID %i), attaching to proc %i\n",
        e.caller_name,
        e.caller,
        e.target);
};

ptrace_agent::ptrace_agent(pid_t protected_pid)
    : handler(on_event)
{
    handler.LoadAndAttachAll(protected_pid);
}

ptrace_agent::~ptrace_agent()
{
}

