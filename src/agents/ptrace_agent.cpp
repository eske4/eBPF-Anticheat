#include "ptrace_agent.h"
#include <iostream>

void ptrace_agent::print_ptrace() {
    auto data = this->handler.GetData();
    std::cout << "ptrace called by " << data.caller_name
            << " (pid " << data.caller
            << "), attaching to proc " << data.target
            << std::endl;
}

ptrace_agent::ptrace_agent(/* args */)
{
    std::cout << "agent constructor" << std::endl;
    this->handler.LoadAndAttachAll(808);
}

ptrace_agent::~ptrace_agent()
{
}
