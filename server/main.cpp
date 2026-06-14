#include <iostream>
#include "server.hpp"
#include <csignal>

int main(){
    std::signal(SIGPIPE, SIG_IGN);
    startServer(8443, "server.crt", "server.key");
    return 0;
}