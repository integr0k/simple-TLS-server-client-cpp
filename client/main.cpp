#include "connection.hpp"
#include <array>
#include <atomic>
#include <iostream>
#include <string>
#include <thread>
#include <cstring>

void handleServer(ClientConnection& conn, std::atomic<bool>& running){
    std::array<char, 1024> buffer{};
    int bytes;

    while(running && (bytes = conn.read(buffer.data(), buffer.size() - 1)) > 0){
        buffer[bytes] = '\0';
        std::cout << "\r[Server Reply] " << buffer.data() << std::endl;
        std::cout << "Client > " << std::flush;
        buffer.fill(0);
    }
}

int main(){
    try {
        TLSClientEngine engine;
        ClientConnection conn(engine, "192.168.1.132", 8443);

        const char* auth_token = "AUTH:my_secret_token_123";
        conn.write(auth_token, std::strlen(auth_token));

        std::atomic<bool> running{true};
        std::thread recv_thread(handleServer, std::ref(conn), std::ref(running));

        std::string msg;
        while(true){
            std::cout << "Client > ";
            std::getline(std::cin, msg);
            if (msg == "exit") {
                break;
            }
            conn.write(msg.c_str(), msg.length());
        }

        running = false;
        recv_thread.detach();

    } catch (const std::exception& e){
        std::cerr << "[Error] " << e.what() << std::endl;
        return 1;
    }
    return 0;
}