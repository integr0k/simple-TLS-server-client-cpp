#pragma once

#include <string>
#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <sys/socket.h>

class TLSClientEngine{
private:
    SSL_CTX* ctx = nullptr;

    TLSClientEngine(const TLSClientEngine&) = delete;
    TLSClientEngine& operator=(const TLSClientEngine&) = delete;

    void printOpenSSLError(const std::string& context_msg);

public:
    TLSClientEngine();
    ~TLSClientEngine();

    SSL* createSSLSession(int sock_fd);
    SSL_CTX* get_ctx() const {return ctx;}
};


class ClientConnection{
private:
    SSL* ssl = nullptr;
    int sock_fd = -1;
    bool handshake_done = false;

    ClientConnection(const ClientConnection&) = delete;
    ClientConnection& operator=(const ClientConnection&) = delete;

    void printOpenSSLError(const std::string& context_msg);

public:
    ClientConnection(TLSClientEngine& engine, const std::string& ip, int port);
    ~ClientConnection();

    SSL* get_ssl() const {return ssl;}
    int get_fd() const {return sock_fd;}
    bool is_connected() const {return handshake_done;}

    int write(const void* buf, int num);
    int read(void* buf, int num);
};