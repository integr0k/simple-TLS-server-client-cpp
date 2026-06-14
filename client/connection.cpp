#include "connection.hpp"
#include <iostream>
#include <openssl/err.h>
#include <unistd.h>
#include <cstring>
#include <cerrno>
#include <stdexcept>

void TLSClientEngine::printOpenSSLError(const std::string& context_msg){
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    std::cerr << "[TLS Error] " << context_msg << ": " << err_buf << std::endl;
}

TLSClientEngine::TLSClientEngine(){
    uint64_t flags = OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS;

    if(OPENSSL_init_ssl(flags, nullptr) != 1){
        throw std::runtime_error("[TLS Error] OpenSSL initialization failed.");
    }

    auto method = TLS_client_method();
    ctx = SSL_CTX_new(method);

    if(method == nullptr || ctx == nullptr){
        printOpenSSLError("Context creation failed");
        throw std::runtime_error("[TLS Error] Context creation failed.");
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

    std::cout << "[TLS] Client engine initialized successfully." << std::endl;
}

TLSClientEngine::~TLSClientEngine(){
    if(ctx != nullptr){
        SSL_CTX_free(ctx);
        std::cout << "[TLS] Client engine context cleared safely (RAII)." << std::endl;
    }
}

SSL* TLSClientEngine::createSSLSession(int sock_fd){
    if(ctx == nullptr) return nullptr;

    SSL* ssl = SSL_new(ctx);
    if(ssl != nullptr){
        SSL_set_fd(ssl, sock_fd);
    }
    return ssl;
}

void ClientConnection::printOpenSSLError(const std::string& context_msg){
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    std::cerr << "[TLS Error] " << context_msg << ": " << err_buf << std::endl;
}

ClientConnection::ClientConnection(TLSClientEngine& engine, const std::string& ip, int port){
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(sock_fd < 0){
        throw std::runtime_error("[Socket Error] Failed to create client socket.");
    }
    std::cout << "[Socket] Client socket created successfully." << std::endl;

    struct sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if(inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr) != 1){
        close(sock_fd);
        sock_fd = -1;
        throw std::runtime_error("[Socket Error] Invalid IP address: " + ip);
    }

    if(connect(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
        std::string err_msg = "[Socket Error] Connection rejected: " + std::string(strerror(errno))
                            + " (Code: " + std::to_string(errno) + ")";
        close(sock_fd);
        sock_fd = -1;
        throw std::runtime_error(err_msg);
    }
    std::cout << "[Socket] Connected to " << ip << ":" << port << std::endl;

    ssl = engine.createSSLSession(sock_fd);
    if(ssl == nullptr){
        printOpenSSLError("Failed to create SSL session");
        close(sock_fd);
        sock_fd = -1;
        throw std::runtime_error("[TLS Error] Failed to create SSL session.");
    }

    if(SSL_connect(ssl) != 1){
        printOpenSSLError("TLS handshake failed");
        SSL_free(ssl);
        ssl = nullptr;
        close(sock_fd);
        sock_fd = -1;
        throw std::runtime_error("[TLS Error] TLS handshake failed.");
    }

    handshake_done = true;
    std::cout << "[TLS] Handshake completed successfully." << std::endl;
}

ClientConnection::~ClientConnection(){
    if(ssl != nullptr){
        SSL_shutdown(ssl);
        SSL_free(ssl);
        std::cout << "[RAII] SSL session freed safely." << std::endl;
    }
    if(sock_fd >= 0){
        close(sock_fd);
        std::cout << "[RAII] Client socket closed safely." << std::endl;
    }
}

int ClientConnection::write(const void* buf, int num){
    if(!handshake_done) return -1;
    return SSL_write(ssl, buf, num);
}

int ClientConnection::read(void* buf, int num){
    if(!handshake_done) return -1;
    return SSL_read(ssl, buf, num);
}