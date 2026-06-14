#include <atomic>
#include <array>
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <thread> 
#include <cstring> 
#include <chrono>
#include <mutex> 
#include <ctime>
#include <sqlite3.h>
#include <string_view>
#include <vector>
#include <signal.h>

std::atomic<bool> server_running{true};

void signal_handler(int signum) {
    std::cout << "\n[System] Shutdown signal received. Stopping server gracefully..." << std::endl;
    server_running = false;
}

class AuthDatabase {
private:
    sqlite3* db = nullptr;
    sqlite3_stmt* stmt = nullptr;
    std::mutex db_mutex;

    AuthDatabase(const AuthDatabase&) = delete;
    AuthDatabase& operator=(const AuthDatabase&) = delete;

public:
    AuthDatabase(const std::string& db_path){
        if(sqlite3_open(db_path.c_str(), &db) != SQLITE_OK){
            throw std::runtime_error("[DB Error] Database file could not be opened: " + db_path);
            if (db) {
                sqlite3_close(db);
                db = nullptr;
            }
            return;     

        } else {
            std::cout << "[DB] Database connection established and kept alive." << std::endl;

            const char* sql = "SELECT 1 FROM users WHERE token = ? LIMIT 1;";

            if(sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK){
                if(db) sqlite3_close(db);
                throw std::runtime_error("[DB Error] Failed to prepare SQL statement.");
                if(stmt){
                    sqlite3_finalize(stmt);
                    stmt = nullptr;
                }
            }  
            std::cout << "[DB] Database connection established and kept alive." << std::endl;
        } 
    }

    ~AuthDatabase(){
        if(stmt != nullptr){
            sqlite3_finalize(stmt);
            std::cout << "[DB] Prepared statement finalized." << std::endl;
        }

        if(db != nullptr){
            sqlite3_close(db);
            std::cout << "[DB] Database connection closed safely." << std::endl;
        }
    }

    bool verify_token(std::string_view token){
        std::lock_guard<std::mutex> lock(db_mutex);

        if (!stmt) {
            std::cerr << "[DB Error] Cannot verify token: statement is not prepared." << std::endl;
            return false;
        }

        bool is_valid = false;

        if(sqlite3_bind_text(stmt, 1, token.data(), token.length(), SQLITE_TRANSIENT) != SQLITE_OK){
            std::cout << "[DB Error] Failed to bind text." << std::endl;
            sqlite3_reset(stmt);
            return false;
        }

        int rc = sqlite3_step(stmt);
        if(rc == SQLITE_ROW){
            is_valid = true;
        } else if (rc != SQLITE_DONE) {
            std::cerr << "[DB Error] Step execution failed: " << sqlite3_errmsg(db) << std::endl;
        } else {
            std::cout << "[DB] Unknown token extension request." << std::endl;
        }

        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);

        return is_valid;
    }
};


class TLSEngine {
private:
    SSL_CTX* ctx = nullptr;

    TLSEngine(const TLSEngine&) = delete;
    TLSEngine& operator=(const TLSEngine&) = delete;

    void printOpenSSLError(const std::string& context_msg){
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        std::cerr << "[TLS Error] " << context_msg << ": " << err_buf << std::endl;
    }

public:
    TLSEngine(int port, const std::string& cert_file, const std::string& key_file){
        uint64_t flags = OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS;

        if (OPENSSL_init_ssl(flags, nullptr) != 1){
            throw std::runtime_error("[TLS Error] OpenSSL initialization failed.");
        }

        auto ssl_server_method = TLS_server_method();
        ctx = SSL_CTX_new(ssl_server_method);

        if (ssl_server_method == nullptr || ctx == nullptr){
            printOpenSSLError("Context creation failed");
            throw std::runtime_error("[TLS Error] Context creation failed.");
        }

        if (SSL_CTX_use_certificate_file(ctx, cert_file.c_str(), SSL_FILETYPE_PEM) != 1){
            printOpenSSLError("Failed to load certificate file");
            throw std::runtime_error("[TLS Error] Failed to load certificate.");
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, key_file.c_str(), SSL_FILETYPE_PEM) != 1){
            printOpenSSLError("Failed to load private key file");
            throw std::runtime_error("[TLS Error] Failed to load private key.");
        }

        if (SSL_CTX_check_private_key(ctx) != 1){
            printOpenSSLError("Private key does not match the certificate");
            throw std::runtime_error("[TLS Error] Verification failed.");
        }
        std::cout << "[TLS] Engine initialized successfully. Certificates verified." << std::endl;
    }

    ~TLSEngine(){
        if(ctx != nullptr){
            std::cout << "[TLS] Engine context cleared safely (RAII)." << std::endl;
            SSL_CTX_free(ctx);
        }
    }

    SSL* createSSLSession(int client_fd){
        if (ctx == nullptr) return nullptr;

        SSL* ssl = SSL_new(ctx);
        if (ssl != nullptr){
            SSL_set_fd(ssl, client_fd);
        }
        return ssl;
    }
};


class ClientSession {
private:
    SSL* ssl = nullptr;
    int client_fd = -1;
    std::atomic<int>& active_clients;

    ClientSession(const ClientSession&) = delete;
    ClientSession& operator=(const ClientSession&) = delete;

public:
    ClientSession(SSL* s, int fd, std::atomic<int>& counter) 
        : ssl(s), client_fd(fd), active_clients(counter) {}

    ~ClientSession() {
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        if (client_fd >= 0) {
            close(client_fd);
        }
        active_clients--;
        std::cout << "[RAII] Client resources cleared safely." << std::endl;
    }

    SSL* get_ssl() const { return ssl; }
    int get_fd() const { return client_fd; }
};

void handleClient(std::unique_ptr<ClientSession> session, AuthDatabase& auth_db){
    SSL* ssl = session->get_ssl();
    std::cout << "[Thread " << std::this_thread::get_id() << "] Client connected safely." << std::endl;

    if (SSL_accept(ssl) != 1){
        std::cout << "Error: TLS handshake declined by client." << std::endl;
        return;
    }
    std::cout << "TLS Handshake successfully accepted!" << std::endl;


    const char* authorize_prefix = "AUTH:";

    std::array<char, 1024> buffer{};
    int bytes;

    bytes = SSL_read(ssl, buffer.data(), buffer.size() - 1);
    if (bytes <= 0){
        return;
    }

    std::string_view message(buffer.data(), bytes);

    if (message.rfind(authorize_prefix, 0) != 0){
        std::cout << "Authorize is failed. Invalid prefix." << std::endl;
        SSL_write(ssl, "Access Denied", 13);
        return;
    }

    std::string_view token = message.substr(5);

    if(token.length() > 64 || token.length() == 0){
        std::cout << "Authorize is failed. Malformed or too long token." << std::endl;
        SSL_write(ssl, "Access Denied", 13);
        return;        
    }

    if(!auth_db.verify_token(token)){
        std::cout << "Authorize is failed. Invalid token." << std::endl;
        SSL_write(ssl, "Access Denied", 13);
        return;
    }
    std::cout << "Client authorized successfully via Database!" << std::endl;

    buffer.fill(0);

    while (server_running && (bytes = SSL_read(ssl, buffer.data(), buffer.size() - 1)) > 0) {
        std::string_view command(buffer.data(), bytes);
        std::cout << "[Log] Received command: " << command << std::endl;
        
        if (command.rfind("time", 0) == 0) {
            auto now = std::chrono::system_clock::now();
            std::time_t now_c = std::chrono::system_clock::to_time_t(now);
            struct tm result_time{}; 
            localtime_r(&now_c, &result_time);

            char time_str[100];
            std::strftime(time_str, sizeof(time_str), "%H:%M:%S", &result_time);
            SSL_write(ssl, time_str, strlen(time_str));
        }
        buffer.fill(0);
    }

    std::cout << "Client connection closed. Thread finished." << std::endl;
}



int startServer(int port, const char* cert_file, const char* key_file){
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    TLSEngine tls_engine(port, cert_file, key_file);
    AuthDatabase auth_db("auth.db");

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0){
        std::cout << "Error: Server socket creation failed." << std::endl;
        return 1;
    }
    std::cout << "Server socket created successfully." << std::endl;

    int opt = 1;
    if(setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0){
        std::cout << "Warning: Failed to set SO_REUSEADDR. Port reuse might be delayed." << std::endl;
    } else {
        std::cout << "SO_REUSEADDR enabled successfully (instant port reuse)." << std::endl;
    }

    struct timeval accept_timeout{};
    accept_timeout.tv_sec = 1; 
    accept_timeout.tv_usec = 0;
    setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, &accept_timeout, sizeof(accept_timeout));
    setsockopt(server_fd, SOL_SOCKET, SO_SNDTIMEO, &accept_timeout, sizeof(accept_timeout));

    struct sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port); 
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
        std::cout << "Error: Failed to bind to port " << port << " (Port might be busy)." << std::endl;
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 10) < 0){
        std::cout << "Error: Listen failed." << std::endl;
        close(server_fd);
        return 1;
    }
    std::cout << "Server is running on port " << port << " and listening for connections..." << std::endl;

    const int MAX_CLIENTS = 4;
    std::atomic<int> active_clients {0};
    std::vector<std::thread> client_threads;

    while(true){
        int client_fd = accept(server_fd, nullptr, nullptr);
        if(client_fd < 0) {
            continue;
        }

        struct timeval timeout{};
        timeout.tv_sec = 15;
        timeout.tv_usec = 0;

        if(setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0){
            std::cout << "Warning: Failed to set recv timeout." << std::endl;
        }

        if(setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0){
            std::cout << "Warning: Failed to set send timeout." << std::endl;
        }

        active_clients++; 
        if(active_clients > MAX_CLIENTS){
            send(client_fd, "Error: Server is busy. Try again later.\n", 40, 0);
            close(client_fd);
            active_clients--;
            continue;
        }
        
        SSL* ssl = tls_engine.createSSLSession(client_fd);
        if (ssl == nullptr){
            close(client_fd);
            active_clients--;
            continue;
        }

        auto session = std::make_unique<ClientSession>(ssl, client_fd, active_clients);
        client_threads.emplace_back(handleClient, std::move(session), std::ref(auth_db));
    }

    std::cout << "[System] Waiting for active clients to disconnect..." << std::endl;
    for (auto& th : client_threads) {
        if (th.joinable()) {
            th.join();
        }
    };

    close(server_fd);
    std::cout << "[System] Server stopped cleanly. All resources released." << std::endl;
    return 0;
}
