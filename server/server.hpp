#pragma once
#include <openssl/ssl.h>

int startServer(int port, const char* cert_file, const char* key_file);