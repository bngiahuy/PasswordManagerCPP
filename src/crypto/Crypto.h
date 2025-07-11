#pragma once
#include <iostream>
#include <string>
#include <random>
#include <iomanip>
#include <openssl/sha.h>
#include <memory>        // For std::unique_ptr
#include <openssl/evp.h> // For EVP functions
#include <openssl/err.h> // For error handling in OpenSSL
#include "utils/Logger.h"
class Crypto
{
public:
    // Encrypts the given plaintext using the provided key
    static std::string encrypt(const std::string &plaintext, const std::string &key);

    // Decrypts the given ciphertext using the provided key
    static std::string decrypt(const std::string &ciphertext, const std::string &key);

    // Generates a random salt for key derivation
    static std::string deriveKey(const std::string &password, const std::string &salt);

    // Generates a random initialization vector (IV) for encryption
    static std::string generateIV();

    // Generates a random salt for password hashing
    static std::string generateSalt();

    // Hashes the given input using SHA-256
    static std::string hashSHA256(const std::string &input);
};