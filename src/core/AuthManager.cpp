#include "AuthManager.h"
#include "../crypto/Crypto.h"
#include <iostream>
#include <fstream>
#include <filesystem>

// Prompts user to create a new master password, generates salt, hashes password+salt, and saves to file.
// Returns the derived key for encryption.
std::string AuthManager::setupNewMasterPassword(const std::string &authFilePath)
{
    std::string password;
    std::cout << "Create a master password: ";
    std::getline(std::cin, password);

    std::string salt = Crypto::generateSalt();
    std::string hashed = Crypto::hashSHA256(password + salt);

    // Save hash and salt to authentication file
    saveHashAndSalt(hashed, salt, authFilePath);
    std::cout << "Master password saved successfully.\n";

    // Return derived key for AES encryption
    return Crypto::deriveKey(password, salt);
}

// Prompts user to enter master password, verifies hash, and returns derived key if correct.
std::string AuthManager::verifyExistingMasterPassword(const std::string &authFilePath)
{
    std::string savedHash, savedSalt;
    // Load hash and salt from authentication file
    if (!loadHashAndSalt(savedHash, savedSalt, authFilePath))
    {
        throw std::runtime_error("Failed to load authentication data.");
    }

    std::string inputPassword;
    std::cout << "Enter your master password to verify: ";
    std::getline(std::cin, inputPassword);

    // Hash input password with loaded salt and compare with saved hash
    std::string hashedInput = Crypto::hashSHA256(inputPassword + savedSalt);
    if (hashedInput != savedHash)
    {
        throw std::runtime_error("Invalid master password.");
    }

    // Return derived key for AES encryption
    return Crypto::deriveKey(inputPassword, savedSalt);
}

// Save the hash and salt to the authentication file (overwrites file if exists)
void AuthManager::saveHashAndSalt(const std::string &hash, const std::string &salt, const std::string &authFilePath)
{
    // Ensure the parent directory exists
    std::filesystem::path authPath(authFilePath);
    std::filesystem::path parentDir = authPath.parent_path();
    if (!parentDir.empty() && !std::filesystem::exists(parentDir))
    {
        std::error_code ec;
        if (!std::filesystem::create_directories(parentDir, ec))
        {
            throw std::runtime_error("Cannot create directory for auth file: " + parentDir.string() + ", error: " + ec.message());
        }
    }
    std::ofstream out(authFilePath);
    if (!out)
    {
        throw std::runtime_error("Cannot write auth file: " + authFilePath);
    }
    out << hash << "\n"
        << salt << "\n";
    out.close();
}

// Load the hash and salt from the authentication file.
// Returns true if both hash and salt are loaded and non-empty.
bool AuthManager::loadHashAndSalt(std::string &hashOut, std::string &saltOut, const std::string &authFilePath)
{
    std::ifstream in(authFilePath);
    if (!in)
        return false;

    std::getline(in, hashOut);
    std::getline(in, saltOut);
    in.close();

    // Debug: check if hash or salt is empty
    // std::cerr << "Loaded hash: " << hashOut << ", salt: " << saltOut << std::endl;

    return !hashOut.empty() && !saltOut.empty();
}
