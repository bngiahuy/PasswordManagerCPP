#pragma once

#include <string>

class AuthManager
{
public:
    // If the authentication file does not exist, prompt the user to create a new master password.
    // Returns the master password (for key derivation).
    static std::string setupNewMasterPassword(const std::string &authFilePath);

    // If the authentication file exists, prompt the user to verify the master password.
    // Returns the master password if authentication is successful.
    static std::string verifyExistingMasterPassword(const std::string &authFilePath);

private:
    // Save the hashed master password and salt to the authentication file.
    static void saveHashAndSalt(const std::string &hash, const std::string &salt, const std::string &authFilePath);

    // Load the hashed master password and salt from the authentication file.
    // Returns true if loading is successful, false otherwise.
    static bool loadHashAndSalt(std::string &hashOut, std::string &saltOut, const std::string &authFilePath);
};
