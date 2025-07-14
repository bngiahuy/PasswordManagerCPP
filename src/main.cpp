#include "crypto/Crypto.h"
#include "core/PasswordManager.h"
#include "cli/Menu.h"
#include "core/AuthManager.h"

#include <filesystem>
#include <iostream>

int main()
{
    // Path to the file that stores the hashed master password (absolute path)
    std::filesystem::path authRelPath = "stored_data/auth.dat";
    std::filesystem::path authPath = std::filesystem::absolute(authRelPath);
    std::string encryptionKey;

    try
    {
        // Check if it's the first run or if a master password already exists
        if (!std::filesystem::exists(authPath))
        {
            std::cout << "No existing master password found. Setting up a new one.\n";
            // Set up a new master password and save its hash
            encryptionKey = AuthManager::setupNewMasterPassword(authPath.string());
        }
        else
        {
            // Verify the existing master password
            std::cout << "Existing master password found. Please verify it.\n";
            encryptionKey = AuthManager::verifyExistingMasterPassword(authPath.string());
        }

        // Initialize PasswordManager with the verified key
        PasswordManager manager(encryptionKey);
        // Set up the CLI menu interface
        Menu menu(manager, encryptionKey);
        // Display the main menu
        menu.displayMainMenu();
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Authentication failed: " << ex.what() << "\n";
        return 1;
    }

    return 0;
}
