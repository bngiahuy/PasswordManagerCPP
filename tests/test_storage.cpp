#include "core/PasswordManager.h"
#include "storage/Storage.h"
#include "crypto/Crypto.h"
#include <iostream>

void testStorage()
{
    std::string filePath = "stored_data/vault.dat";
    std::string salt = Crypto::generateSalt();
    std::string key = Crypto::deriveKey("master123", salt);

    PasswordManager manager(key);
    manager.addAccount("Github", "huy", "ghpass", "dev");
    manager.addAccount("Gmail", "huybui", "gmailpass", "");

    // Save
    if (Storage::saveVault(manager.getAllAccounts(), key, filePath))
        std::cout << "Vault saved.\n";

    // Load
    std::vector<Account> loadedAccounts = Storage::loadVault(key, filePath);
    std::cout << "Loaded " << loadedAccounts.size() << " accounts from vault.\n";
}
