#include "core/PasswordManager.h"
#include "crypto/Crypto.h"
#include <iostream>

void testPasswordManager() {
    std::string salt = Crypto::generateSalt();
    std::string key = Crypto::deriveKey("my_master_password", salt);

    PasswordManager manager(key);

    manager.addAccount("Gmail", "huybui@gmail.com", "mySuperSecretPassword", "Personal");
    manager.addAccount("Facebook", "huybui.fb", "pass123456", "");

    // List all accounts
    manager.listAccounts();

    std::optional<Account> accOpt = manager.getAccount("Gmail");
    if (accOpt) {
        std::string decrypted = Crypto::decrypt(accOpt->getEncryptedPassword(), key);
        std::cout << "Decrypted password for Gmail: " << decrypted << "\n";
    }

    std::optional<Account> facebookAcc = manager.getAccount("Facebook");
    if (facebookAcc) {
        std::string decrypted = Crypto::decrypt(facebookAcc->getEncryptedPassword(), key);
        std::cout << "Decrypted password for Facebook with username " << facebookAcc->getUsername() << " is " << decrypted << "\n";
    }
}
