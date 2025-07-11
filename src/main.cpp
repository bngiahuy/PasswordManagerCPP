#include "crypto/Crypto.h"
#include "core/PasswordManager.h"
#include "cli/Menu.h"

int main() {
    std::string salt = Crypto::generateSalt();
    std::string key = Crypto::deriveKey("master_password_123", salt);

    PasswordManager manager(key);
    Menu menu(manager, key);
    menu.displayMainMenu();

    return 0;
}
