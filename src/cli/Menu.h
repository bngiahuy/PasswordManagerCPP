#pragma once

#include "core/PasswordManager.h"
#include "crypto/Crypto.h"
#include <string>

class Menu {
private:
    PasswordManager& manager;
    std::string vaultFilePath;
    std::string encryptionKey;

public:
    Menu(PasswordManager& manager,
         const std::string& encryptionKey,
         const std::string& vaultFilePath = "vault.dat");

    void displayMainMenu();
    void handleUserChoice(int choice);

private:
    void addAccountFlow();
    void listAccountsFlow();
    void searchAccountsFlow();
    void removeAccountFlow();
    void saveVaultFlow();
    void loadVaultFlow();
};
