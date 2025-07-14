#include "Menu.h"
#include "Storage.h"
#include <iostream>

Menu::Menu(PasswordManager& manager,
           const std::string& encryptionKey,
           const std::string& vaultFilePath)
    : manager(manager),
      encryptionKey(encryptionKey),
      vaultFilePath(vaultFilePath) {}

void Menu::displayMainMenu() {
    int choice;
    do {
        std::cout << "\n--- Password Manager Menu ---\n";
        std::cout << "1. Add Account\n";
        std::cout << "2. List Accounts\n";
        std::cout << "3. Search Accounts\n";
        std::cout << "4. Remove Account\n";
        std::cout << "5. Save Vault\n";
        std::cout << "6. Load Vault\n";
        std::cout << "0. Exit\n";
        std::cout << "Enter your choice: ";
        std::cin >> choice;
        std::cin.ignore(); // bỏ newline
        handleUserChoice(choice);
    } while (choice != 0);
}

void Menu::handleUserChoice(int choice) {
    switch (choice) {
        case 1: addAccountFlow(); break;
        case 2: listAccountsFlow(); break;
        case 3: searchAccountsFlow(); break;
        case 4: removeAccountFlow(); break;
        case 5: saveVaultFlow(); break;
        case 6: loadVaultFlow(); break;
        case 0: std::cout << "Goodbye!\n"; break;
        default: std::cout << "Invalid choice.\n"; break;
    }
}

void Menu::addAccountFlow() {
    std::string service, username, password, note;
    std::cout << "Service: ";
    std::getline(std::cin, service);
    std::cout << "Username: ";
    std::getline(std::cin, username);
    std::cout << "Password: ";
    std::getline(std::cin, password);
    std::cout << "Note (optional): ";
    std::getline(std::cin, note);

    manager.addAccount(service, username, password, note);
    std::cout << "Account added.\n";
}

void Menu::listAccountsFlow() {
    manager.listAccounts();
}

void Menu::searchAccountsFlow() {
    std::string keyword;
    std::cout << "Enter keyword: ";
    std::getline(std::cin, keyword);

    auto results = manager.searchAccounts(keyword);
    if (results.empty()) {
        std::cout << "No accounts found.\n";
        return;
    }

    std::cout << "Found:\n";
    for (const auto& acc : results) {
        std::cout << "Service: " << acc.getServiceName() << "\n";
        std::cout << "Username: " << acc.getUsername() << "\n";
        std::cout << "Password: " << Crypto::decrypt(acc.getEncryptedPassword(), encryptionKey) << "\n";
        std::cout << "Note: " << acc.getNote() << "\n\n";
    }
}

void Menu::removeAccountFlow() {
    std::string service;
    std::cout << "Enter service name to remove: ";
    std::getline(std::cin, service);

    if (manager.removeAccount(service)) {
        std::cout << "Account removed.\n";
    } else {
        std::cout << "No such account.\n";
    }
}

void Menu::saveVaultFlow() {
    if (Storage::saveVault(manager.getAllAccounts(), encryptionKey, vaultFilePath)) {
        std::cout << "Vault saved successfully.\n";
    } else {
        std::cout << "Failed to save vault.\n";
    }
}

void Menu::loadVaultFlow() {
    auto accounts = Storage::loadVault(encryptionKey, vaultFilePath);
    manager.clearAccounts();
    for (const auto& acc : accounts) {
        manager.addAccount(
            acc.getServiceName(),
            acc.getUsername(),
            Crypto::decrypt(acc.getEncryptedPassword(), encryptionKey),
            acc.getNote()
        );
    }
    std::cout << "Vault loaded.\n";
}
