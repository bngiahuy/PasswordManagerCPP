#include "PasswordManager.h"
#include "../crypto/Crypto.h"
#include <iostream>
#include <algorithm>

// Constructor
PasswordManager::PasswordManager(const std::string& encryptionKey)
    : encryptionKey(encryptionKey) {}

// Add account (password will be encrypted before storing)
void PasswordManager::addAccount(const std::string& service,
                                 const std::string& username,
                                 const std::string& password,
                                 const std::string& note) {
    std::string encryptedPwd = Crypto::encrypt(password, encryptionKey);
    Account newAcc(service, username, encryptedPwd, note);
    accounts.push_back(newAcc);
}

// Remove by service name
bool PasswordManager::removeAccount(const std::string& service) {
    auto it = std::remove_if(accounts.begin(), accounts.end(), [&](const Account& acc) {
        return acc.getServiceName() == service;
    });

    if (it != accounts.end()) {
        accounts.erase(it, accounts.end());
        return true;
    }
    return false;
}

// Get account by service name
std::optional<Account> PasswordManager::getAccount(const std::string& service) const {
    for (const auto& acc : accounts) {
        if (acc.getServiceName() == service) {
            return acc;
        }
    }
    return std::nullopt;
}

// Search by keyword
std::vector<Account> PasswordManager::searchAccounts(const std::string& keyword) const {
    std::vector<Account> results;
    for (const auto& acc : accounts) {
        if (acc.getServiceName().find(keyword) != std::string::npos ||
            acc.getUsername().find(keyword) != std::string::npos) {
            results.push_back(acc);
        }
    }
    return results;
}

// Print list of services + usernames (do not print password)
void PasswordManager::listAccounts() const {
    if (accounts.empty()) {
        Logger::info("Vault is empty.");
        return;
    }

    std::cout << "Accounts in vault:\n";
    std::cout << "Service | Username\n";
    std::cout << "---------------------\n";
    for (const auto& acc : accounts) {
        std::cout << acc.getServiceName() + " | " + acc.getUsername() + "\n";
    }
    std::cout << "---------------------\n";
    std::cout << "Total accounts: " + std::to_string(accounts.size()) + "\n";
}

const std::vector<Account>& PasswordManager::getAllAccounts() const {
    return accounts;
}

void PasswordManager::clearAccounts() {
    accounts.clear();
}
