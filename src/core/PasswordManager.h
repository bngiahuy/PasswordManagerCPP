#pragma once

#include <string>
#include <vector>
#include <optional>
#include "Account.h"

class PasswordManager {
private:
    std::vector<Account> accounts;
    std::string encryptionKey; // AES key derived from master password

public:
    PasswordManager(const std::string& encryptionKey);

    void addAccount(const std::string& service,
                    const std::string& username,
                    const std::string& password, // plaintext!
                    const std::string& note = "");

    bool removeAccount(const std::string& service);

    std::optional<Account> getAccount(const std::string& service) const;

    std::vector<Account> searchAccounts(const std::string& keyword) const;

    void listAccounts() const;

    // Optional: getter/setter if you want to support multiple vaults
    const std::vector<Account>& getAllAccounts() const;
    void clearAccounts();
};
