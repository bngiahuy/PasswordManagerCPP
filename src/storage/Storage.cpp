#include "Storage.h"
#include "../crypto/Crypto.h"
#include "third_party/nlohmann/json.hpp"
#include <fstream>
#include <iostream>

using json = nlohmann::json;
bool Storage::saveVault(const std::vector<Account>& accounts,
                        const std::string& encryptionKey,
                        const std::string& filePath) {
    json jAccounts = json::array();
    for (const auto& acc : accounts) {
        jAccounts.push_back(acc.toJson());
    }

    std::string plainText = jAccounts.dump(); // Chuỗi JSON đầy đủ
    std::string cipherText = Crypto::encrypt(plainText, encryptionKey);

    std::ofstream out(filePath, std::ios::binary);
    if (!out) {
        Logger::error("Cannot open file for writing: " + filePath);
        return false;
    }

    out.write(cipherText.c_str(), cipherText.size());
    out.close();
    return true;
}

std::vector<Account> Storage::loadVault(const std::string& encryptionKey,
                                        const std::string& filePath) {
    std::vector<Account> accounts;

    std::ifstream in(filePath, std::ios::binary);
    if (!in) {
        Logger::error("Cannot open file for reading: " + filePath);
        return accounts; // Empty
    }

    std::string cipherText((std::istreambuf_iterator<char>(in)),
                            std::istreambuf_iterator<char>());
    in.close();

    std::string plainText;
    try {
        plainText = Crypto::decrypt(cipherText, encryptionKey);
    } catch (const std::exception& ex) {
        Logger::error("Decryption failed: " + std::string(ex.what()));
        return accounts;
    }

    try {
        json jAccounts = json::parse(plainText);
        for (const auto& j : jAccounts) {
            accounts.push_back(Account::fromJson(j));
        }
    } catch (const std::exception& ex) {
        Logger::error("JSON parsing failed: " + std::string(ex.what()));
        return accounts; // Return empty if parsing fails
    }

    return accounts;
}
