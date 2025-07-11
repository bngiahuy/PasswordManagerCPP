#pragma once

#include <iostream>
#include <string>
#include "third_party/nlohmann/json.hpp"
#include "utils/utils.h"
class Account
{
private:
    std::string serviceName;
    std::string username;
    std::string encryptedPassword;
    std::string note;

public:
    Account() = default;

    Account(const std::string &serviceName,
            const std::string &username,
            const std::string &encryptedPassword,
            const std::string &note = "");

    // Getters
    std::string getServiceName() const;
    std::string getUsername() const;
    std::string getEncryptedPassword() const;
    std::string getNote() const;

    // Setters
    void setEncryptedPassword(const std::string &newEncryptedPassword);
    void setNote(const std::string &newNote);

    // Serialization to JSON
    nlohmann::json toJson() const;
    // Deserialization from JSON
    static Account fromJson(const nlohmann::json &json);
};
