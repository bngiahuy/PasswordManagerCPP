#include "Account.h"

Account::Account(const std::string &serviceName, const std::string &username, const std::string &encryptedPassword, const std::string &note)
{
    this->serviceName = serviceName;
    this->username = username;
    this->encryptedPassword = encryptedPassword;
    this->note = note;
}

std::string Account::getServiceName() const
{
    return this->serviceName;
}

std::string Account::getUsername() const
{
    return this->username;
}

std::string Account::getEncryptedPassword() const
{
    return this->encryptedPassword;
}

std::string Account::getNote() const
{
    return this->note;
}

void Account::setEncryptedPassword(const std::string &newEncryptedPassword)
{
    this->encryptedPassword = newEncryptedPassword;
}

void Account::setNote(const std::string &newNote)
{
    this->note = newNote;
}

nlohmann::json Account::toJson() const
{
    // Since encryptedPassword is stored in binary format, we convert it to hex for JSON serialization
    return nlohmann::json{
        {"service", this->serviceName},
        {"username", this->username},
        {"encrypted_password", Utils::toHex(this->encryptedPassword)},
        {"note", this->note}
    };
}

Account Account::fromJson(const nlohmann::json &json)
{
    return Account(
        json.at("service").get<std::string>(),
        json.at("username").get<std::string>(),
        json.at("encrypted_password").get<std::string>(),
        json.at("note").get<std::string>());
}
