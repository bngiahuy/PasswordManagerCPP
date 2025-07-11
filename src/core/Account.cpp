#include "Account.h"

Account::Account(const std::string &serviceName, const std::string &username, const std::string &encryptedPassword, const std::string &note) {
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
