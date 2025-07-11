#include "core/Account.h"
#include <iostream>

int main() {
    Account acc("Gmail", "huybui@gmail.com", "ENCRYPTED_PWD", "Tài khoản cá nhân");

    std::cout << "Service: " << acc.getServiceName() << "\n";
    std::cout << "Username: " << acc.getUsername() << "\n";
    std::cout << "Encrypted Password: " << acc.getEncryptedPassword() << "\n";
    std::cout << "Note: " << acc.getNote() << "\n";
}
