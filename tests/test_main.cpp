#include "tests/test_account.cpp"
#include "tests/test_crypto.cpp"
#include "tests/test_password_manager.cpp"
#include "tests/test_storage.cpp"

int main() {
    testAccount();
    testCrypto();
    testPasswordManager();
    testStorage();
    return 0;
}
