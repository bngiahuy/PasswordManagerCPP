#include "crypto/Crypto.h"
#include <iostream>
#include "utils/Utils.hpp"


int main() {
    // Test input
    std::string plaintext = "Hello, World!";

    // Generate random salt for key derivation
    std::string salt = Crypto::generateSalt();

    // Generate random IV and convert to hex for display
    std::string iv = toHex(Crypto::generateIV());

    // Hash a sample password using SHA256
    std::string hash = Crypto::hashSHA256("123456");

    // Derive encryption key from password and salt
    std::string derivedKey = Crypto::deriveKey("password", salt);

    // Encrypt the plaintext using the derived key
    std::string encryptionKey = Crypto::encrypt(plaintext, derivedKey);

    // Decrypt the ciphertext to verify correctness
    std::string decryptedText = Crypto::decrypt(encryptionKey, derivedKey);

    // Output test results
    std::cout << "Salt: " << toHex(salt) << "\n";
    std::cout << "IV: " << iv << "\n";
    std::cout << "SHA256: " << hash << "\n";
    std::cout << "Derived Key: " << toHex(derivedKey) << "\n";

    // Check if decryption matches original plaintext
    if (decryptedText == plaintext) {
        std::cout << "Decryption successful: " << decryptedText << "\n";
    } else {
        std::cout << "Decryption failed!\n";
    }

    return 0;
}
