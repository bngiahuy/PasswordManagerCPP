#include "crypto/Crypto.h"
#include <iostream>

// Helper function: Convert a string to its hexadecimal representation
// Used for displaying salts, IVs, and keys in hex format for easier debugging
std::string toHex(const std::string& input) {
    std::stringstream ss;
    for (unsigned char c : input) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    return ss.str();
}

// Helper function: Convert a hexadecimal string back to binary
std::string fromHex(const std::string& hex) {
    std::string result;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char byte = static_cast<char>(strtol(byteString.c_str(), nullptr, 16));
        result.push_back(byte);
    }
    return result;
}

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
