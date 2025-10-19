#include "vaultcrypt/aead.h"
#include "vaultcrypt/crypto_backend.h"
#include <iostream>
#include <fstream>

int main() {
    using namespace vaultcrypt;

    try {
        std::cout << "=== Testing Direct Encryption (No Password) ===\n";

        // Original data
        SecureBytes plaintext = { 'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!' };
        std::cout << "Original: " << std::string(plaintext.begin(), plaintext.end()) << "\n";
        std::cout << "Size: " << plaintext.size() << " bytes\n\n";

        // Generate random key
        SecureBytes key = generate_random(32);
        std::cout << "Generated 32-byte key\n\n";

        // Encrypt
        AESGCMCipher cipher;
        SecureBytes encrypted = cipher.encrypt(key, plaintext);
        std::cout << "Encrypted size: " << encrypted.size() << " bytes\n\n";

        // Decrypt
        SecureBytes decrypted = cipher.decrypt(key, encrypted);
        std::cout << "Decrypted size: " << decrypted.size() << " bytes\n";
        std::cout << "Decrypted: " << std::string(decrypted.begin(), decrypted.end()) << "\n\n";

        if (decrypted == plaintext) {
            std::cout << "✓ SUCCESS: Decrypted matches original!\n";
            return 0;
        }
        else {
            std::cout << "✗ FAIL: Decrypted does NOT match original!\n";
            return 1;
        }

    }
    catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << "\n";
        return 1;
    }
}