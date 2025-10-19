#include <catch2/catch_test_macros.hpp>
#include "vaultcrypt/aead.h"
#include "vaultcrypt/envelope.h"
#include "vaultcrypt/keystore.h"
#include "vaultcrypt/file_io.h"
#include <filesystem>

using namespace vaultcrypt;

TEST_CASE("End-to-end encryption workflow", "[integration]") {
    const std::string test_file = "test_data.txt";
    const std::string encrypted_file = "test_data.txt.enc";
    const std::string decrypted_file = "test_data.txt.dec";

    auto cleanup = [&]() {
        std::filesystem::remove(test_file);
        std::filesystem::remove(encrypted_file);
        std::filesystem::remove(decrypted_file);
        };
    cleanup();

    SECTION("File encryption with password") {
        SecureBytes original_data = { 'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 'a', ' ', 't', 'e', 's', 't' };
        write_file(test_file, original_data);

        SecureString password = { 'm', 'y', 's', 'e', 'c', 'r', 'e', 't' };
        SecureBytes plaintext = read_file(test_file);

        AESGCMCipher cipher;
        KDFParams kdf;
        kdf.iterations = 2;
        kdf.memory_kb = 8192;

        SecureBytes ciphertext = cipher.encrypt_password(password, plaintext, kdf);
        write_file(encrypted_file, ciphertext);

        SecureBytes encrypted = read_file(encrypted_file);
        SecureBytes decrypted = cipher.decrypt_password(password, encrypted);
        write_file(decrypted_file, decrypted);

        SecureBytes result = read_file(decrypted_file);
        REQUIRE(result == original_data);
    }

    SECTION("Hybrid encryption workflow") {
        EnvelopeCrypto envelope;
        auto keypair = envelope.generate_keypair(EnvelopeMode::X25519_XCHACHA20_POLY1305);

        SecureBytes original_data = generate_random(1024);
        write_file(test_file, original_data);

        SecureBytes plaintext = read_file(test_file);
        SecureBytes ciphertext = envelope.encrypt(
            EnvelopeMode::X25519_XCHACHA20_POLY1305,
            keypair.public_key,
            plaintext
        );
        write_file(encrypted_file, ciphertext);

        SecureBytes encrypted = read_file(encrypted_file);
        SecureBytes decrypted = envelope.decrypt(
            EnvelopeMode::X25519_XCHACHA20_POLY1305,
            keypair.private_key,
            encrypted
        );
        write_file(decrypted_file, decrypted);

        SecureBytes result = read_file(decrypted_file);
        REQUIRE(result == original_data);
    }

    cleanup();
}