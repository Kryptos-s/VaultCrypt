#include <catch2/catch_test_macros.hpp>
#include "vaultcrypt/aead.h"
#include "vaultcrypt/crypto_backend.h"
#include "vaultcrypt/error.h"

using namespace vaultcrypt;

TEST_CASE("AES-GCM encryption/decryption", "[aead][aes-gcm]") {
    AESGCMCipher cipher;

    SECTION("Basic round-trip") {
        SecureBytes key = generate_random(32);
        SecureBytes plaintext = { 'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd' };

        SecureBytes ciphertext = cipher.encrypt(key, plaintext);
        SecureBytes decrypted = cipher.decrypt(key, ciphertext);

        REQUIRE(decrypted == plaintext);
    }

    SECTION("With associated data") {
        SecureBytes key = generate_random(32);
        SecureBytes plaintext = { 'T', 'e', 's', 't' };
        SecureBytes aad = { 'm', 'e', 't', 'a', 'd', 'a', 't', 'a' };

        SecureBytes ciphertext = cipher.encrypt(key, plaintext, aad);
        SecureBytes decrypted = cipher.decrypt(key, ciphertext, aad);

        REQUIRE(decrypted == plaintext);
    }

    SECTION("Wrong AAD fails") {
        SecureBytes key = generate_random(32);
        SecureBytes plaintext = { 'T', 'e', 's', 't' };
        SecureBytes aad = { 'c', 'o', 'r', 'r', 'e', 'c', 't' };
        SecureBytes wrong_aad = { 'w', 'r', 'o', 'n', 'g' };

        SecureBytes ciphertext = cipher.encrypt(key, plaintext, aad);

        REQUIRE_THROWS_AS(cipher.decrypt(key, ciphertext, wrong_aad), VaultCryptException);
    }

    SECTION("Password-based encryption") {
        SecureString password = { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', '1', '2', '3' };
        SecureBytes plaintext = { 'S', 'e', 'c', 'r', 'e', 't' };

        KDFParams kdf_params;
        kdf_params.type = KDFType::Argon2id;
        kdf_params.iterations = 2;
        kdf_params.memory_kb = 8192;
        kdf_params.parallelism = 1;

        SecureBytes ciphertext = cipher.encrypt_password(password, plaintext, kdf_params);
        SecureBytes decrypted = cipher.decrypt_password(password, ciphertext);

        REQUIRE(decrypted == plaintext);
    }
}

TEST_CASE("XChaCha20-Poly1305 encryption/decryption", "[aead][chacha20]") {
    ChaCha20Poly1305Cipher cipher;

    SECTION("Basic round-trip") {
        SecureBytes key = generate_random(32);
        SecureBytes plaintext = { 'T', 'e', 's', 't', 'i', 'n', 'g' };

        SecureBytes ciphertext = cipher.encrypt(key, plaintext);
        SecureBytes decrypted = cipher.decrypt(key, ciphertext);

        REQUIRE(decrypted == plaintext);
    }

    SECTION("Large data") {
        SecureBytes key = generate_random(32);
        SecureBytes plaintext = generate_random(1024);

        SecureBytes ciphertext = cipher.encrypt(key, plaintext);
        SecureBytes decrypted = cipher.decrypt(key, ciphertext);

        REQUIRE(decrypted == plaintext);
    }
}