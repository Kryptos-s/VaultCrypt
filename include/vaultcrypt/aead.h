#pragma once

#include "secure_memory.h"
#include "crypto_backend.h"
#include <cstdint>
#include <memory>

namespace vaultcrypt {

    // Container format header
    struct AEADHeader {
        uint32_t version = 1;
        uint8_t algorithm;
        uint8_t mode;
        uint16_t kdf_type;
        uint32_t kdf_iterations;
        uint32_t kdf_memory_kb;
        uint32_t kdf_parallelism;
        uint32_t salt_length;
        uint32_t nonce_length;
        uint32_t tag_length;
        uint32_t aad_length;
        uint32_t chunk_size;
        uint8_t reserved[12];
    };

    // AEAD encryption with AES-GCM
    class AESGCMCipher {
    public:
        AESGCMCipher();
        ~AESGCMCipher();

        SecureBytes encrypt(const SecureBytes& key, const SecureBytes& plaintext, const SecureBytes& aad = {});
        SecureBytes decrypt(const SecureBytes& key, const SecureBytes& ciphertext, const SecureBytes& aad = {});

        SecureBytes encrypt_password(const SecureString& password, const SecureBytes& plaintext,
            const KDFParams& kdf_params, const SecureBytes& aad = {});
        SecureBytes decrypt_password(const SecureString& password, const SecureBytes& ciphertext,
            const SecureBytes& aad = {});

        static constexpr size_t KEY_SIZE = 32;
        static constexpr size_t NONCE_SIZE = 12;
        static constexpr size_t TAG_SIZE = 16;

    private:
        std::unique_ptr<CryptoBackend> backend_;
    };

    // AEAD encryption with XChaCha20-Poly1305
    class ChaCha20Poly1305Cipher {
    public:
        ChaCha20Poly1305Cipher();
        ~ChaCha20Poly1305Cipher();

        SecureBytes encrypt(const SecureBytes& key, const SecureBytes& plaintext, const SecureBytes& aad = {});
        SecureBytes decrypt(const SecureBytes& key, const SecureBytes& ciphertext, const SecureBytes& aad = {});

        SecureBytes encrypt_password(const SecureString& password, const SecureBytes& plaintext,
            const KDFParams& kdf_params, const SecureBytes& aad = {});
        SecureBytes decrypt_password(const SecureString& password, const SecureBytes& ciphertext,
            const SecureBytes& aad = {});

        static constexpr size_t KEY_SIZE = 32;
        static constexpr size_t NONCE_SIZE = 24;
        static constexpr size_t TAG_SIZE = 16;

    private:
        std::unique_ptr<CryptoBackend> backend_;
    };

} // namespace vaultcrypt