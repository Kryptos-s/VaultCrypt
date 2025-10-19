#pragma once

#include "secure_memory.h"
#include <string>
#include <memory>

namespace vaultcrypt {

    enum class Algorithm {
        AES_128, AES_192, AES_256,
        XChaCha20, ChaCha20
    };

    enum class Mode {
        GCM, OCB, EAX
    };

    enum class KDFType {
        Argon2id,
        PBKDF2_SHA256,
        PBKDF2_SHA512
    };

    struct KDFParams {
        KDFType type = KDFType::Argon2id;
        uint32_t iterations = 3;
        uint32_t memory_kb = 65536;
        uint32_t parallelism = 4;
        SecureBytes salt;
    };

    // Generate cryptographically secure random bytes
    SecureBytes generate_random(size_t length);

    // Key derivation
    SecureBytes derive_key(const SecureString& password, const KDFParams& params, size_t key_length);

    // Backend interface for algorithm implementations
    class CryptoBackend {
    public:
        virtual ~CryptoBackend() = default;

        virtual SecureBytes encrypt(
            Algorithm alg,
            Mode mode,
            const SecureBytes& key,
            const SecureBytes& plaintext,
            const SecureBytes& iv,
            const SecureBytes& aad = {}
        ) = 0;

        virtual SecureBytes decrypt(
            Algorithm alg,
            Mode mode,
            const SecureBytes& key,
            const SecureBytes& ciphertext,
            const SecureBytes& iv,
            const SecureBytes& aad = {}
        ) = 0;

        virtual size_t get_iv_size(Algorithm alg, Mode mode) const = 0;
        virtual size_t get_tag_size(Algorithm alg, Mode mode) const = 0;
        virtual bool is_aead(Mode mode) const = 0;
    };

    // Factory for backend selection
    std::unique_ptr<CryptoBackend> create_cryptopp_backend();
    std::unique_ptr<CryptoBackend> create_libsodium_backend();

} // namespace vaultcrypt
