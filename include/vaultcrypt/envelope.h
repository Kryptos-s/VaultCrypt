#pragma once

#include "secure_memory.h"
#include <string>
#include <memory>

namespace vaultcrypt {

    enum class EnvelopeMode {
        RSA_OAEP_AES_GCM,
        X25519_XCHACHA20_POLY1305
    };

    // Hybrid encryption envelope
    class EnvelopeCrypto {
    public:
        EnvelopeCrypto();
        ~EnvelopeCrypto();

        struct KeyPair {
            SecureBytes public_key;
            SecureBytes private_key;
        };

        KeyPair generate_keypair(EnvelopeMode mode);

        SecureBytes encrypt(EnvelopeMode mode, const SecureBytes& public_key,
            const SecureBytes& plaintext, const SecureBytes& aad = {});

        SecureBytes decrypt(EnvelopeMode mode, const SecureBytes& private_key,
            const SecureBytes& ciphertext, const SecureBytes& aad = {});

    private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };

    // Envelope container format
    struct EnvelopeHeader {
        uint32_t version = 1;
        uint8_t mode;
        uint32_t encrypted_key_length;
        uint32_t nonce_length;
        uint32_t tag_length;
        uint32_t aad_length;
        uint8_t reserved[32];
    };

} // namespace vaultcrypt