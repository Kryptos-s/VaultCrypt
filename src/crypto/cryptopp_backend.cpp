#include "vaultcrypt/crypto_backend.h"
#include "vaultcrypt/error.h"
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <iostream>

namespace vaultcrypt {

    class CryptoPPBackend : public CryptoBackend {
    public:
        SecureBytes encrypt(
            Algorithm alg,
            Mode mode,
            const SecureBytes& key,
            const SecureBytes& plaintext,
            const SecureBytes& iv,
            const SecureBytes& aad
        ) override {
            using namespace CryptoPP;

            if (alg == Algorithm::AES_256 && mode == Mode::GCM) {
                try {
                    GCM<AES>::Encryption enc;
                    enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

                    std::string ciphertext_str;

                    AuthenticatedEncryptionFilter aef(enc,
                        new StringSink(ciphertext_str),
                        false, 16  // 16 byte tag
                    );

                    // Add AAD if present
                    if (!aad.empty()) {
                        aef.ChannelPut(AAD_CHANNEL, aad.data(), aad.size());
                        aef.ChannelMessageEnd(AAD_CHANNEL);
                    }

                    // Encrypt plaintext
                    aef.ChannelPut(DEFAULT_CHANNEL, plaintext.data(), plaintext.size());
                    aef.ChannelMessageEnd(DEFAULT_CHANNEL);

                    // Convert to SecureBytes
                    SecureBytes result(ciphertext_str.begin(), ciphertext_str.end());

                    std::cerr << "[BACKEND] Encrypted " << plaintext.size() << " bytes -> "
                        << result.size() << " bytes (with tag)\n";

                    return result;

                }
                catch (const Exception& e) {
                    throw VaultCryptException(ErrorCode::EncryptionFailed,
                        std::string("Crypto++ encryption failed: ") + e.what());
                }
            }

            throw VaultCryptException(ErrorCode::UnsupportedAlgorithm, "Algorithm/mode not implemented");
        }

        SecureBytes decrypt(
            Algorithm alg,
            Mode mode,
            const SecureBytes& key,
            const SecureBytes& ciphertext,
            const SecureBytes& iv,
            const SecureBytes& aad
        ) override {
            using namespace CryptoPP;

            std::cerr << "[BACKEND] decrypt() called with " << ciphertext.size() << " bytes\n";

            if (alg == Algorithm::AES_256 && mode == Mode::GCM) {
                if (ciphertext.size() < 16) {
                    throw VaultCryptException(ErrorCode::InvalidArgument, "Ciphertext too short (no tag)");
                }

                try {
                    GCM<AES>::Decryption dec;
                    dec.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

                    std::string plaintext_str;

                    AuthenticatedDecryptionFilter adf(dec,
                        new StringSink(plaintext_str),
                        AuthenticatedDecryptionFilter::DEFAULT_FLAGS,
                        16  // 16 byte tag
                    );

                    // Add AAD if present
                    if (!aad.empty()) {
                        adf.ChannelPut(AAD_CHANNEL, aad.data(), aad.size());
                        adf.ChannelMessageEnd(AAD_CHANNEL);
                    }

                    // Decrypt (ciphertext includes tag at the end)
                    adf.ChannelPut(DEFAULT_CHANNEL, ciphertext.data(), ciphertext.size());
                    adf.ChannelMessageEnd(DEFAULT_CHANNEL);

                    // Check authentication
                    if (!adf.GetLastResult()) {
                        throw VaultCryptException(ErrorCode::DecryptionFailed, "GCM authentication failed");
                    }

                    // Convert to SecureBytes
                    SecureBytes result(plaintext_str.begin(), plaintext_str.end());

                    std::cerr << "[BACKEND] Decrypted " << ciphertext.size() << " bytes -> "
                        << result.size() << " bytes plaintext\n";

                    return result;

                }
                catch (const Exception& e) {
                    throw VaultCryptException(ErrorCode::DecryptionFailed,
                        std::string("Crypto++ decryption failed: ") + e.what());
                }
            }

            throw VaultCryptException(ErrorCode::UnsupportedAlgorithm, "Algorithm/mode not implemented");
        }

        size_t get_iv_size(Algorithm alg, Mode mode) const override {
            if (mode == Mode::GCM) return 12;
            return 16;
        }

        size_t get_tag_size(Algorithm alg, Mode mode) const override {
            if (is_aead(mode)) return 16;
            return 0;
        }

        bool is_aead(Mode mode) const override {
            return mode == Mode::GCM || mode == Mode::OCB || mode == Mode::EAX;
        }
    };

    SecureBytes generate_random(size_t length) {
        CryptoPP::AutoSeededRandomPool rng;
        SecureBytes result(length);
        rng.GenerateBlock(result.data(), length);
        return result;
    }

    SecureBytes derive_key(const SecureString& password, const KDFParams& params, size_t key_length) {
        using namespace CryptoPP;

        SecureBytes derived_key(key_length);

        // Use PBKDF2 (Argon2 not available in older Crypto++)
        PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;
        pbkdf2.DeriveKey(
            derived_key.data(), derived_key.size(),
            0,
            reinterpret_cast<const byte*>(password.data()), password.size(),
            params.salt.data(), params.salt.size(),
            params.iterations * 10000  // Scale up iterations
        );

        return derived_key;
    }

    std::unique_ptr<CryptoBackend> create_cryptopp_backend() {
        return std::make_unique<CryptoPPBackend>();
    }

} // namespace vaultcrypt

