#include "vaultcrypt/crypto_backend.h"
#include "vaultcrypt/error.h"
#include <sodium.h>

namespace vaultcrypt {

    class LibsodiumBackend : public CryptoBackend {
    public:
        LibsodiumBackend() {
            if (sodium_init() < 0) {
                throw VaultCryptException(ErrorCode::LibraryError, "Failed to initialize libsodium");
            }
        }

        SecureBytes encrypt(
            Algorithm alg,
            Mode mode,
            const SecureBytes& key,
            const SecureBytes& plaintext,
            const SecureBytes& iv,
            const SecureBytes& aad
        ) override {
            if (alg == Algorithm::XChaCha20) {
                if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
                    throw VaultCryptException(ErrorCode::InvalidKey, "Invalid key size for XChaCha20-Poly1305");
                }

                if (iv.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
                    throw VaultCryptException(ErrorCode::InvalidNonce, "Invalid nonce size for XChaCha20-Poly1305");
                }

                SecureBytes ciphertext(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
                unsigned long long ciphertext_len;

                int result = crypto_aead_xchacha20poly1305_ietf_encrypt(
                    ciphertext.data(), &ciphertext_len,
                    plaintext.data(), plaintext.size(),
                    aad.empty() ? nullptr : aad.data(), aad.size(),
                    nullptr,
                    iv.data(),
                    key.data()
                );

                if (result != 0) {
                    throw VaultCryptException(ErrorCode::EncryptionFailed, "XChaCha20-Poly1305 encryption failed");
                }

                ciphertext.resize(ciphertext_len);
                return ciphertext;
            }

            throw VaultCryptException(ErrorCode::UnsupportedAlgorithm, "Algorithm not supported by libsodium backend");
        }

        SecureBytes decrypt(
            Algorithm alg,
            Mode mode,
            const SecureBytes& key,
            const SecureBytes& ciphertext,
            const SecureBytes& iv,
            const SecureBytes& aad
        ) override {
            if (alg == Algorithm::XChaCha20) {
                if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
                    throw VaultCryptException(ErrorCode::InvalidKey, "Invalid key size for XChaCha20-Poly1305");
                }

                if (iv.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
                    throw VaultCryptException(ErrorCode::InvalidNonce, "Invalid nonce size for XChaCha20-Poly1305");
                }

                if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
                    throw VaultCryptException(ErrorCode::InvalidArgument, "Ciphertext too short");
                }

                SecureBytes plaintext(ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
                unsigned long long plaintext_len;

                int result = crypto_aead_xchacha20poly1305_ietf_decrypt(
                    plaintext.data(), &plaintext_len,
                    nullptr,
                    ciphertext.data(), ciphertext.size(),
                    aad.empty() ? nullptr : aad.data(), aad.size(),
                    iv.data(),
                    key.data()
                );

                if (result != 0) {
                    throw VaultCryptException(ErrorCode::DecryptionFailed, "XChaCha20-Poly1305 decryption/authentication failed");
                }

                plaintext.resize(plaintext_len);
                return plaintext;
            }

            throw VaultCryptException(ErrorCode::UnsupportedAlgorithm, "Algorithm not supported by libsodium backend");
        }

        size_t get_iv_size(Algorithm alg, Mode mode) const override {
            if (alg == Algorithm::XChaCha20) return crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
            return 24;
        }

        size_t get_tag_size(Algorithm alg, Mode mode) const override {
            return crypto_aead_xchacha20poly1305_ietf_ABYTES;
        }

        bool is_aead(Mode mode) const override {
            return true;
        }
    };

    std::unique_ptr<CryptoBackend> create_libsodium_backend() {
        return std::make_unique<LibsodiumBackend>();
    }

} // namespace vaultcrypt