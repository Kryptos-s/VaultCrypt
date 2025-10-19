#include "vaultcrypt/envelope.h"
#include "vaultcrypt/error.h"
#include "vaultcrypt/logger.h"
#include "vaultcrypt/aead.h"
#include "vaultcrypt/crypto_backend.h"
#include <sodium.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

namespace vaultcrypt {

    class EnvelopeCrypto::Impl {
    public:
        Impl() {
            if (sodium_init() < 0) {
                throw VaultCryptException(ErrorCode::LibraryError, "Failed to initialize libsodium");
            }
        }

        EnvelopeCrypto::KeyPair generate_x25519_keypair() {
            SecureBytes public_key(crypto_box_PUBLICKEYBYTES);
            SecureBytes private_key(crypto_box_SECRETKEYBYTES);

            crypto_box_keypair(public_key.data(), private_key.data());

            return { public_key, private_key };
        }

        EnvelopeCrypto::KeyPair generate_rsa_keypair() {
            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
            if (!ctx) {
                throw VaultCryptException(ErrorCode::LibraryError, "Failed to create RSA context");
            }

            if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 4096) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                throw VaultCryptException(ErrorCode::LibraryError, "Failed to initialize RSA keygen");
            }

            EVP_PKEY* pkey = nullptr;
            if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                throw VaultCryptException(ErrorCode::LibraryError, "RSA key generation failed");
            }

            EVP_PKEY_CTX_free(ctx);

            BIO* bio_pub = BIO_new(BIO_s_mem());
            BIO* bio_priv = BIO_new(BIO_s_mem());

            PEM_write_bio_PUBKEY(bio_pub, pkey);
            PEM_write_bio_PrivateKey(bio_priv, pkey, nullptr, nullptr, 0, nullptr, nullptr);

            char* pub_data;
            long pub_len = BIO_get_mem_data(bio_pub, &pub_data);
            SecureBytes public_key(pub_data, pub_data + pub_len);

            char* priv_data;
            long priv_len = BIO_get_mem_data(bio_priv, &priv_data);
            SecureBytes private_key(priv_data, priv_data + priv_len);

            BIO_free(bio_pub);
            BIO_free(bio_priv);
            EVP_PKEY_free(pkey);

            return { public_key, private_key };
        }

        SecureBytes encrypt_x25519_xchacha20(
            const SecureBytes& public_key,
            const SecureBytes& plaintext,
            const SecureBytes& aad
        ) {
            if (public_key.size() != crypto_box_PUBLICKEYBYTES) {
                throw VaultCryptException(ErrorCode::InvalidKey, "Invalid X25519 public key size");
            }

            SecureBytes ephemeral_public(crypto_box_PUBLICKEYBYTES);
            SecureBytes ephemeral_secret(crypto_box_SECRETKEYBYTES);
            crypto_box_keypair(ephemeral_public.data(), ephemeral_secret.data());

            SecureBytes shared_key(crypto_box_BEFORENMBYTES);
            crypto_box_beforenm(shared_key.data(), public_key.data(), ephemeral_secret.data());

            ChaCha20Poly1305Cipher cipher;
            SecureBytes encrypted_data = cipher.encrypt(shared_key, plaintext, aad);
            secure_zero(shared_key.data(), shared_key.size());
            secure_zero(ephemeral_secret.data(), ephemeral_secret.size());

            EnvelopeHeader header{};
            header.version = htonl(1);
            header.mode = static_cast<uint8_t>(EnvelopeMode::X25519_XCHACHA20_POLY1305);
            header.encrypted_key_length = htonl(static_cast<uint32_t>(ephemeral_public.size()));
            header.aad_length = htonl(static_cast<uint32_t>(aad.size()));

            SecureBytes result;
            result.insert(result.end(),
                reinterpret_cast<const unsigned char*>(&header),
                reinterpret_cast<const unsigned char*>(&header) + sizeof(header));
            result.insert(result.end(), ephemeral_public.begin(), ephemeral_public.end());
            result.insert(result.end(), aad.begin(), aad.end());
            result.insert(result.end(), encrypted_data.begin(), encrypted_data.end());

            LOG_INFO("X25519+XChaCha20-Poly1305 envelope encryption complete");
            return result;
        }

        SecureBytes decrypt_x25519_xchacha20(
            const SecureBytes& private_key,
            const SecureBytes& ciphertext,
            const SecureBytes& aad
        ) {
            if (private_key.size() != crypto_box_SECRETKEYBYTES) {
                throw VaultCryptException(ErrorCode::InvalidKey, "Invalid X25519 private key size");
            }

            if (ciphertext.size() < sizeof(EnvelopeHeader)) {
                throw VaultCryptException(ErrorCode::InvalidArgument, "Invalid envelope");
            }

            EnvelopeHeader header;
            std::memcpy(&header, ciphertext.data(), sizeof(header));

            uint32_t ephemeral_key_len = ntohl(header.encrypted_key_length);
            uint32_t aad_len = ntohl(header.aad_length);

            size_t offset = sizeof(header);
            SecureBytes ephemeral_public(ciphertext.begin() + offset,
                ciphertext.begin() + offset + ephemeral_key_len);
            offset += ephemeral_key_len;

            SecureBytes stored_aad(ciphertext.begin() + offset,
                ciphertext.begin() + offset + aad_len);
            offset += aad_len;

            SecureBytes encrypted_data(ciphertext.begin() + offset, ciphertext.end());

            SecureBytes shared_key(crypto_box_BEFORENMBYTES);
            crypto_box_beforenm(shared_key.data(), ephemeral_public.data(), private_key.data());

            ChaCha20Poly1305Cipher cipher;
            SecureBytes plaintext = cipher.decrypt(shared_key, encrypted_data, aad.empty() ? stored_aad : aad);
            secure_zero(shared_key.data(), shared_key.size());

            LOG_INFO("X25519+XChaCha20-Poly1305 envelope decryption complete");
            return plaintext;
        }

        SecureBytes encrypt_rsa_oaep_aes_gcm(
            const SecureBytes& public_key,
            const SecureBytes& plaintext,
            const SecureBytes& aad
        ) {
            SecureBytes aes_key = generate_random(32);

            AESGCMCipher aes;
            SecureBytes encrypted_data = aes.encrypt(aes_key, plaintext, aad);

            BIO* bio = BIO_new_mem_buf(public_key.data(), static_cast<int>(public_key.size()));
            EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);

            if (!pkey) {
                throw VaultCryptException(ErrorCode::InvalidKey, "Invalid RSA public key");
            }

            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
            EVP_PKEY_encrypt_init(ctx);
            EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

            size_t encrypted_key_len;
            EVP_PKEY_encrypt(ctx, nullptr, &encrypted_key_len, aes_key.data(), aes_key.size());

            SecureBytes encrypted_key(encrypted_key_len);
            EVP_PKEY_encrypt(ctx, encrypted_key.data(), &encrypted_key_len, aes_key.data(), aes_key.size());

            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            secure_zero(aes_key.data(), aes_key.size());

            EnvelopeHeader header{};
            header.version = htonl(1);
            header.mode = static_cast<uint8_t>(EnvelopeMode::RSA_OAEP_AES_GCM);
            header.encrypted_key_length = htonl(static_cast<uint32_t>(encrypted_key.size()));
            header.aad_length = htonl(static_cast<uint32_t>(aad.size()));

            SecureBytes result;
            result.insert(result.end(),
                reinterpret_cast<const unsigned char*>(&header),
                reinterpret_cast<const unsigned char*>(&header) + sizeof(header));
            result.insert(result.end(), encrypted_key.begin(), encrypted_key.end());
            result.insert(result.end(), aad.begin(), aad.end());
            result.insert(result.end(), encrypted_data.begin(), encrypted_data.end());

            LOG_INFO("RSA-OAEP+AES-GCM envelope encryption complete");
            return result;
        }

        SecureBytes decrypt_rsa_oaep_aes_gcm(
            const SecureBytes& private_key,
            const SecureBytes& ciphertext,
            const SecureBytes& aad
        ) {
            if (ciphertext.size() < sizeof(EnvelopeHeader)) {
                throw VaultCryptException(ErrorCode::InvalidArgument, "Invalid envelope");
            }

            EnvelopeHeader header;
            std::memcpy(&header, ciphertext.data(), sizeof(header));

            uint32_t encrypted_key_len = ntohl(header.encrypted_key_length);
            uint32_t aad_len = ntohl(header.aad_length);

            size_t offset = sizeof(header);
            SecureBytes encrypted_key(ciphertext.begin() + offset,
                ciphertext.begin() + offset + encrypted_key_len);
            offset += encrypted_key_len;

            SecureBytes stored_aad(ciphertext.begin() + offset,
                ciphertext.begin() + offset + aad_len);
            offset += aad_len;

            SecureBytes encrypted_data(ciphertext.begin() + offset, ciphertext.end());

            BIO* bio = BIO_new_mem_buf(private_key.data(), static_cast<int>(private_key.size()));
            EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);

            if (!pkey) {
                throw VaultCryptException(ErrorCode::InvalidKey, "Invalid RSA private key");
            }

            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
            EVP_PKEY_decrypt_init(ctx);
            EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

            size_t aes_key_len;
            EVP_PKEY_decrypt(ctx, nullptr, &aes_key_len, encrypted_key.data(), encrypted_key.size());

            SecureBytes aes_key(aes_key_len);
            if (EVP_PKEY_decrypt(ctx, aes_key.data(), &aes_key_len, encrypted_key.data(), encrypted_key.size()) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                EVP_PKEY_free(pkey);
                throw VaultCryptException(ErrorCode::DecryptionFailed, "Failed to decrypt envelope key");
            }

            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);

            AESGCMCipher aes;
            SecureBytes plaintext = aes.decrypt(aes_key, encrypted_data, aad.empty() ? stored_aad : aad);
            secure_zero(aes_key.data(), aes_key.size());

            LOG_INFO("RSA-OAEP+AES-GCM envelope decryption complete");
            return plaintext;
        }
    };

    EnvelopeCrypto::EnvelopeCrypto() : impl_(std::make_unique<Impl>()) {}

    EnvelopeCrypto::~EnvelopeCrypto() = default;

    EnvelopeCrypto::KeyPair EnvelopeCrypto::generate_keypair(EnvelopeMode mode) {
        switch (mode) {
        case EnvelopeMode::RSA_OAEP_AES_GCM:
            return impl_->generate_rsa_keypair();
        case EnvelopeMode::X25519_XCHACHA20_POLY1305:
            return impl_->generate_x25519_keypair();
        default:
            throw VaultCryptException(ErrorCode::UnsupportedAlgorithm, "Unknown envelope mode");
        }
    }

    SecureBytes EnvelopeCrypto::encrypt(
        EnvelopeMode mode,
        const SecureBytes& public_key,
        const SecureBytes& plaintext,
        const SecureBytes& aad
    ) {
        switch (mode) {
        case EnvelopeMode::RSA_OAEP_AES_GCM:
            return impl_->encrypt_rsa_oaep_aes_gcm(public_key, plaintext, aad);
        case EnvelopeMode::X25519_XCHACHA20_POLY1305:
            return impl_->encrypt_x25519_xchacha20(public_key, plaintext, aad);
        default:
            throw VaultCryptException(ErrorCode::UnsupportedAlgorithm, "Unknown envelope mode");
        }
    }

    SecureBytes EnvelopeCrypto::decrypt(
        EnvelopeMode mode,
        const SecureBytes& private_key,
        const SecureBytes& ciphertext,
        const SecureBytes& aad
    ) {
        switch (mode) {
        case EnvelopeMode::RSA_OAEP_AES_GCM:
            return impl_->decrypt_rsa_oaep_aes_gcm(private_key, ciphertext, aad);
        case EnvelopeMode::X25519_XCHACHA20_POLY1305:
            return impl_->decrypt_x25519_xchacha20(private_key, ciphertext, aad);
        default:
            throw VaultCryptException(ErrorCode::UnsupportedAlgorithm, "Unknown envelope mode");
        }
    }

} // namespace vaultcrypt