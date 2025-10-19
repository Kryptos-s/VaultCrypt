#include "vaultcrypt/aead.h"
#include "vaultcrypt/error.h"
#include "vaultcrypt/crypto_backend.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#endif

#include <cstring>

namespace vaultcrypt {

    ChaCha20Poly1305Cipher::ChaCha20Poly1305Cipher() : backend_(create_libsodium_backend()) {}
    ChaCha20Poly1305Cipher::~ChaCha20Poly1305Cipher() = default;

    SecureBytes ChaCha20Poly1305Cipher::encrypt(
        const SecureBytes& key,
        const SecureBytes& plaintext,
        const SecureBytes& aad
    ) {
        if (key.size() != KEY_SIZE) {
            throw VaultCryptException(ErrorCode::InvalidKey, "Invalid key size for XChaCha20-Poly1305");
        }

        SecureBytes nonce = generate_random(NONCE_SIZE);

        AEADHeader header = {};
        header.version = htonl(1);
        header.algorithm = static_cast<uint8_t>(Algorithm::XChaCha20);
        header.mode = static_cast<uint8_t>(Mode::GCM);
        header.nonce_length = htonl(NONCE_SIZE);
        header.tag_length = htonl(TAG_SIZE);
        header.aad_length = htonl(static_cast<uint32_t>(aad.size()));

        SecureBytes ciphertext_with_tag = backend_->encrypt(
            Algorithm::XChaCha20,
            Mode::GCM,
            key,
            plaintext,
            nonce,
            aad
        );

        SecureBytes result;
        result.reserve(sizeof(header) + nonce.size() + ciphertext_with_tag.size());

        result.insert(result.end(),
            reinterpret_cast<const unsigned char*>(&header),
            reinterpret_cast<const unsigned char*>(&header) + sizeof(header));

        result.insert(result.end(), nonce.begin(), nonce.end());
        result.insert(result.end(), ciphertext_with_tag.begin(), ciphertext_with_tag.end());

        return result;
    }

    SecureBytes ChaCha20Poly1305Cipher::decrypt(
        const SecureBytes& key,
        const SecureBytes& ciphertext,
        const SecureBytes& aad
    ) {
        if (key.size() != KEY_SIZE) {
            throw VaultCryptException(ErrorCode::InvalidKey, "Invalid key size");
        }

        if (ciphertext.size() < sizeof(AEADHeader) + NONCE_SIZE + TAG_SIZE) {
            throw VaultCryptException(ErrorCode::InvalidArgument, "Ciphertext too short");
        }

        AEADHeader header;
        std::memcpy(&header, ciphertext.data(), sizeof(header));

        uint32_t nonce_len = ntohl(header.nonce_length);

        if (nonce_len != NONCE_SIZE) {
            throw VaultCryptException(ErrorCode::InvalidArgument, "Invalid nonce length");
        }

        SecureBytes nonce(ciphertext.begin() + sizeof(header),
            ciphertext.begin() + sizeof(header) + nonce_len);

        SecureBytes ciphertext_with_tag(ciphertext.begin() + sizeof(header) + nonce_len,
            ciphertext.end());

        return backend_->decrypt(
            Algorithm::XChaCha20,
            Mode::GCM,
            key,
            ciphertext_with_tag,
            nonce,
            aad
        );
    }

    // PASSWORD-BASED ENCRYPTION - SIMPLIFIED FORMAT
    SecureBytes ChaCha20Poly1305Cipher::encrypt_password(
        const SecureString& password,
        const SecureBytes& plaintext,
        const KDFParams& kdf_params,
        const SecureBytes& aad
    ) {
        // Generate salt if not provided
        SecureBytes salt = kdf_params.salt.empty() ? generate_random(32) : kdf_params.salt;

        // Store KDF parameters
        KDFParams params = kdf_params;
        params.salt = salt;

        // Derive key from password using KDF
        SecureBytes key = derive_key(password, params, KEY_SIZE);

        // Encrypt with the derived key
        SecureBytes encrypted = encrypt(key, plaintext, aad);

        // Zero the key from memory
        secure_zero(key.data(), key.size());

        // Simple format: [salt_length (4 bytes)][salt][kdf_type (2)][iterations (4)][memory (4)][encrypted data]
        SecureBytes result;
        uint32_t salt_len = static_cast<uint32_t>(salt.size());

        // Write salt length (big-endian, 4 bytes)
        result.push_back((salt_len >> 24) & 0xFF);
        result.push_back((salt_len >> 16) & 0xFF);
        result.push_back((salt_len >> 8) & 0xFF);
        result.push_back(salt_len & 0xFF);

        // Write salt
        result.insert(result.end(), salt.begin(), salt.end());

        // Write KDF parameters
        uint16_t kdf_type = static_cast<uint16_t>(params.type);
        result.push_back((kdf_type >> 8) & 0xFF);
        result.push_back(kdf_type & 0xFF);

        uint32_t iterations = params.iterations;
        result.push_back((iterations >> 24) & 0xFF);
        result.push_back((iterations >> 16) & 0xFF);
        result.push_back((iterations >> 8) & 0xFF);
        result.push_back(iterations & 0xFF);

        uint32_t memory = params.memory_kb;
        result.push_back((memory >> 24) & 0xFF);
        result.push_back((memory >> 16) & 0xFF);
        result.push_back((memory >> 8) & 0xFF);
        result.push_back(memory & 0xFF);

        // Write encrypted data
        result.insert(result.end(), encrypted.begin(), encrypted.end());

        return result;
    }

    // PASSWORD-BASED DECRYPTION
    SecureBytes ChaCha20Poly1305Cipher::decrypt_password(
        const SecureString& password,
        const SecureBytes& ciphertext,
        const SecureBytes& aad
    ) {
        // Minimum size: 4 (salt_len) + 1 (min salt) + 2 (kdf_type) + 4 (iterations) + 4 (memory) + encrypted data
        if (ciphertext.size() < 15) {
            throw VaultCryptException(ErrorCode::InvalidArgument, "Ciphertext too short");
        }

        size_t offset = 0;

        // Read salt length
        uint32_t salt_len =
            (static_cast<uint32_t>(ciphertext[offset++]) << 24) |
            (static_cast<uint32_t>(ciphertext[offset++]) << 16) |
            (static_cast<uint32_t>(ciphertext[offset++]) << 8) |
            static_cast<uint32_t>(ciphertext[offset++]);

        if (ciphertext.size() < 4 + salt_len + 10) {
            throw VaultCryptException(ErrorCode::InvalidArgument, "Invalid salt length");
        }

        // Extract salt
        SecureBytes salt(ciphertext.begin() + offset, ciphertext.begin() + offset + salt_len);
        offset += salt_len;

        // Read KDF parameters
        uint16_t kdf_type_raw =
            (static_cast<uint16_t>(ciphertext[offset++]) << 8) |
            static_cast<uint16_t>(ciphertext[offset++]);

        uint32_t iterations =
            (static_cast<uint32_t>(ciphertext[offset++]) << 24) |
            (static_cast<uint32_t>(ciphertext[offset++]) << 16) |
            (static_cast<uint32_t>(ciphertext[offset++]) << 8) |
            static_cast<uint32_t>(ciphertext[offset++]);

        uint32_t memory =
            (static_cast<uint32_t>(ciphertext[offset++]) << 24) |
            (static_cast<uint32_t>(ciphertext[offset++]) << 16) |
            (static_cast<uint32_t>(ciphertext[offset++]) << 8) |
            static_cast<uint32_t>(ciphertext[offset++]);

        // Extract encrypted data
        SecureBytes encrypted(ciphertext.begin() + offset, ciphertext.end());

        // Set up KDF params
        KDFParams params;
        params.salt = salt;
        params.type = static_cast<KDFType>(kdf_type_raw);
        params.iterations = iterations;
        params.memory_kb = memory;
        params.parallelism = 4;

        // Derive key from password
        SecureBytes key = derive_key(password, params, KEY_SIZE);

        // Decrypt
        SecureBytes plaintext = decrypt(key, encrypted, aad);

        // Zero the key
        secure_zero(key.data(), key.size());

        return plaintext;
    }

} // namespace vaultcrypt