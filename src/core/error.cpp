#include "vaultcrypt/error.h"

namespace vaultcrypt {

    VaultCryptException::VaultCryptException(ErrorCode code, const std::string& message)
        : std::runtime_error(std::string(error_code_string(code)) + ": " + message)
        , code_(code) {
    }

    const char* error_code_string(ErrorCode code) {
        switch (code) {
        case ErrorCode::Success: return "Success";
        case ErrorCode::InvalidArgument: return "Invalid argument";
        case ErrorCode::InvalidKey: return "Invalid key";
        case ErrorCode::InvalidNonce: return "Invalid nonce";
        case ErrorCode::InvalidTag: return "Invalid authentication tag";
        case ErrorCode::DecryptionFailed: return "Decryption failed";
        case ErrorCode::EncryptionFailed: return "Encryption failed";
        case ErrorCode::KeystoreError: return "Keystore error";
        case ErrorCode::FileIOError: return "File I/O error";
        case ErrorCode::UnsupportedAlgorithm: return "Unsupported algorithm";
        case ErrorCode::UnsupportedMode: return "Unsupported mode";
        case ErrorCode::LibraryError: return "Cryptographic library error";
        case ErrorCode::MemoryError: return "Memory allocation error";
        case ErrorCode::NonceReuseDetected: return "Nonce reuse detected";
        default: return "Unknown error";
        }
    }

} // namespace vaultcrypt