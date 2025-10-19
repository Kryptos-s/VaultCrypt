#pragma once

#include <string>
#include <stdexcept>

namespace vaultcrypt {

    enum class ErrorCode {
        Success = 0,
        InvalidArgument,
        InvalidKey,
        InvalidNonce,
        InvalidTag,
        DecryptionFailed,
        EncryptionFailed,
        KeystoreError,
        FileIOError,
        UnsupportedAlgorithm,
        UnsupportedMode,
        LibraryError,
        MemoryError,
        NonceReuseDetected
    };

    class VaultCryptException : public std::runtime_error {
    public:
        explicit VaultCryptException(ErrorCode code, const std::string& message);
        ErrorCode code() const noexcept { return code_; }
    private:
        ErrorCode code_;
    };

    const char* error_code_string(ErrorCode code);

} // namespace vaultcrypt