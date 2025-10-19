#include "vaultcrypt/file_io.h"
#include "vaultcrypt/error.h"
#include "vaultcrypt/logger.h"
#include <fstream>
#include <filesystem>

namespace vaultcrypt {

    SecureBytes read_file(const std::string& path) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            throw VaultCryptException(ErrorCode::InvalidArgument, "Cannot open file: " + path);
        }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        SecureBytes buffer(size);
        if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
            throw VaultCryptException(ErrorCode::InvalidArgument, "Cannot read file: " + path);
        }

        LOG_DEBUG("Read " + std::to_string(size) + " bytes from: " + path);
        return buffer;
    }

    void write_file(const std::string& path, const SecureBytes& data, bool overwrite) {
        if (!overwrite && std::filesystem::exists(path)) {
            throw VaultCryptException(ErrorCode::InvalidArgument, "File already exists: " + path);
        }

        LOG_DEBUG("Writing " + std::to_string(data.size()) + " bytes to: " + path);

        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        if (!file.is_open()) {
            throw VaultCryptException(ErrorCode::InvalidArgument, "Cannot create file: " + path);
        }

        if (!file.write(reinterpret_cast<const char*>(data.data()), data.size())) {
            throw VaultCryptException(ErrorCode::InvalidArgument, "Cannot write file: " + path);
        }

        file.close();

        // Verify the file was written
        if (std::filesystem::exists(path)) {
            auto written_size = std::filesystem::file_size(path);
            LOG_DEBUG("File written successfully. Size on disk: " + std::to_string(written_size) + " bytes");

            if (written_size != data.size()) {
                LOG_ERROR("WARNING: Written size mismatch! Expected: " + std::to_string(data.size()) +
                    ", Actual: " + std::to_string(written_size));
            }
        }
    }

} // namespace vaultcrypt