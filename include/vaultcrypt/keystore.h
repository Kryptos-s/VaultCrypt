#pragma once

#include "secure_memory.h"
#include "crypto_backend.h"
#include <string>
#include <map>
#include <optional>
#include <vector>
#include <memory>

namespace vaultcrypt {

    enum class KeyType {
        Symmetric,
        PublicKey,
        PrivateKey
    };

    struct KeyMetadata {
        std::string id;
        KeyType type;
        std::string algorithm;
        uint64_t created_timestamp;
        std::map<std::string, std::string> tags;
    };

    class Keystore {
    public:
        Keystore();
        ~Keystore();

        void create(const std::string& path, const SecureString& master_password);
        void open(const std::string& path, const SecureString& master_password);
        void close();

        std::string add_key(const std::string& name, const SecureBytes& key_data,
            KeyType type, const std::string& algorithm);
        std::optional<SecureBytes> get_key(const std::string& id);
        KeyMetadata get_metadata(const std::string& id);
        std::vector<KeyMetadata> list_keys();
        bool remove_key(const std::string& id);

        void change_password(const SecureString& new_password);

    private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };

} // namespace vaultcrypt