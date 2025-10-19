#include "vaultcrypt/keystore.h"
#include "vaultcrypt/error.h"
#include "vaultcrypt/logger.h"
#include "vaultcrypt/aead.h"
#include "vaultcrypt/file_io.h"
#include <nlohmann/json.hpp>
#include <chrono>
#include <map>
#include <sstream>
#include <iomanip>

using json = nlohmann::json;

namespace vaultcrypt {

    struct KeyEntry {
        std::string id;
        KeyMetadata metadata;
        SecureBytes encrypted_key;
        SecureBytes salt;
    };

    class Keystore::Impl {
    public:
        void create(const std::string& path, const SecureString& master_password) {
            if (is_open_) {
                throw VaultCryptException(ErrorCode::KeystoreError, "Keystore already open");
            }

            path_ = path;
            master_password_ = master_password;
            entries_.clear();
            master_salt_ = generate_random(32);

            save();
            is_open_ = true;
            LOG_INFO("Created new keystore: " + path);
        }

        void open(const std::string& path, const SecureString& master_password) {
            if (is_open_) {
                throw VaultCryptException(ErrorCode::KeystoreError, "Keystore already open");
            }

            path_ = path;
            master_password_ = master_password;

            load();
            is_open_ = true;
            LOG_INFO("Opened keystore: " + path);
        }

        void close() {
            if (!is_open_) return;

            entries_.clear();
            secure_zero(const_cast<char*>(master_password_.data()), master_password_.size());
            master_password_.clear();
            secure_zero(master_salt_.data(), master_salt_.size());
            master_salt_.clear();

            is_open_ = false;
            LOG_INFO("Closed keystore");
        }

        std::string add_key(const std::string& name, const SecureBytes& key_data,
            KeyType type, const std::string& algorithm) {
            if (!is_open_) {
                throw VaultCryptException(ErrorCode::KeystoreError, "Keystore not open");
            }

            std::string id = generate_id();

            SecureBytes salt = generate_random(32);
            KDFParams kdf_params;
            kdf_params.salt = salt;
            kdf_params.type = KDFType::Argon2id;
            kdf_params.iterations = 3;
            kdf_params.memory_kb = 65536;
            kdf_params.parallelism = 4;

            AESGCMCipher cipher;
            SecureBytes encrypted = cipher.encrypt_password(master_password_, key_data, kdf_params);

            KeyEntry entry;
            entry.id = id;
            entry.metadata.id = id;
            entry.metadata.type = type;
            entry.metadata.algorithm = algorithm;
            entry.metadata.created_timestamp = std::chrono::system_clock::now().time_since_epoch().count();
            entry.metadata.tags["name"] = name;
            entry.encrypted_key = encrypted;
            entry.salt = salt;

            entries_[id] = entry;
            save();

            LOG_INFO("Added key to keystore: " + id);
            return id;
        }

        std::optional<SecureBytes> get_key(const std::string& id) {
            if (!is_open_) {
                throw VaultCryptException(ErrorCode::KeystoreError, "Keystore not open");
            }

            auto it = entries_.find(id);
            if (it == entries_.end()) {
                return std::nullopt;
            }

            try {
                AESGCMCipher cipher;
                SecureBytes decrypted = cipher.decrypt_password(master_password_, it->second.encrypted_key);
                LOG_DEBUG("Retrieved key from keystore: " + id);
                return decrypted;
            }
            catch (const VaultCryptException& e) {
                LOG_ERROR("Failed to decrypt key " + id + ": " + e.what());
                throw VaultCryptException(ErrorCode::DecryptionFailed, "Invalid master password or corrupted key");
            }
        }

        KeyMetadata get_metadata(const std::string& id) {
            if (!is_open_) {
                throw VaultCryptException(ErrorCode::KeystoreError, "Keystore not open");
            }

            auto it = entries_.find(id);
            if (it == entries_.end()) {
                throw VaultCryptException(ErrorCode::InvalidArgument, "Key not found: " + id);
            }

            return it->second.metadata;
        }

        std::vector<KeyMetadata> list_keys() {
            if (!is_open_) {
                throw VaultCryptException(ErrorCode::KeystoreError, "Keystore not open");
            }

            std::vector<KeyMetadata> result;
            for (const auto& [id, entry] : entries_) {
                result.push_back(entry.metadata);
            }
            return result;
        }

        bool remove_key(const std::string& id) {
            if (!is_open_) {
                throw VaultCryptException(ErrorCode::KeystoreError, "Keystore not open");
            }

            auto it = entries_.find(id);
            if (it == entries_.end()) {
                return false;
            }

            secure_zero(it->second.encrypted_key.data(), it->second.encrypted_key.size());
            entries_.erase(it);
            save();

            LOG_INFO("Removed key from keystore: " + id);
            return true;
        }

        void change_password(const SecureString& new_password) {
            if (!is_open_) {
                throw VaultCryptException(ErrorCode::KeystoreError, "Keystore not open");
            }

            std::map<std::string, SecureBytes> decrypted_keys;

            for (auto& [id, entry] : entries_) {
                auto key_data = get_key(id);
                if (key_data) {
                    decrypted_keys[id] = *key_data;
                }
            }

            master_password_ = new_password;
            master_salt_ = generate_random(32);

            for (auto& [id, entry] : entries_) {
                auto it = decrypted_keys.find(id);
                if (it != decrypted_keys.end()) {
                    SecureBytes salt = generate_random(32);
                    KDFParams kdf_params;
                    kdf_params.salt = salt;
                    kdf_params.type = KDFType::Argon2id;

                    AESGCMCipher cipher;
                    entry.encrypted_key = cipher.encrypt_password(master_password_, it->second, kdf_params);
                    entry.salt = salt;

                    secure_zero(it->second.data(), it->second.size());
                }
            }

            save();
            LOG_INFO("Changed keystore master password");
        }

    private:
        bool is_open_ = false;
        std::string path_;
        SecureString master_password_;
        SecureBytes master_salt_;
        std::map<std::string, KeyEntry> entries_;

        std::string generate_id() {
            SecureBytes random = generate_random(16);
            std::stringstream ss;
            ss << std::hex << std::setfill('0');
            for (size_t i = 0; i < 16; ++i) {
                ss << std::setw(2) << static_cast<int>(random[i]);
            }
            return ss.str();
        }

        void save() {
            json j;
            j["version"] = 1;
            j["master_salt"] = std::vector<uint8_t>(master_salt_.begin(), master_salt_.end());

            json entries_json = json::array();
            for (const auto& [id, entry] : entries_) {
                json entry_json;
                entry_json["id"] = entry.id;
                entry_json["type"] = static_cast<int>(entry.metadata.type);
                entry_json["algorithm"] = entry.metadata.algorithm;
                entry_json["created"] = entry.metadata.created_timestamp;
                entry_json["tags"] = entry.metadata.tags;
                entry_json["encrypted_key"] = std::vector<uint8_t>(entry.encrypted_key.begin(), entry.encrypted_key.end());
                entry_json["salt"] = std::vector<uint8_t>(entry.salt.begin(), entry.salt.end());
                entries_json.push_back(entry_json);
            }
            j["entries"] = entries_json;

            std::string json_str = j.dump();
            SecureBytes data(json_str.begin(), json_str.end());

            KDFParams kdf_params;
            kdf_params.salt = master_salt_;
            kdf_params.type = KDFType::Argon2id;

            AESGCMCipher cipher;
            SecureBytes encrypted = cipher.encrypt_password(master_password_, data, kdf_params);

            write_file(path_, encrypted, true);
        }

        void load() {
            SecureBytes encrypted = read_file(path_);

            AESGCMCipher cipher;
            SecureBytes decrypted = cipher.decrypt_password(master_password_, encrypted);

            std::string json_str(decrypted.begin(), decrypted.end());
            json j = json::parse(json_str);

            int version = j["version"];
            if (version != 1) {
                throw VaultCryptException(ErrorCode::KeystoreError, "Unsupported keystore version");
            }

            auto salt_vec = j["master_salt"].get<std::vector<uint8_t>>();
            master_salt_ = SecureBytes(salt_vec.begin(), salt_vec.end());

            for (const auto& entry_json : j["entries"]) {
                KeyEntry entry;
                entry.id = entry_json["id"];
                entry.metadata.id = entry.id;
                entry.metadata.type = static_cast<KeyType>(entry_json["type"].get<int>());
                entry.metadata.algorithm = entry_json["algorithm"];
                entry.metadata.created_timestamp = entry_json["created"];
                entry.metadata.tags = entry_json["tags"].get<std::map<std::string, std::string>>();

                auto enc_key_vec = entry_json["encrypted_key"].get<std::vector<uint8_t>>();
                entry.encrypted_key = SecureBytes(enc_key_vec.begin(), enc_key_vec.end());

                auto salt_vec = entry_json["salt"].get<std::vector<uint8_t>>();
                entry.salt = SecureBytes(salt_vec.begin(), salt_vec.end());

                entries_[entry.id] = entry;
            }
        }
    };

    // PUBLIC API IMPLEMENTATIONS
    Keystore::Keystore() : impl_(std::make_unique<Impl>()) {}
    Keystore::~Keystore() = default;

    void Keystore::create(const std::string& path, const SecureString& master_password) {
        impl_->create(path, master_password);
    }

    void Keystore::open(const std::string& path, const SecureString& master_password) {
        impl_->open(path, master_password);
    }

    void Keystore::close() {
        impl_->close();
    }

    std::string Keystore::add_key(const std::string& name, const SecureBytes& key_data,
        KeyType type, const std::string& algorithm) {
        return impl_->add_key(name, key_data, type, algorithm);
    }

    std::optional<SecureBytes> Keystore::get_key(const std::string& id) {
        return impl_->get_key(id);
    }

    KeyMetadata Keystore::get_metadata(const std::string& id) {
        return impl_->get_metadata(id);
    }

    std::vector<KeyMetadata> Keystore::list_keys() {
        return impl_->list_keys();
    }

    bool Keystore::remove_key(const std::string& id) {
        return impl_->remove_key(id);
    }

    void Keystore::change_password(const SecureString& new_password) {
        impl_->change_password(new_password);
    }

} // namespace vaultcrypt