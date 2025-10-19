#pragma once

#include <string>
#include <map>

namespace vaultcrypt::cli {

    struct Options {
        std::string command;
        std::string algorithm = "aes-256-gcm";
        std::string keyfile;
        std::string password;
        std::string kdf = "argon2id";
        uint32_t kdf_ops = 3;
        uint32_t kdf_mem = 65536;
        uint32_t kdf_par = 4;
        std::string input_file;
        std::string output_file;
        std::string associated_data;
        bool overwrite = false;
        std::string keystore_path;
        std::string key_id;
        std::string key_name;
        std::string envelope_mode = "x25519";
        bool verbose = false;
    };

    int cmd_genkey(const Options& opts);
    int cmd_encrypt(const Options& opts);
    int cmd_decrypt(const Options& opts);
    int cmd_list_keys(const Options& opts);
    int cmd_import_key(const Options& opts);
    int cmd_export_key(const Options& opts);
    int cmd_wipe_key(const Options& opts);
    int cmd_benchmark(const Options& opts);
    int cmd_doctor(const Options& opts);

} // namespace vaultcrypt::cli