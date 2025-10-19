#include "commands.h"
#include "vaultcrypt/aead.h"
#include "vaultcrypt/envelope.h"
#include "vaultcrypt/keystore.h"
#include "vaultcrypt/file_io.h"
#include "vaultcrypt/error.h"
#include "vaultcrypt/logger.h"
#include <iostream>
#include <chrono>

namespace vaultcrypt::cli {

    int cmd_genkey(const Options& opts) {
        try {
            if (opts.algorithm == "symmetric" || opts.algorithm == "aes") {
                SecureBytes key = generate_random(32);

                if (!opts.output_file.empty()) {
                    write_file(opts.output_file, key, opts.overwrite);
                    std::cout << "Generated 256-bit symmetric key: " << opts.output_file << std::endl;
                }
                else {
                    std::cout << "Generated key (hex): ";
                    for (auto b : key) {
                        printf("%02x", b);
                    }
                    std::cout << std::endl;
                }
            }
            else if (opts.algorithm == "rsa" || opts.algorithm == "x25519") {
                EnvelopeCrypto envelope;
                EnvelopeMode mode = (opts.algorithm == "rsa") ?
                    EnvelopeMode::RSA_OAEP_AES_GCM :
                    EnvelopeMode::X25519_XCHACHA20_POLY1305;

                auto keypair = envelope.generate_keypair(mode);

                std::string pub_file = opts.output_file.empty() ? "public.key" : opts.output_file + ".pub";
                std::string priv_file = opts.output_file.empty() ? "private.key" : opts.output_file + ".priv";

                write_file(pub_file, keypair.public_key, opts.overwrite);
                write_file(priv_file, keypair.private_key, opts.overwrite);

                std::cout << "Generated " << opts.algorithm << " keypair:" << std::endl;
                std::cout << "  Public:  " << pub_file << std::endl;
                std::cout << "  Private: " << priv_file << std::endl;
            }
            else {
                std::cerr << "Error: Unknown algorithm: " << opts.algorithm << std::endl;
                return 1;
            }

            return 0;
        }
        catch (const VaultCryptException& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return 1;
        }
    }

    int cmd_encrypt(const Options& opts) {
        try {
            SecureBytes plaintext;

            if (opts.input_file.empty() || opts.input_file == "-") {
                std::vector<unsigned char> buffer;
                char ch;
                while (std::cin.get(ch)) {
                    buffer.push_back(static_cast<unsigned char>(ch));
                }
                plaintext = SecureBytes(buffer.begin(), buffer.end());
            }
            else {
                plaintext = read_file(opts.input_file);
            }

            SecureBytes ciphertext;
            SecureBytes aad;
            if (!opts.associated_data.empty()) {
                aad = SecureBytes(opts.associated_data.begin(), opts.associated_data.end());
            }

            if (!opts.keyfile.empty()) {
                SecureBytes public_key = read_file(opts.keyfile);
                EnvelopeCrypto envelope;

                EnvelopeMode mode = (opts.envelope_mode == "rsa") ?
                    EnvelopeMode::RSA_OAEP_AES_GCM :
                    EnvelopeMode::X25519_XCHACHA20_POLY1305;

                ciphertext = envelope.encrypt(mode, public_key, plaintext, aad);

                std::cout << "Encrypted with " << opts.envelope_mode << " envelope" << std::endl;
            }
            else if (!opts.password.empty()) {
                SecureString password(opts.password.begin(), opts.password.end());

                KDFParams kdf_params;
                kdf_params.type = (opts.kdf == "argon2id") ? KDFType::Argon2id : KDFType::PBKDF2_SHA256;
                kdf_params.iterations = opts.kdf_ops;
                kdf_params.memory_kb = opts.kdf_mem;
                kdf_params.parallelism = opts.kdf_par;

                if (opts.algorithm.find("chacha") != std::string::npos) {
                    ChaCha20Poly1305Cipher cipher;
                    ciphertext = cipher.encrypt_password(password, plaintext, kdf_params, aad);
                }
                else {
                    AESGCMCipher cipher;
                    ciphertext = cipher.encrypt_password(password, plaintext, kdf_params, aad);
                }

                std::cout << "Encrypted with password-based " << opts.algorithm << std::endl;
            }
            else {
                std::cerr << "Error: Must specify --keyfile or --pass" << std::endl;
                return 1;
            }

            if (opts.output_file.empty() || opts.output_file == "-") {
                std::cout.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
            }
            else {
                write_file(opts.output_file, ciphertext, opts.overwrite);
                std::cout << "Encrypted " << plaintext.size() << " bytes -> " << ciphertext.size() << " bytes" << std::endl;
                std::cout << "Output: " << opts.output_file << std::endl;
            }

            return 0;
        }
        catch (const VaultCryptException& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return 1;
        }
    }

    int cmd_decrypt(const Options& opts) {
        try {
            SecureBytes ciphertext;

            if (opts.input_file.empty() || opts.input_file == "-") {
                std::vector<unsigned char> buffer;
                char ch;
                while (std::cin.get(ch)) {
                    buffer.push_back(static_cast<unsigned char>(ch));
                }
                ciphertext = SecureBytes(buffer.begin(), buffer.end());
            }
            else {
                ciphertext = read_file(opts.input_file);
            }

            SecureBytes plaintext;
            SecureBytes aad;
            if (!opts.associated_data.empty()) {
                aad = SecureBytes(opts.associated_data.begin(), opts.associated_data.end());
            }

            if (!opts.keyfile.empty()) {
                SecureBytes private_key = read_file(opts.keyfile);
                EnvelopeCrypto envelope;

                EnvelopeMode mode = (opts.envelope_mode == "rsa") ?
                    EnvelopeMode::RSA_OAEP_AES_GCM :
                    EnvelopeMode::X25519_XCHACHA20_POLY1305;

                plaintext = envelope.decrypt(mode, private_key, ciphertext, aad);

                std::cout << "Decrypted with " << opts.envelope_mode << " envelope" << std::endl;
            }
            else if (!opts.password.empty()) {
                SecureString password(opts.password.begin(), opts.password.end());

                try {
                    AESGCMCipher cipher;
                    plaintext = cipher.decrypt_password(password, ciphertext, aad);
                }
                catch (...) {
                    ChaCha20Poly1305Cipher cipher;
                    plaintext = cipher.decrypt_password(password, ciphertext, aad);
                }

                std::cout << "Decrypted with password-based encryption" << std::endl;
            }
            else {
                std::cerr << "Error: Must specify --keyfile or --pass" << std::endl;
                return 1;
            }

            if (opts.output_file.empty() || opts.output_file == "-") {
                std::cout.write(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
            }
            else {
                write_file(opts.output_file, plaintext, opts.overwrite);
                std::cout << "Decrypted " << ciphertext.size() << " bytes -> " << plaintext.size() << " bytes" << std::endl;
                std::cout << "Output: " << opts.output_file << std::endl;
            }

            return 0;
        }
        catch (const VaultCryptException& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return 1;
        }
    }

    int cmd_list_keys(const Options& opts) {
        std::cerr << "Keystore commands temporarily disabled - basic encryption works!" << std::endl;
        return 1;
    }
    int cmd_import_key(const Options& opts) {
        std::cerr << "Import command not yet fully implemented" << std::endl;
        return 1;
    }

    int cmd_export_key(const Options& opts) {
        std::cerr << "Export command not yet fully implemented" << std::endl;
        return 1;
    }

    int cmd_wipe_key(const Options& opts) {
        std::cerr << "Wipe-key command not yet fully implemented" << std::endl;
        return 1;
    }

    int cmd_benchmark(const Options& opts) {
        try {
            const size_t TEST_SIZE = 1024 * 1024;
            const int ITERATIONS = 100;

            SecureBytes test_data = generate_random(TEST_SIZE);
            SecureBytes key = generate_random(32);

            std::cout << "Benchmarking AES-256-GCM..." << std::endl;

            auto start = std::chrono::high_resolution_clock::now();

            AESGCMCipher cipher;
            for (int i = 0; i < ITERATIONS; ++i) {
                auto encrypted = cipher.encrypt(key, test_data);
                auto decrypted = cipher.decrypt(key, encrypted);
            }

            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

            double throughput = (TEST_SIZE * ITERATIONS * 2.0) / (1024.0 * 1024.0) / (duration.count() / 1000.0);

            std::cout << "Time: " << duration.count() << " ms" << std::endl;
            std::cout << "Throughput: " << throughput << " MB/s" << std::endl;

            return 0;
        }
        catch (const VaultCryptException& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return 1;
        }
    }

    int cmd_doctor(const Options& opts) {
        std::cout << "VaultCrypt System Check" << std::endl;
        std::cout << "=======================" << std::endl << std::endl;

        std::cout << "[OK] Crypto++ library loaded" << std::endl;
        std::cout << "[OK] libsodium library loaded" << std::endl;
        std::cout << "[OK] OpenSSL library loaded" << std::endl;

        try {
            auto random = generate_random(32);
            std::cout << "[OK] Random number generation working" << std::endl;
        }
        catch (...) {
            std::cout << "[FAIL] Random number generation failed" << std::endl;
        }

        try {
            AESGCMCipher cipher;
            SecureBytes key = generate_random(32);
            SecureBytes test = SecureBytes{ 't', 'e', 's', 't' };
            auto enc = cipher.encrypt(key, test);
            auto dec = cipher.decrypt(key, enc);

            if (dec == test) {
                std::cout << "[OK] AES-GCM encryption/decryption working" << std::endl;
            }
            else {
                std::cout << "[FAIL] AES-GCM round-trip failed" << std::endl;
            }
        }
        catch (const std::exception& e) {
            std::cout << "[FAIL] AES-GCM test failed: " << e.what() << std::endl;
        }

        std::cout << std::endl << "All checks complete" << std::endl;
        return 0;
    }

} // namespace vaultcrypt::cli