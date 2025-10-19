#include "commands.h"
#include "vaultcrypt/version.h"
#include "vaultcrypt/logger.h"
#include <iostream>
#include <cstring>

using namespace vaultcrypt::cli;

void print_usage() {
    std::cout << "VaultCrypt v" << VAULTCRYPT_VERSION << " - Production-Grade Encryption Tool\n\n";
    std::cout << "Usage: vaultcrypt <command> [options]\n\n";
    std::cout << "Commands:\n";
    std::cout << "  genkey      Generate encryption keys\n";
    std::cout << "  encrypt     Encrypt data\n";
    std::cout << "  decrypt     Decrypt data\n";
    std::cout << "  list-keys   List keys in keystore\n";
    std::cout << "  import      Import key to keystore\n";
    std::cout << "  export      Export key from keystore\n";
    std::cout << "  wipe-key    Securely delete key from keystore\n";
    std::cout << "  benchmark   Run performance benchmarks\n";
    std::cout << "  doctor      Run system diagnostics\n\n";
    std::cout << "Options:\n";
    std::cout << "  --alg <algorithm>       Algorithm (aes-256-gcm, xchacha20, rsa, x25519)\n";
    std::cout << "  --keyfile <file>        Key file path\n";
    std::cout << "  --pass <password>       Password for encryption\n";
    std::cout << "  --kdf <type>            KDF (argon2id, pbkdf2)\n";
    std::cout << "  --kdf-ops <n>           KDF iterations/time cost\n";
    std::cout << "  --kdf-mem <kb>          KDF memory cost (KB)\n";
    std::cout << "  --kdf-par <n>           KDF parallelism\n";
    std::cout << "  --in <file>             Input file (or stdin with -)\n";
    std::cout << "  --out <file>            Output file (or stdout with -)\n";
    std::cout << "  --ad <data>             Associated data for AEAD\n";
    std::cout << "  --overwrite             Overwrite existing files\n";
    std::cout << "  --keystore <file>       Keystore file path\n";
    std::cout << "  --key-id <id>           Key identifier\n";
    std::cout << "  --key-name <name>       Key name\n";
    std::cout << "  --envelope <mode>       Envelope mode (rsa, x25519)\n";
    std::cout << "  --verbose               Verbose output\n";
    std::cout << "  --help                  Show this help\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    Options opts;
    opts.command = argv[1];

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            print_usage();
            return 0;
        }
        else if (arg == "--alg" && i + 1 < argc) {
            opts.algorithm = argv[++i];
        }
        else if (arg == "--keyfile" && i + 1 < argc) {
            opts.keyfile = argv[++i];
        }
        else if (arg == "--pass" && i + 1 < argc) {
            opts.password = argv[++i];
        }
        else if (arg == "--kdf" && i + 1 < argc) {
            opts.kdf = argv[++i];
        }
        else if (arg == "--kdf-ops" && i + 1 < argc) {
            opts.kdf_ops = std::stoul(argv[++i]);
        }
        else if (arg == "--kdf-mem" && i + 1 < argc) {
            opts.kdf_mem = std::stoul(argv[++i]);
        }
        else if (arg == "--kdf-par" && i + 1 < argc) {
            opts.kdf_par = std::stoul(argv[++i]);
        }
        else if (arg == "--in" && i + 1 < argc) {
            opts.input_file = argv[++i];
        }
        else if (arg == "--out" && i + 1 < argc) {
            opts.output_file = argv[++i];
        }
        else if (arg == "--ad" && i + 1 < argc) {
            opts.associated_data = argv[++i];
        }
        else if (arg == "--overwrite") {
            opts.overwrite = true;
        }
        else if (arg == "--keystore" && i + 1 < argc) {
            opts.keystore_path = argv[++i];
        }
        else if (arg == "--key-id" && i + 1 < argc) {
            opts.key_id = argv[++i];
        }
        else if (arg == "--key-name" && i + 1 < argc) {
            opts.key_name = argv[++i];
        }
        else if (arg == "--envelope" && i + 1 < argc) {
            opts.envelope_mode = argv[++i];
        }
        else if (arg == "--verbose" || arg == "-v") {
            opts.verbose = true;
            vaultcrypt::Logger::instance().set_level(vaultcrypt::LogLevel::Debug);
        }
    }

    if (opts.command == "genkey") {
        return cmd_genkey(opts);
    }
    else if (opts.command == "encrypt") {
        return cmd_encrypt(opts);
    }
    else if (opts.command == "decrypt") {
        return cmd_decrypt(opts);
    }
    else if (opts.command == "list-keys") {
        return cmd_list_keys(opts);
    }
    else if (opts.command == "import") {
        return cmd_import_key(opts);
    }
    else if (opts.command == "export") {
        return cmd_export_key(opts);
    }
    else if (opts.command == "wipe-key") {
        return cmd_wipe_key(opts);
    }
    else if (opts.command == "benchmark") {
        return cmd_benchmark(opts);
    }
    else if (opts.command == "doctor") {
        return cmd_doctor(opts);
    }
    else {
        std::cerr << "Unknown command: " << opts.command << std::endl;
        print_usage();
        return 1;
    }
}