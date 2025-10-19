#include <catch2/catch_test_macros.hpp>
#include "vaultcrypt/keystore.h"
#include "vaultcrypt/error.h"
#include <filesystem>

using namespace vaultcrypt;

TEST_CASE("Keystore operations", "[keystore]") {
    const std::string test_keystore = "test_keystore.vks";
    SecureString password = { 't', 'e', 's', 't', 'p', 'a', 's', 's' };

    if (std::filesystem::exists(test_keystore)) {
        std::filesystem::remove(test_keystore);
    }

    SECTION("Create and open keystore") {
        Keystore keystore;

        keystore.create(test_keystore, password);
        keystore.close();

        keystore.open(test_keystore, password);
        keystore.close();

        REQUIRE(std::filesystem::exists(test_keystore));
    }

    SECTION("Add and retrieve key") {
        Keystore keystore;
        keystore.create(test_keystore, password);

        SecureBytes key_data = generate_random(32);
        std::string key_id = keystore.add_key("test_key", key_data, KeyType::Symmetric, "AES-256");

        auto retrieved = keystore.get_key(key_id);
        REQUIRE(retrieved.has_value());
        REQUIRE(*retrieved == key_data);

        keystore.close();
    }

    SECTION("List keys") {
        Keystore keystore;
        keystore.create(test_keystore, password);

        keystore.add_key("key1", generate_random(32), KeyType::Symmetric, "AES-256");
        keystore.add_key("key2", generate_random(32), KeyType::Symmetric, "ChaCha20");

        auto keys = keystore.list_keys();
        REQUIRE(keys.size() == 2);

        keystore.close();
    }

    if (std::filesystem::exists(test_keystore)) {
        std::filesystem::remove(test_keystore);
    }
}