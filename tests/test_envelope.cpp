#include <catch2/catch_test_macros.hpp>
#include "vaultcrypt/envelope.h"
#include "vaultcrypt/error.h"

using namespace vaultcrypt;

TEST_CASE("X25519 envelope encryption", "[envelope][x25519]") {
    EnvelopeCrypto envelope;

    SECTION("Key generation") {
        auto keypair = envelope.generate_keypair(EnvelopeMode::X25519_XCHACHA20_POLY1305);

        REQUIRE(keypair.public_key.size() == 32);
        REQUIRE(keypair.private_key.size() == 32);
    }

    SECTION("Encrypt and decrypt") {
        auto keypair = envelope.generate_keypair(EnvelopeMode::X25519_XCHACHA20_POLY1305);
        SecureBytes plaintext = { 'T', 'e', 's', 't', ' ', 'd', 'a', 't', 'a' };

        SecureBytes ciphertext = envelope.encrypt(
            EnvelopeMode::X25519_XCHACHA20_POLY1305,
            keypair.public_key,
            plaintext
        );

        SecureBytes decrypted = envelope.decrypt(
            EnvelopeMode::X25519_XCHACHA20_POLY1305,
            keypair.private_key,
            ciphertext
        );

        REQUIRE(decrypted == plaintext);
    }

    SECTION("Wrong private key fails") {
        auto keypair1 = envelope.generate_keypair(EnvelopeMode::X25519_XCHACHA20_POLY1305);
        auto keypair2 = envelope.generate_keypair(EnvelopeMode::X25519_XCHACHA20_POLY1305);

        SecureBytes plaintext = { 'T', 'e', 's', 't' };

        SecureBytes ciphertext = envelope.encrypt(
            EnvelopeMode::X25519_XCHACHA20_POLY1305,
            keypair1.public_key,
            plaintext
        );

        REQUIRE_THROWS_AS(
            envelope.decrypt(EnvelopeMode::X25519_XCHACHA20_POLY1305, keypair2.private_key, ciphertext),
            VaultCryptException
        );
    }
}