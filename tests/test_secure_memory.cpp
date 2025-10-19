#include <catch2/catch_test_macros.hpp>
#include "vaultcrypt/secure_memory.h"

using namespace vaultcrypt;

TEST_CASE("Secure memory operations", "[secure_memory]") {
    SECTION("Secure zero") {
        unsigned char data[16];
        for (int i = 0; i < 16; ++i) {
            data[i] = static_cast<unsigned char>(i);
        }

        secure_zero(data, 16);

        for (int i = 0; i < 16; ++i) {
            REQUIRE(data[i] == 0);
        }
    }

    SECTION("Constant time compare - equal") {
        unsigned char a[] = { 1, 2, 3, 4, 5 };
        unsigned char b[] = { 1, 2, 3, 4, 5 };

        REQUIRE(constant_time_compare(a, b, 5));
    }

    SECTION("Constant time compare - not equal") {
        unsigned char a[] = { 1, 2, 3, 4, 5 };
        unsigned char b[] = { 1, 2, 3, 4, 6 };

        REQUIRE(!constant_time_compare(a, b, 5));
    }

    SECTION("SecureVector allocation") {
        SecureVector<unsigned char> vec(100);
        REQUIRE(vec.size() == 100);

        vec.push_back(42);
        REQUIRE(vec.size() == 101);
    }
}