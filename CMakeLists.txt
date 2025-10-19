cmake_minimum_required(VERSION 3.20)
project(VaultCrypt VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# IMPORTANT: Set include directory at project level
include_directories(${CMAKE_SOURCE_DIR}/include)

option(BUILD_CLI "Build CLI tool" ON)
option(BUILD_GUI "Build GUI application" ON)
option(BUILD_TESTS "Build unit tests" OFF)

if(WIN32)
    add_compile_definitions(_WIN32_WINNT=0x0A00 NOMINMAX WIN32_LEAN_AND_MEAN)
endif()

if(MSVC)
    add_compile_options(/W4 /permissive- /Zc:__cplusplus)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Find dependencies
find_package(cryptopp CONFIG REQUIRED)
find_package(unofficial-sodium CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

if(BUILD_GUI)
    set(CMAKE_PREFIX_PATH "C:/Users/kryptos/vcpkg/vcpkg/installed/x64-windows")
    find_package(Qt5 REQUIRED COMPONENTS Core Widgets)
    set(CMAKE_AUTOMOC ON)
    set(CMAKE_AUTOUIC ON)
    message(STATUS "Found Qt5: ${Qt5_VERSION}")
endif()

if(BUILD_TESTS)
    find_package(Catch2 3 CONFIG REQUIRED)
endif()

# Core library - NO GUI FILES HERE!
add_library(vaultcrypt_core STATIC
    src/core/error.cpp
    src/core/secure_memory.cpp
    src/core/file_io.cpp
    src/core/logger.cpp
    src/core/aead_aes_gcm.cpp
    src/core/aead_chacha20poly1305.cpp
    src/core/envelope.cpp
    src/crypto/cryptopp_backend.cpp
    src/crypto/libsodium_backend.cpp
    src/crypto/openssl_backend.cpp
)

# Set include directories for the core library
target_include_directories(vaultcrypt_core
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(vaultcrypt_core
    PUBLIC
        cryptopp::cryptopp
        unofficial-sodium::sodium
        OpenSSL::Crypto
        nlohmann_json::nlohmann_json
)

if(WIN32)
    target_link_libraries(vaultcrypt_core PUBLIC ws2_32)
endif()

# Subdirectories
if(BUILD_CLI)
    add_subdirectory(src/cli)
endif()

if(BUILD_GUI)
    add_subdirectory(src/gui)
endif()

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()