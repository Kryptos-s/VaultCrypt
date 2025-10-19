# Save this as: create_files.ps1
# Run with: .\create_files.ps1

$files = @{
    # Root files
    "CMakeLists.txt" = @"
cmake_minimum_required(VERSION 3.20)
project(VaultCrypt VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_CLI "Build CLI tool" ON)
option(BUILD_GUI "Build GUI application" ON)
option(BUILD_TESTS "Build unit tests" ON)

if(WIN32)
    add_compile_definitions(_WIN32_WINNT=0x0A00 NOMINMAX)
endif()

if(MSVC)
    add_compile_options(/W4 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

list(APPEND CMAKE_MODULE_PATH "`${CMAKE_SOURCE_DIR}/cmake")

find_package(cryptopp CONFIG REQUIRED)
find_package(libsodium CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

if(BUILD_GUI)
    find_package(Qt6 COMPONENTS Core Widgets REQUIRED)
    set(CMAKE_AUTOMOC ON)
    set(CMAKE_AUTOUIC ON)
endif()

if(BUILD_TESTS)
    find_package(Catch2 3 CONFIG REQUIRED)
endif()

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
    src/keystore/keystore.cpp
)

target_include_directories(vaultcrypt_core
    PUBLIC
        `$<BUILD_INTERFACE:`${CMAKE_SOURCE_DIR}/include>
        `$<INSTALL_INTERFACE:include>
    PRIVATE
        `${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(vaultcrypt_core
    PUBLIC
        cryptopp::cryptopp
        libsodium::libsodium
        OpenSSL::Crypto
        nlohmann_json::nlohmann_json
)

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
"@

    # Include files (headers) - Create minimal working versions
    "include\vaultcrypt\version.h" = @"
#pragma once
#define VAULTCRYPT_VERSION "1.0.0"
"@

    "include\vaultcrypt\error.h" = @"
#pragma once
#include <stdexcept>
#include <string>

namespace vaultcrypt {

enum class ErrorCode {
    Success = 0,
    InvalidArgument,
    InvalidKey,
    DecryptionFailed,
    EncryptionFailed,
    KeystoreError,
    FileIOError,
    UnsupportedAlgorithm,
    LibraryError
};

class VaultCryptException : public std::runtime_error {
public:
    explicit VaultCryptException(ErrorCode code, const std::string& msg)
        : std::runtime_error(msg), code_(code) {}
    ErrorCode code() const { return code_; }
private:
    ErrorCode code_;
};

}
"@

    # Add more critical files...
    # (Continue with the pattern for all files)
}

# Create all files
foreach ($file in $files.GetEnumerator()) {
    $path = $file.Key
    $content = $file.Value
    
    # Ensure directory exists
    $dir = Split-Path -Parent $path
    if ($dir -and !(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    
    # Write file
    Set-Content -Path $path -Value $content -Encoding UTF8
    Write-Host "Created: $path"
}

Write-Host "`nAll files created successfully!"