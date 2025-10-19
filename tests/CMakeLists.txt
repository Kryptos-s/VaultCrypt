add_executable(vaultcrypt_tests
    test_aead.cpp
    test_envelope.cpp
    test_keystore.cpp
    test_secure_memory.cpp
    integration_test.cpp
)

target_link_libraries(vaultcrypt_tests PRIVATE
    vaultcrypt_core
    Catch2::Catch2WithMain
)

# Only include CTest if Catch2 discovery is available
if(TARGET Catch2::Catch2)
    include(CTest)
    include(Catch)
    catch_discover_tests(vaultcrypt_tests)
endif()