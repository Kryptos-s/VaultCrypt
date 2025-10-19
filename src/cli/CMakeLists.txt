add_executable(vaultcrypt
    main.cpp
    commands.cpp
)

target_link_libraries(vaultcrypt PRIVATE vaultcrypt_core)

# Add test program
add_executable(test_direct
    test_direct.cpp
)

target_link_libraries(test_direct PRIVATE vaultcrypt_core)

install(TARGETS vaultcrypt DESTINATION bin)