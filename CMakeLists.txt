find_package(OpenSSL REQUIRED)
target_link_libraries(PasswordManager PRIVATE OpenSSL::SSL OpenSSL::Crypto)
