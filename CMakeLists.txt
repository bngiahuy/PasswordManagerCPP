cmake_minimum_required(VERSION 3.16)
project(PasswordManager)

# C++ version
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Tạo biến danh sách thư mục source
set(SRC_DIR src)

# Add thư mục con
include_directories(
    ${SRC_DIR}
    ${SRC_DIR}/crypto
    ${SRC_DIR}/core
    ${SRC_DIR}/storage
    ${SRC_DIR}/ui
    ${SRC_DIR}/third_party
)


# Add executable cho app chính
add_executable(PasswordManager
    ${SRC_DIR}/main.cpp
    ${SRC_DIR}/crypto/Crypto.cpp
    ${SRC_DIR}/core/Account.cpp
    ${SRC_DIR}/core/PasswordManager.cpp
    ${SRC_DIR}/core/AuthManager.cpp
    ${SRC_DIR}/storage/Storage.cpp
    ${SRC_DIR}/cli/Menu.cpp
    ${SRC_DIR}/utils/Logger.cpp
    ${SRC_DIR}/utils/utils.cpp
)

# Optional: Nếu bạn dùng OpenSSL
find_package(OpenSSL REQUIRED)
target_link_libraries(PasswordManager PRIVATE OpenSSL::Crypto)

# ============================
# === Build test executable ==
# ============================

# Thêm tất cả test files vào executable test
#add_executable(TestSuite
#    tests/test_crypto.cpp
#    tests/test_account.cpp
#    tests/test_password_manager.cpp
#    tests/test_storage.cpp
#)