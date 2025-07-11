#pragma once

#include <string>
#include <vector>
#include "core/Account.h"

class Storage {
public:
    // Lưu vault (sau khi mã hóa) vào file
    static bool saveVault(const std::vector<Account>& accounts,
                          const std::string& encryptionKey,
                          const std::string& filePath);

    // Tải vault từ file (giải mã thành danh sách account)
    static std::vector<Account> loadVault(const std::string& encryptionKey,
                                          const std::string& filePath);
};
