#include "Crypto.h"

std::string Crypto::generateSalt()
{
    // Generate a random salt using a secure random number generator
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> distribution(0, 255);

    std::string salt;
    for (size_t i = 0; i < 16; ++i)
    { // Generate a 16-byte salt
        salt += static_cast<char>(distribution(generator));
    }
    return salt;
}

std::string Crypto::generateIV()
{
    // Generate a random initialization vector (IV) using a secure random number generator
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> distribution(0, 255);

    std::string iv;
    for (size_t i = 0; i < 16; ++i)
    { // Generate a 16-byte IV
        iv += static_cast<char>(distribution(generator));
    }
    return iv;
}

void handleOpenSSLError()
{
    ERR_print_errors_fp(stderr);
    exit(1);
}

std::string Crypto::hashSHA256(const std::string &input)
{
    // Sử dụng std::unique_ptr để quản lý bộ nhớ của EVP_MD_CTX một cách an toàn
    // Tự động giải phóng khi ra khỏi scope
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);

    if (md_ctx == nullptr)
    {
        handleOpenSSLError();
    }

    // Khởi tạo quá trình băm SHA256
    if (1 != EVP_DigestInit_ex(md_ctx.get(), EVP_sha256(), nullptr))
    {
        handleOpenSSLError();
    }

    // Cập nhật dữ liệu đầu vào
    if (1 != EVP_DigestUpdate(md_ctx.get(), input.c_str(), input.length()))
    {
        handleOpenSSLError();
    }

    // Hoàn tất tính toán và lấy giá trị băm
    unsigned char hash[EVP_MAX_MD_SIZE]; // Kích thước tối đa cho mọi hàm băm
    unsigned int hash_len;               // Chiều dài thực tế của hash

    if (1 != EVP_DigestFinal_ex(md_ctx.get(), hash, &hash_len))
    {
        handleOpenSSLError();
    }

    // Kiểm tra để đảm bảo đúng kích thước SHA256
    if (hash_len != SHA256_DIGEST_LENGTH)
    {
        // Đây là một kiểm tra sanity, EVP_sha256() luôn cho ra 32 byte
        Logger::error("Unexpected hash length for SHA256.");
        exit(1);
    }

    // Chuyển đổi giá trị băm (byte array) sang chuỗi hex
    std::stringstream ss;
    for (unsigned int i = 0; i < hash_len; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::string Crypto::deriveKey(const std::string &password, const std::string &salt)
{
    // salt is expected to be a 16-byte binary string
    // Use PKCS5_PBKDF2_HMAC to derive a key from the password and salt

    constexpr int keyLength = 32;      // 256-bit key for AES-256
    constexpr int iterations = 100000; // Recommended iteration count for PBKDF2

    unsigned char key[keyLength];

    int res = PKCS5_PBKDF2_HMAC(
        password.c_str(),
        static_cast<int>(password.size()),
        reinterpret_cast<const unsigned char *>(salt.data()),
        static_cast<int>(salt.size()),
        iterations,
        EVP_sha256(),
        keyLength,
        key);

    if (res != 1)
    {
        handleOpenSSLError();
    }

    // Return key as a binary string
    return std::string(reinterpret_cast<char *>(key), keyLength);
}

std::string Crypto::encrypt(const std::string &plaintext, const std::string &key)
{
    // Generate a random IV (16 bytes for AES)
    if (key.size() != 32)
    {
        std::cerr << "Key must be 32 bytes for AES-256!" << std::endl;
        exit(1);
    }
    // Ensure the plaintext is not empty
    if (plaintext.empty())
    {
        std::cerr << "Plaintext cannot be empty!" << std::endl;
        exit(1);
    }

    std::string iv = generateIV();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleOpenSSLError();

    int len;
    int ciphertext_len;
    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                                reinterpret_cast<const unsigned char *>(key.data()),
                                reinterpret_cast<const unsigned char *>(iv.data())))
    {
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLError();
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                               reinterpret_cast<const unsigned char *>(plaintext.data()),
                               static_cast<int>(plaintext.size())))
    {
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLError();
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len))
    {
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLError();
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    // Result: IV + ciphertext (binary)
    std::string result = iv + std::string(reinterpret_cast<char *>(ciphertext.data()), ciphertext_len);
    return result;
}

std::string Crypto::decrypt(const std::string &ciphertext, const std::string &key)
{
    // Ensure the key is 32 bytes for AES-256
    if (key.size() != 32)
    {
        std::cerr << "Key must be 32 bytes for AES-256!" << std::endl;
        exit(1);
    }
    // Ensure the ciphertext is not empty
    if (ciphertext.empty())
    {
        std::cerr << "Ciphertext cannot be empty!" << std::endl;
        exit(1);
    }
    
    // Extract IV and ciphertext
    if (ciphertext.size() < 16)
    {
        std::cerr << "Ciphertext too short!" << std::endl;
        exit(1);
    }
    std::string iv = ciphertext.substr(0, 16);
    std::string real_cipher = ciphertext.substr(16);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleOpenSSLError();

    int len;
    int plaintext_len;
    std::vector<unsigned char> plaintext(real_cipher.size() + EVP_MAX_BLOCK_LENGTH);

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                                reinterpret_cast<const unsigned char *>(key.data()),
                                reinterpret_cast<const unsigned char *>(iv.data())))
    {
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLError();
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                               reinterpret_cast<const unsigned char *>(real_cipher.data()),
                               static_cast<int>(real_cipher.size())))
    {
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLError();
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len))
    {
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLError();
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return std::string(reinterpret_cast<char *>(plaintext.data()), plaintext_len);
}