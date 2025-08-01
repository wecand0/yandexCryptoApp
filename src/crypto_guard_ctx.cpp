#include "crypto_guard_ctx.h"

#include <iomanip>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sstream>

#include <vector>

namespace CryptoGuard {

struct AesCipherParams {
    static constexpr size_t KEY_SIZE{32};          // AES-256 key size
    static constexpr size_t IV_SIZE{16};           // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    // I use EVP_EncryptInit_ex2 from https://docs.openssl.org/master/man3/EVP_EncryptInit/#examples, this 'int encrypt'
    // is not necessary
    std::array<unsigned char, KEY_SIZE> key{};  // Encryption key
    std::array<unsigned char, IV_SIZE> iv{};    // Initialization vector
};

struct OpenSslCipherContextDeleter {
    void operator()(EVP_CIPHER_CTX *ctx) const noexcept {
        if (ctx)
            EVP_CIPHER_CTX_free(ctx);
    }
};
struct OpenSslMDContextDeleter {
    void operator()(EVP_MD_CTX *ctx) const noexcept {
        if (ctx)
            EVP_MD_CTX_free(ctx);
    }
};

using openssl_context_cipher_ptr = std::unique_ptr<EVP_CIPHER_CTX, OpenSslCipherContextDeleter>;
using openssl_context_md_ptr = std::unique_ptr<EVP_MD_CTX, OpenSslMDContextDeleter>;

class CryptoGuardCtx::Impl {
public:
    Impl();
    ~Impl();

    void Encrypt(std::iostream &inStream, std::iostream &outStream, std::string_view password) const;
    void Decrypt(std::iostream &inStream, std::iostream &outStream, std::string_view password) const;
    std::string CalculateChecksum(std::iostream &inStream) const;

private:
    const int bufferSize_c{1024};
    static AesCipherParams CreateCipherParamsFromPassword(std::string_view password);
    static void CheckStreamState(const std::iostream &input);
    static void CheckStreamState(const std::iostream &input, const std::iostream &output);
    [[nodiscard("Детальная обработка ошибок OpenSSL")]] static std::string GetOpenSSLError();
};

CryptoGuardCtx::Impl::Impl() { OpenSSL_add_all_algorithms(); }

CryptoGuardCtx::Impl::~Impl() { EVP_cleanup(); }

void CryptoGuardCtx::Impl::Encrypt(std::iostream &inStream, std::iostream &outStream,
                                   const std::string_view password) const {
    CheckStreamState(inStream, outStream);

    const auto aesCipherParams = CreateCipherParamsFromPassword(password);

    const openssl_context_cipher_ptr ctx(EVP_CIPHER_CTX_new());

    // Инициализация шифрования AES-256-CBC
    if (EVP_EncryptInit_ex2(ctx.get(), EVP_aes_256_cbc(), aesCipherParams.key.data(), aesCipherParams.iv.data(),
                            nullptr) != 1) {
        throw std::runtime_error("Failed to initialize encryption: " + GetOpenSSLError());
    }

    // Шифрование данных по блокам
    std::vector<unsigned char> in_buffer(bufferSize_c);
    std::vector<unsigned char> out_buffer(bufferSize_c + EVP_CIPHER_block_size(EVP_aes_256_cbc()));

    int out_len = 0;
    while (inStream.read(reinterpret_cast<char *>(in_buffer.data()), bufferSize_c) || inStream.gcount() > 0) {

        if (const int bytes_read = static_cast<int>(inStream.gcount());
            EVP_EncryptUpdate(ctx.get(), out_buffer.data(), &out_len, in_buffer.data(), bytes_read) != 1) {
            throw std::runtime_error("Encryption failed: " + GetOpenSSLError());
        }

        outStream.write(reinterpret_cast<const char *>(out_buffer.data()), out_len);
        if (!outStream.good()) {
            throw std::runtime_error("Failed to write encrypted data");
        }
    }

    if (EVP_EncryptFinal_ex(ctx.get(), out_buffer.data(), &out_len) != 1) {
        throw std::runtime_error("Encryption finalization failed: " + GetOpenSSLError());
    }

    outStream.write(reinterpret_cast<const char *>(out_buffer.data()), out_len);
    if (!outStream.good()) {
        throw std::runtime_error("Failed to write final encrypted block");
    }
}
void CryptoGuardCtx::Impl::Decrypt(std::iostream &inStream, std::iostream &outStream,
                                   const std::string_view password) const {
    CheckStreamState(inStream, outStream);

    // Создание параметров шифрования из пароля и соли
    const auto params = CreateCipherParamsFromPassword(password);

    const openssl_context_cipher_ptr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context: " + GetOpenSSLError());
    }

    // Инициализация дешифрования
    if (EVP_DecryptInit_ex2(ctx.get(), EVP_aes_256_cbc(), params.key.data(), params.iv.data(), nullptr) != 1) {
        throw std::runtime_error("Failed to initialize decryption: " + GetOpenSSLError());
    }

    // Дешифрование данных по блокам
    std::vector<unsigned char> in_buffer(bufferSize_c);
    std::vector<unsigned char> out_buffer(bufferSize_c + EVP_CIPHER_block_size(EVP_aes_256_cbc()));

    int out_len = 0;
    while (inStream.read(reinterpret_cast<char *>(in_buffer.data()), bufferSize_c) || inStream.gcount() > 0) {

        if (const int bytes_read = static_cast<int>(inStream.gcount());
            EVP_DecryptUpdate(ctx.get(), out_buffer.data(), &out_len, in_buffer.data(), bytes_read) != 1) {
            throw std::runtime_error("Decryption failed: " + GetOpenSSLError());
        }

        outStream.write(reinterpret_cast<const char *>(out_buffer.data()), out_len);
        if (!outStream.good()) {
            throw std::runtime_error("Failed to write decrypted data");
        }
    }

    if (EVP_DecryptFinal_ex(ctx.get(), out_buffer.data(), &out_len) != 1) {
        throw std::runtime_error("Decryption finalization failed - wrong password or corrupted data: " +
                                 GetOpenSSLError());
    }

    outStream.write(reinterpret_cast<const char *>(out_buffer.data()), out_len);
    if (!outStream.good()) {
        throw std::runtime_error("Failed to write final decrypted block");
    }
}

std::string CryptoGuardCtx::Impl::CalculateChecksum(std::iostream &inStream) const {
    CheckStreamState(inStream);

    const openssl_context_md_ptr ctx(EVP_MD_CTX_new());
    if (!ctx) {
        throw std::runtime_error("Failed to create hash context: " + GetOpenSSLError());
    }

    // Инициализация SHA-256
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("Failed to initialize SHA-256: " + GetOpenSSLError());
    }

    // Вычисление хеша по блокам
    std::vector<unsigned char> buffer(bufferSize_c);
    while (inStream.read(reinterpret_cast<char *>(buffer.data()), bufferSize_c) || inStream.gcount() > 0) {
        if (const int bytes_read = static_cast<int>(inStream.gcount());
            EVP_DigestUpdate(ctx.get(), buffer.data(), bytes_read) != 1) {
            throw std::runtime_error("Hash update failed: " + GetOpenSSLError());
        }
    }

    // Получение результата хеширования
    std::array<unsigned char, EVP_MAX_MD_SIZE> hash{};
    unsigned int hash_len;

    if (EVP_DigestFinal_ex(ctx.get(), hash.data(), &hash_len) != 1) {
        throw std::runtime_error("Hash finalization failed: " + GetOpenSSLError());
    }

    // Преобразование в hex строку
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < hash_len; ++i) {
        ss << std::setw(2) << static_cast<unsigned int>(hash[i]);
    }

    return ss.str();
}

AesCipherParams CryptoGuardCtx::Impl::CreateCipherParamsFromPassword(const std::string_view password) {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};
    const int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                      reinterpret_cast<const unsigned char *>(password.data()),
                                      static_cast<int>(password.size()), 1, params.key.data(), params.iv.data());

    if (result == 0) {
        throw std::runtime_error{"Failed to create a key from password"};
    }
    return params;
}
void CryptoGuardCtx::Impl::CheckStreamState(const std::iostream &stream) {
    if (stream.bad()) {
        throw std::runtime_error("Stream error: irrecoverable read/write error (badbit set)");
    }
    if (stream.fail()) {
        throw std::runtime_error("Stream error: logical I/O operation failed (failbit set)");
    }
    if (stream.eof()) {
        throw std::runtime_error("Stream error: unexpected EOF encountered (eofbit set)");
    }
    if (!stream.good()) {
        throw std::runtime_error("Stream is not in a good state");
    }
}
void CryptoGuardCtx::Impl::CheckStreamState(const std::iostream &input, const std::iostream &output) {
    try {
        CheckStreamState(input);
    } catch (const std::exception &e) {
        throw std::runtime_error(std::string("Input stream check failed: ") + e.what());
    }

    try {
        CheckStreamState(output);
    } catch (const std::exception &e) {
        throw std::runtime_error(std::string("Output stream check failed: ") + e.what());
    }
}
std::string CryptoGuardCtx::Impl::GetOpenSSLError() {
    const auto err = ERR_get_error();
    if (err == 0)
        return "Unknown OpenSSL error";

    char buffer[256];
    ERR_error_string_n(err, buffer, sizeof(buffer));
    return buffer;
}

// Реализация основного класса CryptoGuardCtx
CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

CryptoGuardCtx::CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;

CryptoGuardCtx &CryptoGuardCtx::operator=(CryptoGuardCtx &&) noexcept = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream,
                                 const std::string_view password) const {
    pImpl_->Encrypt(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream,
                                 const std::string_view password) const {
    pImpl_->Decrypt(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) const {
    return pImpl_->CalculateChecksum(inStream);
}

}  // namespace CryptoGuard
