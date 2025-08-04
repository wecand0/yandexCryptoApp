#pragma once

#include <experimental/propagate_const>
#include <memory>

namespace CryptoGuard {

class CryptoGuardCtx {
public:
    CryptoGuardCtx();
    ~CryptoGuardCtx();

    CryptoGuardCtx(const CryptoGuardCtx &) = delete;
    CryptoGuardCtx &operator=(const CryptoGuardCtx &) = delete;

    CryptoGuardCtx(CryptoGuardCtx &&) = delete;
    CryptoGuardCtx &operator=(CryptoGuardCtx &&) = delete;

    // API
    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const;
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const;
    std::string CalculateChecksum(std::iostream &inStream) const;

private:
    class Impl;
    std::experimental::propagate_const<std::unique_ptr<Impl>> pImpl_;
};

}  // namespace CryptoGuard
