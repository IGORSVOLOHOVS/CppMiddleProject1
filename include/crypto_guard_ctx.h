#pragma once

#include <string>
#include <memory>

namespace CryptoGuard {
    
constexpr unsigned int CRIPT_BLOCK_SPACE = 1024;
constexpr unsigned int ERROR_MSG_SIZE = 1024;

class openssl_error : public std::runtime_error
{
    std::unique_ptr<char[]> what_message = std::make_unique<char[]>(ERROR_MSG_SIZE);
public:
    openssl_error(std::string msg);
    const char * what () const throw ();
};

class CryptoGuardCtx {
public:
    CryptoGuardCtx();
    ~CryptoGuardCtx();

    CryptoGuardCtx(const CryptoGuardCtx &) = delete;
    CryptoGuardCtx &operator=(const CryptoGuardCtx &) = delete;

    CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;
    CryptoGuardCtx &operator=(CryptoGuardCtx &&) noexcept = default;

    // API
    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    std::string CalculateChecksum(std::iostream &inStream);// { return "NOT_IMPLEMENTED"; }

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

}  // namespace CryptoGuard
