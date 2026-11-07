#ifndef CRYPTO_GUARD_CTX_H
#define CRYPTO_GUARD_CTX_H

#include <cstdint>
#include <expected>
#include <iosfwd>
#include <memory>
#include <string>
#include <string_view>

namespace CryptoGuard {

constexpr unsigned int CRIPT_BLOCK_SIZE = 1024;
constexpr unsigned int ERROR_MSG_SIZE = 1024;

enum class CryptoErrorKind : std::uint8_t {
    Stream,   // a stream was unusable, or a write to it failed
    OpenSsl,  // OpenSSL refused: a wrong password or a damaged input ends here
};

struct CryptoError {
    CryptoErrorKind kind;
    std::string message;
};

// Every failure comes back as a value: this class holds no exception.
class CryptoGuardCtx {
public:
    CryptoGuardCtx();
    ~CryptoGuardCtx();

    CryptoGuardCtx(const CryptoGuardCtx &) = delete;
    CryptoGuardCtx &operator=(const CryptoGuardCtx &) = delete;

    CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;
    CryptoGuardCtx &operator=(CryptoGuardCtx &&) noexcept = default;

    // API
    [[nodiscard]] std::expected<void, CryptoError> EncryptFile(std::iostream &inStream, std::iostream &outStream,
                                                               std::string_view password);
    [[nodiscard]] std::expected<void, CryptoError> DecryptFile(std::iostream &inStream, std::iostream &outStream,
                                                               std::string_view password);
    [[nodiscard]] std::expected<std::string, CryptoError> CalculateChecksum(std::iostream &inStream);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

}  // namespace CryptoGuard

#endif  // CRYPTO_GUARD_CTX_H
