#include "crypto_guard_ctx.h"

#include <array>
#include <cstddef>
#include <format>
#include <iomanip>
#include <ios>
#include <iostream>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sstream>
#include <string>
#include <utility>

namespace CryptoGuard {

namespace {

std::unexpected<CryptoError> StreamError(std::string message) {
    return std::unexpected(CryptoError{CryptoErrorKind::Stream, std::move(message)});
}

// Reads the reason from the error queue of OpenSSL, while it is still there.
std::unexpected<CryptoError> OpenSslError(std::string_view call) {
    std::array<char, ERROR_MSG_SIZE> reason{};
    ERR_error_string_n(ERR_get_error(), reason.data(), reason.size());
    return std::unexpected(CryptoError{CryptoErrorKind::OpenSsl, std::format("{}: {}", call, reason.data())});
}

}  // namespace

class CryptoGuardCtx::Impl {
public:
    using UniqueEVPCipherCTX =
        std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *cp_ctx) { EVP_CIPHER_CTX_free(cp_ctx); })>;

    using UniqueEVPMDCTX = std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *md_ctx) { EVP_MD_CTX_free(md_ctx); })>;
    using UniqueEVPMD =
        std::unique_ptr<const EVP_MD, decltype([](const EVP_MD *md) { EVP_MD_free(const_cast<EVP_MD *>(md)); })>;

    Impl() {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
    }
    ~Impl() { EVP_cleanup(); }

    std::expected<void, CryptoError> EncryptFile(std::iostream &inStream, std::iostream &outStream,
                                                 std::string_view password) {
        return Transform(inStream, outStream, password, 1);
    }
    std::expected<void, CryptoError> DecryptFile(std::iostream &inStream, std::iostream &outStream,
                                                 std::string_view password) {
        return Transform(inStream, outStream, password, 0);
    }
    std::expected<std::string, CryptoError> CalculateChecksum(std::iostream &inStream) {
        if (inStream.fail()) {
            return StreamError("Input stream is in invalid state!");
        }

        std::array<unsigned char, EVP_MAX_BLOCK_LENGTH> mdBuf{};
        std::array<unsigned char, CRIPT_BLOCK_SIZE> inBuf{};

        unsigned int mdLen{};

        UniqueEVPMD md{EVP_sha256()};
        UniqueEVPMDCTX md_ctx{EVP_MD_CTX_new()};

        if (!EVP_DigestInit_ex2(md_ctx.get(), md.get(), nullptr)) {
            return OpenSslError("EVP_DigestInit_ex2 failed");
        }

        while (!inStream.eof()) {
            if (inStream.fail()) {
                return StreamError("Input stream is in invalid state!");
            }
            inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());
            const auto inLen = static_cast<std::size_t>(inStream.gcount());

            if (inLen > 0 && !EVP_DigestUpdate(md_ctx.get(), inBuf.data(), inLen)) {
                return OpenSslError("EVP_DigestUpdate failed");
            }
        }

        if (!EVP_DigestFinal_ex(md_ctx.get(), mdBuf.data(), &mdLen)) {
            return OpenSslError("EVP_DigestFinal_ex failed");
        }

        std::stringstream output{};
        output << std::hex << std::setfill('0');
        for (std::size_t i = 0; i < mdLen; i++) {
            output << std::setw(2) << static_cast<int>(mdBuf[i]);
        }
        return output.str();
    }

private:
    struct AesCipherParams {
        static const std::size_t KEY_SIZE = 32;        // AES-256 key size
        static const std::size_t IV_SIZE = 16;         // AES block size (IV length)
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

        std::array<unsigned char, KEY_SIZE> key{};  // Encryption key
        std::array<unsigned char, IV_SIZE> iv{};    // Initialization vector
    };

    // Encryption and decryption differ only in the flag OpenSSL is given: 1 encrypts, 0 decrypts.
    std::expected<void, CryptoError> Transform(std::iostream &inStream, std::iostream &outStream,
                                               std::string_view password, int encrypt) {
        if (inStream.fail() || outStream.fail()) {
            return StreamError("I/O streams are in invalid state!");
        }

        UniqueEVPCipherCTX ctx{EVP_CIPHER_CTX_new()};

        std::array<unsigned char, CRIPT_BLOCK_SIZE> inBuf{};
        std::array<unsigned char, CRIPT_BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH> outBuf{};

        int outLen{0};

        const auto params = CreateChiperParamsFromPassword(password);
        if (!params) {
            return std::unexpected(params.error());
        }

        if (!EVP_CipherInit_ex(ctx.get(), params->cipher, nullptr, params->key.data(), params->iv.data(), encrypt)) {
            return OpenSslError("EVP_CipherInit_ex failed");
        }

        while (!inStream.eof()) {
            if (inStream.fail()) {
                return StreamError("Input stream is in invalid state!");
            }
            inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());
            const auto inLen = static_cast<int>(inStream.gcount());

            if (inLen > 0) {
                if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), inLen)) {
                    return OpenSslError("EVP_CipherUpdate failed");
                }
                if (!Write(outStream, outBuf.data(), outLen)) {
                    return StreamError("Failed to write to file!");
                }
            }
        }
        if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
            return OpenSslError("EVP_CipherFinal_ex failed");
        }
        if (!Write(outStream, outBuf.data(), outLen)) {
            return StreamError("Failed to write to file!");
        }
        return {};
    }

    static bool Write(std::iostream &outStream, const unsigned char *data, int length) {
        if (length > 0) {
            outStream.write(reinterpret_cast<const char *>(data), length);
        }
        return length <= 0 || !outStream.fail();
    }

    std::expected<AesCipherParams, CryptoError> CreateChiperParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        const int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                          reinterpret_cast<const unsigned char *>(password.data()),
                                          static_cast<int>(password.size()), 1, params.key.data(), params.iv.data());

        if (result == 0) {
            return OpenSslError("Failed to create a key from password");
        }

        return params;
    }
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}
CryptoGuardCtx::~CryptoGuardCtx() {}

// API
std::expected<void, CryptoError> CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream,
                                                             std::string_view password) {
    return pImpl_->EncryptFile(inStream, outStream, password);
}
std::expected<void, CryptoError> CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream,
                                                             std::string_view password) {
    return pImpl_->DecryptFile(inStream, outStream, password);
}
std::expected<std::string, CryptoError> CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) {
    return pImpl_->CalculateChecksum(inStream);
}
}  // namespace CryptoGuard
