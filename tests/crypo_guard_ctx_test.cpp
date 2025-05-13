#include <gtest/gtest.h>
#include <memory>
#include <sstream>

#include "crypto_guard_ctx.h"

using namespace CryptoGuard;

std::string HexView(std::iostream& inStream){
    std::string output{};
    
    char c;
    while (inStream.get(c)) {
        output.append(std::format("{:x}", c));
    }

    return output;
}

class CryptoGuardCtxTest: public ::testing::Test{
protected:
    void SetUp() override{
        ctx_ = std::make_unique<CryptoGuardCtx>();
    }
    void TearDown() override{
        inStream_.clear();
        outStream_.clear();

        password_.clear();
        res_.clear();
    }

    std::stringstream inStream_{};
    std::stringstream outStream_{};
    std::string password_{};

    std::string res_{};

    std::unique_ptr<CryptoGuardCtx> ctx_{};
};

TEST_F(CryptoGuardCtxTest, EncryptDecrypt_HelloOpenSSL_Correct) {
    res_ = "Hello OpenSSL crypto world!";
    inStream_ << res_;
    password_ = "1234";

    ctx_->EncryptFile(inStream_, outStream_, password_);
    
    std::stringstream outStream2_;
    ctx_->DecryptFile(outStream_, outStream2_, password_);

    ASSERT_EQ(res_, outStream2_.str());
}

TEST_F(CryptoGuardCtxTest, EncryptDecrypt_HelloOpenSSLWrongPassword_Exception) {
    res_ = "Hello OpenSSL crypto world!";
    inStream_ << res_;
    
    password_ = "1234";
    ctx_->EncryptFile(inStream_, outStream_, password_);
    std::stringstream outStream2_;
    password_ = "12345";

    ASSERT_THROW({
        ctx_->DecryptFile(outStream_, outStream2_, password_);
    }, openssl_error);
}

// TEST_F(CryptoGuardCtxTest, Encrypt_EmptyText_Exception) {
//     password_ = "1234";

//     ASSERT_THROW({
//         ctx_->EncryptFile(inStream_, outStream_, password_);
//     }, openssl_error);
// }

// TEST_F(CryptoGuardCtxTest, Encrypt_EmptyPassword_Exception) {
//     inStream_ << "Hello OpenSSL crypto world!";
//     password_ = "";

//     ASSERT_THROW({
//         ctx_->EncryptFile(inStream_, outStream_, password_);
//     }, openssl_error);
// }

TEST_F(CryptoGuardCtxTest, Decrypt_EmptyText_Exception) {
    password_ = "1234";

    ASSERT_THROW({
        ctx_->DecryptFile(inStream_, outStream_, password_);
    }, openssl_error);
}

TEST_F(CryptoGuardCtxTest, Decrypt_EmptyPassword_Exception) {
    inStream_ << "Hello OpenSSL crypto world!";
    password_ = "";

    ASSERT_THROW({
        ctx_->DecryptFile(inStream_, outStream_, password_);
    }, openssl_error);
}

TEST_F(CryptoGuardCtxTest, CheckSum_HelloOpenSSL_Correct) {
    inStream_ << "Hello OpenSSL crypto world!";
    auto const res = ctx_->CalculateChecksum(inStream_);

    ASSERT_EQ(res, "");
}
