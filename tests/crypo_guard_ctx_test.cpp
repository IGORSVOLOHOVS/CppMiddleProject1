#include <gtest/gtest.h>
#include <memory>
#include <print>
#include <sstream>
#include <stdexcept>

#include "crypto_guard_ctx.h"

using namespace CryptoGuard;

class CryptoGuardCtxTest: public ::testing::Test{
protected:
    void SetUp() override{
    }
    void TearDown() override{
        inStream_.clear();
        outStream_.clear();

        password_.clear();
        expected_.clear();
    }

    std::stringstream inStream_{};
    std::stringstream outStream_{};
    std::string password_{};

    std::string expected_{};

    CryptoGuardCtx ctx_{};
};

TEST_F(CryptoGuardCtxTest, EncryptDecrypt_HelloOpenSSL_Correct) {
    expected_ = "Hello OpenSSL crypto world!";
    inStream_ << expected_;
    password_ = "1234";

    ctx_.EncryptFile(inStream_, outStream_, password_);
    
    std::stringstream decOutStream;
    ctx_.DecryptFile(outStream_, decOutStream, password_);

    ASSERT_EQ(expected_, decOutStream.str());
}

TEST_F(CryptoGuardCtxTest, EncryptDecrypt_HelloOpenSSLWrongPassword_Exception) {
    expected_ = "Hello OpenSSL crypto world!";
    inStream_ << expected_;
    
    password_ = "1234";
    ctx_.EncryptFile(inStream_, outStream_, password_);
    std::stringstream outStream2_;
    password_ = "12345";

    ASSERT_THROW({
        ctx_.DecryptFile(outStream_, outStream2_, password_);
    }, openssl_error);
}

TEST_F(CryptoGuardCtxTest, Decrypt_EmptyText_Exception) {
    password_ = "1234";

    ASSERT_THROW({
        ctx_.DecryptFile(inStream_, outStream_, password_);
    }, openssl_error);
}

TEST_F(CryptoGuardCtxTest, Decrypt_EmptyPassword_Exception) {
    inStream_ << "Hello OpenSSL crypto world!";
    password_ = "";

    ASSERT_THROW({
        ctx_.DecryptFile(inStream_, outStream_, password_);
    }, openssl_error);
}

TEST_F(CryptoGuardCtxTest, Encrypt_ImputIsEqualOutput_Exception) {
    ASSERT_THROW({
        ctx_.EncryptFile(inStream_, inStream_, password_);
    }, std::runtime_error);
}

TEST_F(CryptoGuardCtxTest, Decrypt_ImputIsEqualOutput_Exception) {
    ASSERT_THROW({
        ctx_.DecryptFile(inStream_, inStream_, password_);
    }, std::runtime_error);
}

TEST_F(CryptoGuardCtxTest, Encrypt_InvalidInput_Exception) {
    inStream_.setstate(std::ios_base::eofbit | std::ios_base::failbit);
    ASSERT_THROW({
        ctx_.EncryptFile(inStream_, outStream_, password_);
    }, std::runtime_error);
}
TEST_F(CryptoGuardCtxTest, Encrypt_InvalidOutput_Exception) {
    outStream_.setstate(std::ios_base::eofbit | std::ios_base::failbit);
    ASSERT_THROW({
        ctx_.EncryptFile(inStream_, outStream_, password_);
    }, std::runtime_error);
}
TEST_F(CryptoGuardCtxTest, Decrypt_InvalidInput_Exception) {
    inStream_.setstate(std::ios_base::eofbit | std::ios_base::failbit);
    ASSERT_THROW({
        ctx_.DecryptFile(inStream_, outStream_, password_);
    }, std::runtime_error);
}
TEST_F(CryptoGuardCtxTest, Decrypt_InvalidOutput_Exception) {
    outStream_.setstate(std::ios_base::eofbit | std::ios_base::failbit);
    ASSERT_THROW({
        ctx_.DecryptFile(inStream_, outStream_, password_);
    }, std::runtime_error);
}
TEST_F(CryptoGuardCtxTest, CheckSum_InvalidInput_Exception) {
    inStream_.setstate(std::ios_base::eofbit | std::ios_base::failbit);
    ASSERT_THROW({
        auto const result = ctx_.CalculateChecksum(inStream_);
    }, std::runtime_error);
}


// https://emn178.github.io/online-tools/sha256.html
TEST_F(CryptoGuardCtxTest, CheckSum_HelloOpenSSL_Correct) {
    inStream_ << "Hello OpenSSL crypto world!";
    expected_ = "abec80fdd708340513c54b7c6522cd3c9318a5decce7305e48fb1b51da6a4899";

    auto const result = ctx_.CalculateChecksum(inStream_);

    ASSERT_EQ(result, expected_);
}

TEST_F(CryptoGuardCtxTest, CheckSum_EncryptDecript_Correct) {
    inStream_ << "Hello OpenSSL crypto world!";
    password_ = "qwerty12345";
    expected_ = "abec80fdd708340513c54b7c6522cd3c9318a5decce7305e48fb1b51da6a4899";

    ctx_.EncryptFile(inStream_, outStream_, password_);
    
    inStream_.clear(); // now it is output
    ctx_.DecryptFile(outStream_, inStream_, password_);

    auto const result = ctx_.CalculateChecksum(inStream_);

    ASSERT_EQ(result, expected_);
}