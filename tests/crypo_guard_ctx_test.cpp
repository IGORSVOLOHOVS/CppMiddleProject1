#include <gtest/gtest.h>
#include <sstream>
#include <string>

#include "crypto_guard_ctx.h"

using namespace CryptoGuard;

// A failure must arrive as a value, of the kind the caller can tell apart.
template <typename Result>
void ExpectFailure(const Result &result, CryptoErrorKind kind) {
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().kind, kind);
    EXPECT_FALSE(result.error().message.empty());
}

class CryptoGuardCtxTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {
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

    ASSERT_TRUE(ctx_.EncryptFile(inStream_, outStream_, password_));

    std::stringstream decOutStream;
    ASSERT_TRUE(ctx_.DecryptFile(outStream_, decOutStream, password_));

    ASSERT_EQ(expected_, decOutStream.str());
}

TEST_F(CryptoGuardCtxTest, EncryptDecrypt_HelloOpenSSLWrongPassword_Error) {
    expected_ = "Hello OpenSSL crypto world!";
    inStream_ << expected_;

    password_ = "1234";
    ASSERT_TRUE(ctx_.EncryptFile(inStream_, outStream_, password_));
    std::stringstream outStream2_;
    password_ = "12345";

    ExpectFailure(ctx_.DecryptFile(outStream_, outStream2_, password_), CryptoErrorKind::OpenSsl);
}

TEST_F(CryptoGuardCtxTest, Decrypt_EmptyText_Error) {
    password_ = "1234";

    ExpectFailure(ctx_.DecryptFile(inStream_, outStream_, password_), CryptoErrorKind::OpenSsl);
}

TEST_F(CryptoGuardCtxTest, Decrypt_EmptyPassword_Error) {
    inStream_ << "Hello OpenSSL crypto world!";
    password_ = "";

    ExpectFailure(ctx_.DecryptFile(inStream_, outStream_, password_), CryptoErrorKind::OpenSsl);
}

TEST_F(CryptoGuardCtxTest, Encrypt_ImputIsEqualOutput_Error) {
    ExpectFailure(ctx_.EncryptFile(inStream_, inStream_, password_), CryptoErrorKind::Stream);
}

TEST_F(CryptoGuardCtxTest, Decrypt_ImputIsEqualOutput_Error) {
    ExpectFailure(ctx_.DecryptFile(inStream_, inStream_, password_), CryptoErrorKind::OpenSsl);
}

TEST_F(CryptoGuardCtxTest, Encrypt_InvalidInput_Error) {
    inStream_.setstate(std::ios_base::eofbit | std::ios_base::failbit);
    ExpectFailure(ctx_.EncryptFile(inStream_, outStream_, password_), CryptoErrorKind::Stream);
}
TEST_F(CryptoGuardCtxTest, Encrypt_InvalidOutput_Error) {
    outStream_.setstate(std::ios_base::eofbit | std::ios_base::failbit);
    ExpectFailure(ctx_.EncryptFile(inStream_, outStream_, password_), CryptoErrorKind::Stream);
}
TEST_F(CryptoGuardCtxTest, Decrypt_InvalidInput_Error) {
    inStream_.setstate(std::ios_base::eofbit | std::ios_base::failbit);
    ExpectFailure(ctx_.DecryptFile(inStream_, outStream_, password_), CryptoErrorKind::Stream);
}
TEST_F(CryptoGuardCtxTest, Decrypt_InvalidOutput_Error) {
    outStream_.setstate(std::ios_base::eofbit | std::ios_base::failbit);
    ExpectFailure(ctx_.DecryptFile(inStream_, outStream_, password_), CryptoErrorKind::Stream);
}
TEST_F(CryptoGuardCtxTest, CheckSum_InvalidInput_Error) {
    inStream_.setstate(std::ios_base::eofbit | std::ios_base::failbit);
    ExpectFailure(ctx_.CalculateChecksum(inStream_), CryptoErrorKind::Stream);
}

// https://emn178.github.io/online-tools/sha256.html
TEST_F(CryptoGuardCtxTest, CheckSum_HelloOpenSSL_Correct) {
    inStream_ << "Hello OpenSSL crypto world!";
    expected_ = "abec80fdd708340513c54b7c6522cd3c9318a5decce7305e48fb1b51da6a4899";

    auto const result = ctx_.CalculateChecksum(inStream_);

    ASSERT_TRUE(result);
    ASSERT_EQ(*result, expected_);
}

TEST_F(CryptoGuardCtxTest, CheckSum_EncryptDecript_Correct) {
    inStream_ << "Hello OpenSSL crypto world!";
    password_ = "qwerty12345";
    expected_ = "abec80fdd708340513c54b7c6522cd3c9318a5decce7305e48fb1b51da6a4899";

    ASSERT_TRUE(ctx_.EncryptFile(inStream_, outStream_, password_));

    inStream_.clear();  // now it is output
    ASSERT_TRUE(ctx_.DecryptFile(outStream_, inStream_, password_));

    auto const result = ctx_.CalculateChecksum(inStream_);

    ASSERT_TRUE(result);
    ASSERT_EQ(*result, expected_);
}
