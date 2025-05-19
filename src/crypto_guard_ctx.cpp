#include "crypto_guard_ctx.h"
#include <iomanip>
#include <ios>
#include <istream>
#include <memory>
#include <array>
#include <iostream>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <print>
#include <stdexcept>
#include <string>
#include <sstream>     


namespace CryptoGuard {

    openssl_error::openssl_error(std::string msg): std::runtime_error(std::move(msg)){
        what_message.reserve(ERROR_MSG_SIZE);
    }
    const char * openssl_error::what () const noexcept
    {
        ERR_error_string(ERR_get_error(), const_cast<char*>(what_message.data()));
        return what_message.c_str();
    }

    class CryptoGuardCtx::Impl{
    public:
        using UniqueEVPCipherCTX = std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX* cp_ctx){ EVP_CIPHER_CTX_free(cp_ctx); })>;
        
        using UniqueEVPMDCTX = std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX* md_ctx){ EVP_MD_CTX_free(md_ctx); })>;
        using UniqueEVPMD = std::unique_ptr<const EVP_MD, decltype([](const EVP_MD* md){EVP_MD_free(const_cast<EVP_MD*>(md));})>;
        
        Impl() {
            OpenSSL_add_all_algorithms();
            ERR_load_crypto_strings();
        }
        ~Impl(){
            EVP_cleanup();
        }
        void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password){
            if(inStream.fail() || outStream.fail())
                throw std::runtime_error("I/O streams are in invalid state!");

            
            UniqueEVPCipherCTX ctx{EVP_CIPHER_CTX_new()};

            std::array<unsigned char, CRIPT_BLOCK_SIZE> inBuf{};
            std::array<unsigned char, CRIPT_BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH> outBuf{};
    
            int inLen{0};
            int outLen{0};

            auto params = CreateChiperParamsFromPassword(password);
            params.encrypt = 1;

            // Инициализируем cipher
            if(!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt)){
                throw openssl_error("EVP_CipherInit_ex failed!");
            }

            while (!inStream.eof()) {
                if (inStream.fail()) {
                    throw std::runtime_error("Input stream is in invalid state!");
                }
                inStream.read(reinterpret_cast<char*>(inBuf.data()), inBuf.size());
                inLen = inStream.gcount();

                if(inLen > 0){
                    if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), inStream.gcount())) {
                        throw openssl_error("EVP_CipherUpdate failed!");
                    }

                    if(outLen > 0){
                        outStream.write(reinterpret_cast<char*>(outBuf.data()), outLen);
                        if(outStream.fail()){
                            throw std::runtime_error("Failed to write to file!");
                        }
                    }
                }
            }
            if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
                throw openssl_error("EVP_CipherFinal_ex failed!");
            }

            if(outLen > 0){
                outStream.write(reinterpret_cast<char*>(outBuf.data()), outLen);
                if(outStream.fail()){
                    throw std::runtime_error("Failed to write to file!");
                }
            }
        }
        void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password){
            if(inStream.fail() || outStream.fail())
                throw std::runtime_error("I/O streams are in invalid state!");

            
            UniqueEVPCipherCTX ctx{EVP_CIPHER_CTX_new()};

            std::array<unsigned char, CRIPT_BLOCK_SIZE> inBuf{};
            std::array<unsigned char, CRIPT_BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH> outBuf{};
    
            int inLen{0};
            int outLen{0};

            auto params = CreateChiperParamsFromPassword(password);
            params.encrypt = 0;

            // Инициализируем cipher
            if(!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt)){
                throw openssl_error("EVP_CipherInit_ex failed!");
            }

            while (!inStream.eof()) {
                if (inStream.fail()) {
                    throw std::runtime_error("Input stream is in invalid state!");
                }
                inStream.read(reinterpret_cast<char*>(inBuf.data()), inBuf.size());
                inLen = inStream.gcount();

                if(inLen > 0){
                    if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), inStream.gcount())) {
                        throw openssl_error("EVP_CipherUpdate failed!");
                    }

                    if(outLen > 0){
                        outStream.write(reinterpret_cast<char*>(outBuf.data()), outLen);
                        if(outStream.fail()){
                            throw std::runtime_error("Failed to write to file!");
                        }
                    }
                }
            }
            if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
                throw openssl_error("EVP_CipherFinal_ex failed!");
            }

            if(outLen > 0){
                outStream.write(reinterpret_cast<char*>(outBuf.data()), outLen);
                if(outStream.fail()){
                    throw std::runtime_error("Failed to write to file!");
                }
            }
        }
        std::string CalculateChecksum(std::iostream &inStream) { 
            if(inStream.fail())
                throw std::runtime_error("Input stream is in invalid state!");
            
            std::array<unsigned char, EVP_MAX_BLOCK_LENGTH> mdBuf{};            
            std::array<unsigned char, CRIPT_BLOCK_SIZE> inBuf{};
            
            unsigned int mdLen{};
            int inLen{0};

            UniqueEVPMD md{EVP_sha256()};
            UniqueEVPMDCTX md_ctx{EVP_MD_CTX_new()};

            if (!EVP_DigestInit_ex2(md_ctx.get(), md.get(), NULL)) {
                throw openssl_error("EVP_DigestInit_ex2 failed!");
            }

            while (!inStream.eof()) {
                if (inStream.fail()) {
                    throw std::runtime_error("Input stream is in invalid state!");
                }
                inStream.read(reinterpret_cast<char*>(inBuf.data()), inBuf.size());
                inLen = inStream.gcount();

                if(inLen > 0){
                    if (!EVP_DigestUpdate(md_ctx.get(), inBuf.data(), inLen)) {
                        throw openssl_error("EVP_DigestUpdate failed!");
                    }
                }
            }

            if (!EVP_DigestFinal_ex(md_ctx.get(), mdBuf.data(), &mdLen)) {
                throw openssl_error("EVP_DigestFinal_ex failed!");
            }

            std::stringstream output{};
            output << std::hex << std::setfill('0'); 
            for (size_t i = 0; i < mdLen; i++) {
                output << std::setw(2) << static_cast<int>(mdBuf[i]); 
            }
            return output.str();
        }
    private:
        struct AesCipherParams {
            static const size_t KEY_SIZE = 32;             // AES-256 key size
            static const size_t IV_SIZE = 16;              // AES block size (IV length)
            const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm
        
            int encrypt;                              // 1 for encryption, 0 for decryption
            std::array<unsigned char, KEY_SIZE> key;  // Encryption key
            std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
        };
        
        AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
            AesCipherParams params;
            constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

            int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                        reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                        params.key.data(), params.iv.data());

            if (result == 0) {
                throw std::runtime_error{"Failed to create a key from password"};
            }

            return params;
        }
    };

    CryptoGuardCtx::CryptoGuardCtx(): pImpl_(std::make_unique<Impl>()){}
    CryptoGuardCtx::~CryptoGuardCtx(){}

    // API
    void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password){
        pImpl_->EncryptFile(inStream, outStream, password);
    }
    void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password){
        pImpl_->DecryptFile(inStream, outStream, password);
    }
    std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { 
        return pImpl_->CalculateChecksum(inStream);
    }
}  // namespace CryptoGuard
