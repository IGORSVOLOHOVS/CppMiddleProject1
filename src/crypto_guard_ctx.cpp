#include "crypto_guard_ctx.h"
#include <algorithm>
#include <ios>
#include <istream>
#include <iterator>
#include <memory>
#include <array>
#include <iostream>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <boost/scope/scope_fail.hpp>
#include <print>
#include <stdexcept>
#include <string>
#include <vector>
#include <sstream>      // std::stringstream


namespace CryptoGuard {

    openssl_error::openssl_error(std::string msg): std::runtime_error(std::move(msg)){}
    const char * openssl_error::what () const throw ()
    {
        ERR_error_string(ERR_get_error(), what_message.get());
        return what_message.get();
    }

    class CryptoGuardCtx::Impl{
    public:
        using UniqueEVPCipherCTX = std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX* cp_ctx){ EVP_CIPHER_CTX_free(cp_ctx); })>;
        
        using UniqueEVPMDCTX = std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX* md_ctx){ EVP_MD_CTX_free(md_ctx); })>;
        using UniqueEVPMD = std::unique_ptr<EVP_MD, decltype([](EVP_MD* md){EVP_MD_free(md);})>;
        
        Impl() {
            OpenSSL_add_all_algorithms();
            ERR_load_crypto_strings();
        }
        ~Impl(){
            EVP_cleanup();
        }
        void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password){
            auto fail_guard = boost::scope::make_scope_fail([&inStream, &outStream]
            {
                inStream.clear();
                inStream.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                
                outStream.clear();
                outStream.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            });

            if(inStream.bad() || outStream.bad())
                throw std::runtime_error("inStream.bad() || outStream.bad() is true!");

            
            UniqueEVPCipherCTX ctx{EVP_CIPHER_CTX_new()};

            std::array<unsigned char, CRIPT_BLOCK_SPACE> inBuf{};
            std::array<unsigned char, CRIPT_BLOCK_SPACE + EVP_MAX_BLOCK_LENGTH> outBuf{};
    
            int inLen{0};
            int outLen{0};

            auto params = CreateChiperParamsFromPassword(password);
            params.encrypt = 1;

            // Инициализируем cipher
            if(!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt)){
                throw openssl_error("EVP_CipherInit_ex failed!");
            }

            while(true){
                inStream.read(reinterpret_cast<char*>(&inBuf), CRIPT_BLOCK_SPACE);
                if(inStream.bad()){
                    throw std::runtime_error("inStream.read(reinterpret_cast<char*>(&inBuf), CRIPT_BLOCK_SPACE); failed!");
                }
                
                inLen = inStream.gcount();

                if(inLen <= 0)
                    break;

                if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), inStream.gcount())) {
                    throw openssl_error("EVP_CipherUpdate failed!");
                }

                outStream.write(reinterpret_cast<char*>(&outBuf), outLen);
                if(outStream.bad()){
                    throw std::runtime_error("outStream.write(reinterpret_cast<char*>(&outBuf), outLen); failed!");
                }
            }
            if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
                throw openssl_error("EVP_CipherFinal_ex failed!");
            }

            outStream.write(reinterpret_cast<char*>(&outBuf), outLen);
            if(outStream.bad()){
                throw std::runtime_error("outStream.write(reinterpret_cast<char*>(&outBuf), outLen); failed!");
            }
        }
        void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password){
            auto fail_guard = boost::scope::make_scope_fail([&inStream, &outStream]
            {
                inStream.clear();
                inStream.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                
                outStream.clear();
                outStream.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            });

            if(inStream.bad() || outStream.bad())
                throw std::runtime_error("inStream.bad() || outStream.bad()");

            UniqueEVPCipherCTX ctx{EVP_CIPHER_CTX_new()};

            std::array<unsigned char, CRIPT_BLOCK_SPACE> inBuf{};
            std::array<unsigned char, CRIPT_BLOCK_SPACE + EVP_MAX_BLOCK_LENGTH> outBuf{};
    
            int inLen{0};
            int outLen{0};


            auto params = CreateChiperParamsFromPassword(password);
            params.encrypt = 0;

            // Инициализируем cipher
            if(!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt)){
                throw openssl_error("EVP_CipherInit_ex failed!");
            }

            while(true){
                inStream.read(reinterpret_cast<char*>(&inBuf), CRIPT_BLOCK_SPACE);
                if(inStream.bad()){
                    throw std::runtime_error("inStream.read(reinterpret_cast<char*>(&inBuf), CRIPT_BLOCK_SPACE); failed!");
                }
                inLen = inStream.gcount();

                if(inLen <= 0)
                    break;

                if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), inLen)) {
                    throw openssl_error("EVP_CipherUpdate failed!");
                }

                outStream.write(reinterpret_cast<char*>(&outBuf), outLen);
                if(outStream.bad()){
                    throw std::runtime_error("outStream.write(reinterpret_cast<char*>(&outBuf), outLen); failed!");
                }
            }
            if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
                throw openssl_error("EVP_CipherFinal_ex failed!");
            }

            outStream.write(reinterpret_cast<char*>(&outBuf), outLen);
            if(outStream.bad()){
                throw std::runtime_error("outStream.write(reinterpret_cast<char*>(&outBuf), outLen); failed!");
            }
        }
        std::string CalculateChecksum(std::iostream &inStream) { 
            auto fail_guard = boost::scope::make_scope_fail([&inStream]
            {
                inStream.clear();
                inStream.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            });

            if(inStream.bad())
                throw std::runtime_error("inStream.bad()!");
            
            std::array<unsigned char, CRIPT_BLOCK_SPACE + EVP_MAX_BLOCK_LENGTH> mdBuf{};            
            std::array<unsigned char, CRIPT_BLOCK_SPACE> inBuf{};
            
            unsigned int mdLen{};
            int inLen{0};
            //ERR_error_string(ERR_get_error(), errstr);
            UniqueEVPMD md{(EVP_MD*)EVP_get_digestbyname("SHA256")};
            if(md){
                throw openssl_error("EVP_get_digestbyname failed!");
            }
            
            UniqueEVPMDCTX md_ctx{EVP_MD_CTX_new()};
            if(md_ctx){
                throw openssl_error("EVP_MD_CTX_new() failed!");
            }

            if (!EVP_DigestInit_ex2(md_ctx.get(), md.get(), NULL)) {
                throw openssl_error("EVP_DigestInit_ex2 failed!");
            }

            while(true){
                inStream.read(reinterpret_cast<char*>(&inBuf), CRIPT_BLOCK_SPACE);
                if(inStream.bad()){
                    throw std::runtime_error("inStream.read(reinterpret_cast<char*>(&inBuf), CRIPT_BLOCK_SPACE); failed!");
                }
                inLen = inStream.gcount();

                if(inLen <= 0)
                    break;

                if (!EVP_DigestUpdate(md_ctx.get(), inBuf.data(), inLen)) {
                    throw openssl_error("EVP_DigestUpdate failed!");
                }
            }
            if (!EVP_DigestFinal_ex(md_ctx.get(), mdBuf.data(), &mdLen)) {
                throw openssl_error("EVP_DigestFinal_ex failed!");
            }

            std::stringstream output{};
            for (size_t i = 0; i < mdLen; i++) {
                output << std::hex << mdBuf[i];
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
