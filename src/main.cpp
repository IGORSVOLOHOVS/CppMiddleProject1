#include "cmd_options.h"
#include "crypto_guard_ctx.h"

#include <fstream>
#include <iostream>
#include <ostream>
#include <print>
#include <stdexcept>

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        if(!options.Parse(argc, argv))
            throw std::runtime_error("options.Parse(argc, argv) returns false!");

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        auto const inputStr = options.GetInputFile();
        auto const outputStr = options.GetOutputFile();
        auto const password = options.GetPassword();

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT:
        {
            // Open input file
            std::fstream inStream(inputStr, std::ios::in);
            if (!inStream.is_open()) {
                throw std::runtime_error(std::format("Open file error: {}", inputStr));
            }
           
            // Open output file
            std::fstream outStream(outputStr, std::ios::out);
            if (!outStream.is_open()) {
                throw std::runtime_error(std::format("Open file error: {}", outputStr));
            }
            cryptoCtx.EncryptFile(inStream, outStream, password);

            // Encrypt file
            std::print("Input file {} was encrypted successfuly in output file {}.\n", inputStr, outputStr);
            break;
        }
        case COMMAND_TYPE::DECRYPT:
        {
            // Open input file
            std::fstream inStream(inputStr, std::ios::in);
            if (!inStream.is_open()) {
                throw std::runtime_error(std::format("Open file error: {}", inputStr));
            }
           
            // Open output file
            std::fstream outStream(outputStr, std::ios::out);
            if (!outStream.is_open()) {
                throw std::runtime_error(std::format("Open file error: {}", outputStr));
            }
            cryptoCtx.DecryptFile(inStream, outStream, password);
            

            std::print("Input file {} was decrypted successfuly in output file {}.\n", inputStr, outputStr);
            break;
        }
        case COMMAND_TYPE::CHECKSUM:
        {
            // Open input file
            std::fstream inStream(inputStr, std::ios::in);
            if (!inStream.is_open()) {
                throw std::runtime_error(std::format("Open file error: {}", inputStr));
            }

            // Calculate checksum
            auto const checkSum = cryptoCtx.CalculateChecksum(inStream);

            std::print("Check sum of input file {} was calculated successfuly.\nResult: {}\n", inputStr, checkSum);
            break;
        }

        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}