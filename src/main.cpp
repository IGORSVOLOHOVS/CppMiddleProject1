#include "cmd_options.h"
#include "crypto_guard_ctx.h"

#include <fstream>
#include <iostream>
#include <ostream>
#include <print>
#include <sstream>

std::string HexView(std::iostream& inStream){
    std::string output{};
    
    char c;
    while (inStream.get(c)) {
        output.append(std::format("{:x}", c));
    }

    return output;
}

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

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
           
            std::stringstream outStream;
            cryptoCtx.EncryptFile(inStream, outStream, password);
            
            // Open output file
            std::fstream outStreamFile(outputStr, std::ios::out);
            if (!outStreamFile.is_open()) {
                throw std::runtime_error(std::format("Open file error: {}", outputStr));
            }
            outStreamFile << outStream.str();

            // Encrypt file

            std::print("Input file {} was encrypted successfuly in output file {}.\n", inputStr, outputStr);
            std::print("Result: {}\n", HexView(outStream));
            break;
        }
        case COMMAND_TYPE::DECRYPT:
        {
            // Open input file
            std::fstream inStream(inputStr, std::ios::in);
            if (!inStream.is_open()) {
                throw std::runtime_error(std::format("Open file error: {}", inputStr));
            }
           
            std::stringstream outStream;
            cryptoCtx.DecryptFile(inStream, outStream, password);
            
            // Open output file
            std::fstream outStreamFile(outputStr, std::ios::out);
            if (!outStreamFile.is_open()) {
                throw std::runtime_error(std::format("Open file error: {}", outputStr));
            }
            outStreamFile << outStream.str();

            std::print("Input file {} was decrypted successfuly in output file {}.\n", inputStr, outputStr);
            std::print("Result: {}\n", outStream.str());
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

            std::print("Check sum of input file {} was calculated successfuly.\n", inputStr);
            std::print("Result: {}\n", checkSum);
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