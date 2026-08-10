#include "cmd_options.h"
#include "crypto_guard_ctx.h"

#include <fstream>
#include <iostream>
#include <ostream>
#include <print>
#include <stdexcept>

std::fstream GetFilestream(std::string_view filename, std::ios::openmode mode){
    // std::ios::binary добавляется всегда. На Linux флаг ничего не меняет, а на
    // Windows без него поток работает в текстовом режиме и портит шифртекст:
    // при записи 0x0A превращается в 0x0D 0x0A, при чтении 0x1A обрывает файл.
    // Проявляется как "wrong final block length" на расшифровке.
    std::fstream file(filename.data(), mode | std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error(std::format("Open file error: {}", filename));
    }
    return file;
}

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        auto const inputStr = options.GetInputFile();
        auto const password = options.GetPassword();
        auto const outputStr = options.GetOutputFile();

        if(inputStr == outputStr){
            throw std::runtime_error(std::format("Names of input and output files are the same: {}", inputStr));
        }
        
        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT:
        {
            std::fstream inStream = GetFilestream(inputStr, std::ios::in);
            std::fstream outStream = GetFilestream(outputStr, std::ios::out);

            cryptoCtx.EncryptFile(inStream, outStream, password);

            std::print("Input file {} was encrypted successfuly in output file {}.\n", inputStr, outputStr);
            break;
        }
        case COMMAND_TYPE::DECRYPT:
        {
            std::fstream inStream = GetFilestream(inputStr, std::ios::in);
            std::fstream outStream = GetFilestream(outputStr, std::ios::out);

            cryptoCtx.DecryptFile(inStream, outStream, password);
            
            std::print("Input file {} was decrypted successfuly in output file {}.\n", inputStr, outputStr);
            break;
        }
        case COMMAND_TYPE::CHECKSUM:
        {
            std::fstream inStream = GetFilestream(inputStr, std::ios::in);

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