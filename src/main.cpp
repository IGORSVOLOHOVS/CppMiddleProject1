#include "cmd_options.h"
#include "crypto_guard_ctx.h"

#include <fstream>
#include <iostream>
#include <ostream>
#include <print>
#include <sstream>

// Привет, Игорь!
// Получил твою работу. Здорово, что ты учёл многие, важные для сдачи работы нюансы 👍.
// Сначала хочу подсветить решения, которые отлично удались:
// Отличное решение, использовать using и unique_ptr с пользовательским удалителем для OpenSSL функций. Отдельно хочу отметить, что ты правильно сделал, что не стал проверять указатель перед удалением, ведь при передаче nullptr OpenSSL отработает корректно
// Хочу отметить, что несмотря на то, что в задании явно этого не было, ты разобрался как получить текстовое сообщение об ошибке и добавил его при выбрасывании исключения.
// Молодец, что стараешься использовать std::array
// Здорово, что ты проверяешь и состояния потоков после записи, и коды возврата OpenSSL функций
// Наконец, хочу отметить хорошее покрытие кода как позитивными, так и негативными тестами!
// У тебя отлично получилось разобраться с OpenSSL и реализовать задуманную нами библиотеку CryptoGuard! К сожалению, я пока не могу принять твою работу по следующим причинам:

// В С++ не надо использовать Си строки
// используется уже удалённый из стандарта throw()
// закомментированный код в файлах библиотеки и тестах
// не проверяется результат работы Parse
// нет сообщений об ошибках в случае неудачной обработки аргументов командной строки
// в main для шифрования/де-шифрования используется промежуточный буфер
// всегда проверяй что input != output - такое часто забывают и вместо красивой ошибки могут получить какой-нибудь SEGFAULT
// нет сообщений об ошибках в случае ошибок в обработке командной строки
// можно запустить вычисление контрольной суммы с параметрами output/password
// Также, я бы хотел подсветить некоторые моменты, которые помогут тебе в будущем:
// в тестах лучше использовать имена expected и result
// используй говорящие названия переменных и не используй 1, 2, ...
// Обрати внимание, что у потоков есть 2 флага плохого состояния: fail() и bad(). Лучше использовать флаг fail() так как он покрывает больше "плохих". Подробнее о разнице можно почитать тут: https://en.cppreference.com/w/cpp/io/basic_ios/fail
// Один из наиболее полезных атрибутов в C++ - [[nodiscard]], чтобы гарантировать, что пользователь не сможет игнорировать результат работы функции. Это особенно полезно, при работе с функциями, возвращающими код ошибки. В твоём коде это можно было бы применить для функции Parse / CalculateChecksum. Подробнее об этом можно почитать тут https://en.cppreference.com/w/cpp/language/attributes/nodiscard
// Несмотря на комментарии, ты проделал отличную работу по реализации функционала шифрования и дешифрования файлов! Более того, код хорошо структурирован и использует современные практики C++.
// Удачи!

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