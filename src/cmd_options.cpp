#include "cmd_options.h"

#include <iostream>

// Разработайте класс ProgramOptions:
// Изучите документацию о классе boost::program_options по ссылкам:

// https://www.boost.org/doc/libs/1_63_0/doc/html/program_options.html;
// https://www.boost.org/doc/libs/1_63_0/doc/html/program_options/tutorial.html.

// Реализуйте конструктор, который настроит парсер командной строки с помощью boost::program_options для следующих опций:
    // help — список доступных опций;
    // command — команда encrypt, decrypt или checksum;
    // input — путь до входного файла;
    // output — путь до файла, в котором будет сохранён результат;
    // password — пароль для шифрования и дешифрования.
// Добавьте обработку перечисленных опций с соответствующими параметрами (например, входные и выходные данные для шифрования файла) и их проверку.
// Реализуйте маппинг строковых команд на enum COMMAND_TYPE.

// Добавьте вызов метода Parse(), который в случае ошибки будет выводить сообщение об ошибке, а при выборе help — список доступных опций.


namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    namespace po = boost::program_options;

    desc_.add_options()
    ("help,h", "list of available options;")
    ("command,c", po::value<std::vector<std::string>>(), "encrypt, decrypt or checksum command;")
    ("input,i", po::value<std::vector<std::string>>(), "path to the input file;")
    ("output,o", po::value<std::vector<std::string>>(), "path to the file where the result will be saved;")
    ("password,p", po::value<std::vector<std::string>>(), "password for encryption and decryption.")
;
}

ProgramOptions::~ProgramOptions() = default;

bool ProgramOptions::Parse(int argc, char *argv[]) { 
    if(argc < 2) return false;

    namespace po = boost::program_options;

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);
    po::notify(vm);    

    // if help exists - print info
    if (vm.count("help")) {
        std::cout << desc_ << std::endl;
        return true;
    }

    // if command esists, parse it, if command without arg - return false
    if (vm.count("command")) {
        auto cmds = vm["command"].as<std::vector<std::string>>();

        if(commandMapping_.contains(cmds.front()))
            command_ = commandMapping_.at(cmds.front());
        else 
            return false;
    }

    // if input esists, parse it, if input without arg - return false
    if (vm.count("input")) {
        auto cmds = vm["input"].as<std::vector<std::string>>();

        if(cmds.empty())
            return false;

        inputFile_ = cmds.front();
    }

    // if output esists, parse it, if output without arg - return false
    if (vm.count("output")) {
        auto cmds = vm["output"].as<std::vector<std::string>>();

        if(cmds.empty())
            return false;

        outputFile_ = cmds.front();
    }

    // if password esists, parse it, if password without arg - return false
    if (vm.count("password")) {
        auto cmds = vm["password"].as<std::vector<std::string>>();

        if(cmds.empty())
            return false;

        password_ = cmds.front();
    }
    
    return true; 
}
}  // namespace CryptoGuard
