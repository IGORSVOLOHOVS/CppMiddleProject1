#include "cmd_options.h"

#include <exception>
#include <iostream>
#include <print>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    namespace po = boost::program_options;

    desc_.add_options()
    ("help,h", "list of available options;")
    ("command,c", po::value<std::string>(), "encrypt, decrypt or checksum command;")
    ("input,i", po::value<std::string>(), "path to the input file;")
    ("output,o", po::value<std::string>(), "path to the file where the result will be saved;")
    ("password,p", po::value<std::string>(), "password for encryption and decryption.")
;
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) { 
    if(argc < 2) {
        std::cout << desc_ << std::endl;
        throw std::runtime_error{"No arguments!"};
    }

    namespace po = boost::program_options;

    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc, argv, desc_), vm);
    } catch (std::exception const& e){
        std::cout << desc_ << std::endl;
        throw std::runtime_error{std::format("Parsingrror: {}", e.what())};
    }    
    po::notify(vm);    

    // if help exists - print info
    if (vm.count("help")) {
        std::cout << desc_ << std::endl;
        throw std::runtime_error{"No arguments!"};
    }

    if(!vm.count("input") || !vm.count("command")) {
        throw std::runtime_error{"Not all mandatory args were provided: no input or command"};
    }

    
    const auto command = vm["command"].as<std::string>();
    if(!commandMapping_.contains(command)) 
    {
        throw std::runtime_error{std::format("Invalid command: {}", command)};
    }
    
    command_ = commandMapping_.at(command);
    inputFile_ = vm["input"].as<std::string>();

    switch (command_) {
        case ProgramOptions::COMMAND_TYPE::ENCRYPT:{
            if(vm.count("password") && vm.count("output")){
                password_ = vm["password"].as<std::string>();
                outputFile_ = vm["output"].as<std::string>();
                return;
            }
            throw std::runtime_error{"Not all mandatory args were provided: no password or output!"};
            break;
        }
        case ProgramOptions::COMMAND_TYPE::DECRYPT:{
            if(vm.count("password") && vm.count("output")){
                password_ = vm["password"].as<std::string>();
                outputFile_ = vm["output"].as<std::string>();
                return;
            }
            throw std::runtime_error{"Not all mandatory args were provided: no password or output!"};
            break;
        }
        case ProgramOptions::COMMAND_TYPE::CHECKSUM:{
            return;
        }
        default:
            break;
    }

    throw std::runtime_error("Something is wrong!");
}
}  // namespace CryptoGuard
