#include "cmd_options.h"

#include <exception>
#include <iostream>
#include <print>

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
    if(argc < 2) {
        std::cout << desc_ << std::endl;
        return true;
    }

    namespace po = boost::program_options;

    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc, argv, desc_), vm);
    } catch (std::exception const& e){
        std::print("ProgramOptions error: {}\n", e.what());
        return false;
    }    
    po::notify(vm);    

    // if help exists - print info
    if (vm.count("help")) {
        std::cout << desc_ << std::endl;
        return true;
    }else if(vm.count("input") && vm.count("command")){
        inputFile_ = vm["input"].as<std::vector<std::string>>().front();
        const auto command = vm["command"].as<std::vector<std::string>>().front();
        
        if(commandMapping_.contains(command))
            command_ = commandMapping_.at(command);
        else 
            return false;

        switch (command_) {
            case ProgramOptions::COMMAND_TYPE::ENCRYPT:{
                if(vm.count("password") && vm.count("output")){
                    password_ = vm["password"].as<std::vector<std::string>>().front();
                    outputFile_ = vm["output"].as<std::vector<std::string>>().front();
                    return true;
                }
                break;
            }
            case ProgramOptions::COMMAND_TYPE::DECRYPT:{
                if(vm.count("password") && vm.count("output")){
                    password_ = vm["password"].as<std::vector<std::string>>().front();
                    outputFile_ = vm["output"].as<std::vector<std::string>>().front();
                    return true;
                }
                break;
            }
            case ProgramOptions::COMMAND_TYPE::CHECKSUM:{
                return true;
            }
            default:
                break;
        }
        return false;
    }else{
        return false;
    }

    return false; 
}
}  // namespace CryptoGuard
