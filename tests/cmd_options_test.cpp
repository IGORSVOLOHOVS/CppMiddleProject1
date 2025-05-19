#include <memory>
#include <print>
#include <gtest/gtest.h>

#include <array>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>

#include "cmd_options.h"

using namespace CryptoGuard;

constexpr unsigned int TEST_ARG_MAX_COUNT = 100;

class ProgramOptionsTest: public ::testing::Test{
protected:
    void SetUp() override{
    }
    void TearDown() override{
        argc_ = 0;
        for (unsigned int  i = 0; i < TEST_ARG_MAX_COUNT; i++) {
            argv_[i] = const_cast<char*>("");
        }
    }

    int argc_;
    std::array<char*, TEST_ARG_MAX_COUNT> argv_;

    ProgramOptions po_{};
};


TEST_F(ProgramOptionsTest, Parse_Help_Exception) { 
    argv_[argc_++] = const_cast<char*>("./CryptoGuard");
    argv_[argc_++] = const_cast<char*>("--help");

    ASSERT_THROW({
        po_.Parse(argc_, argv_.data());
    }, std::runtime_error);
}

TEST_F(ProgramOptionsTest, Parse_HelpAndOtherArg_Exception) { 
    argv_[argc_++] = const_cast<char*>("./CryptoGuard");
    argv_[argc_++] = const_cast<char*>("-i");
    argv_[argc_++] = const_cast<char*>("input.txt");
    argv_[argc_++] = const_cast<char*>("-o");
    argv_[argc_++] = const_cast<char*>("encrypted.txt");
    argv_[argc_++] = const_cast<char*>("-p");
    argv_[argc_++] = const_cast<char*>("1234");
    argv_[argc_++] = const_cast<char*>("--command");
    argv_[argc_++] = const_cast<char*>("decrypt");
    argv_[argc_++] = const_cast<char*>("--help");

    ASSERT_THROW({
        po_.Parse(argc_, argv_.data());
    }, std::runtime_error);
}

TEST_F(ProgramOptionsTest, ParseGetCommand_CommandEncrypt_True) { 
    argv_[argc_++] = const_cast<char*>("./CryptoGuard");
    argv_[argc_++] = const_cast<char*>("-i");
    argv_[argc_++] = const_cast<char*>("input.txt");
    argv_[argc_++] = const_cast<char*>("-o");
    argv_[argc_++] = const_cast<char*>("encrypted.txt");
    argv_[argc_++] = const_cast<char*>("-p");
    argv_[argc_++] = const_cast<char*>("1234");
    argv_[argc_++] = const_cast<char*>("--command");
    argv_[argc_++] = const_cast<char*>("encrypt");

    po_.Parse(argc_, argv_.data());
    ASSERT_EQ(po_.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
}
TEST_F(ProgramOptionsTest, ParseGetCommand_CommandDecrypt_True) { 
    argv_[argc_++] = const_cast<char*>("./CryptoGuard");
    argv_[argc_++] = const_cast<char*>("-i");
    argv_[argc_++] = const_cast<char*>("input.txt");
    argv_[argc_++] = const_cast<char*>("-o");
    argv_[argc_++] = const_cast<char*>("encrypted.txt");
    argv_[argc_++] = const_cast<char*>("-p");
    argv_[argc_++] = const_cast<char*>("1234");
    argv_[argc_++] = const_cast<char*>("--command");
    argv_[argc_++] = const_cast<char*>("decrypt");

    po_.Parse(argc_, argv_.data());
    ASSERT_EQ(po_.GetCommand(), ProgramOptions::COMMAND_TYPE::DECRYPT);
}
TEST_F(ProgramOptionsTest, ParseGetCommand_CommandCheckSum_True) { 
    argv_[argc_++] = const_cast<char*>("./CryptoGuard");
    argv_[argc_++] = const_cast<char*>("-i");
    argv_[argc_++] = const_cast<char*>("input.txt");
    argv_[argc_++] = const_cast<char*>("-o");
    argv_[argc_++] = const_cast<char*>("encrypted.txt");
    argv_[argc_++] = const_cast<char*>("-p");
    argv_[argc_++] = const_cast<char*>("1234");
    argv_[argc_++] = const_cast<char*>("--command");
    argv_[argc_++] = const_cast<char*>("checksum");

    po_.Parse(argc_, argv_.data());
    ASSERT_EQ(po_.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
}
TEST_F(ProgramOptionsTest, ParseGetCommand_UnknownCommand_Exception) { 
    argv_[argc_++] = const_cast<char*>("./CryptoGuard");
    argv_[argc_++] = const_cast<char*>("--input");
    argv_[argc_++] = const_cast<char*>("input.txt");
    argv_[argc_++] = const_cast<char*>("--command");
    argv_[argc_++] = const_cast<char*>("getpassword");
    argv_[argc_++] = const_cast<char*>("--password");
    argv_[argc_++] = const_cast<char*>("1234");   
    argv_[argc_++] = const_cast<char*>("--output");
    argv_[argc_++] = const_cast<char*>("encrypted.txt");

    ASSERT_THROW({
        po_.Parse(argc_, argv_.data());
    }, std::runtime_error);
}

TEST_F(ProgramOptionsTest, Parse_EmptyInput_Exception) { 
    argv_[argc_++] = const_cast<char*>("./CryptoGuard");
    argv_[argc_++] = const_cast<char*>("--input");
    argv_[argc_++] = const_cast<char*>("--command");
    argv_[argc_++] = const_cast<char*>("checksum");
    argv_[argc_++] = const_cast<char*>("--password");
    argv_[argc_++] = const_cast<char*>("1234");   
    argv_[argc_++] = const_cast<char*>("--output");

    ASSERT_THROW({
        po_.Parse(argc_, argv_.data());
    }, std::runtime_error);
}
TEST_F(ProgramOptionsTest, ParseGetInputFile_Input_True) { 
    argv_[argc_++] = const_cast<char*>("./CryptoGuard");
    argv_[argc_++] = const_cast<char*>("--input");
    argv_[argc_++] = const_cast<char*>("input.txt");
    argv_[argc_++] = const_cast<char*>("--command");
    argv_[argc_++] = const_cast<char*>("checksum");

    po_.Parse(argc_, argv_.data());
    ASSERT_EQ(po_.GetInputFile(), "input.txt");
}
TEST_F(ProgramOptionsTest, Parse_EmptyOutput_Exception) { 
    argv_[argc_++] = const_cast<char*>("./CryptoGuard");
    argv_[argc_++] = const_cast<char*>("--input");
    argv_[argc_++] = const_cast<char*>("input.txt");
    argv_[argc_++] = const_cast<char*>("--command");
    argv_[argc_++] = const_cast<char*>("checksum");
    argv_[argc_++] = const_cast<char*>("--password");
    argv_[argc_++] = const_cast<char*>("1234");   
    argv_[argc_++] = const_cast<char*>("--output");

    ASSERT_THROW({
        po_.Parse(argc_, argv_.data());
    }, std::runtime_error);
}
TEST_F(ProgramOptionsTest, ParseGetOutputFile_Output_True) { 
    argv_[argc_++] = const_cast<char*>("./CryptoGuard");
    argv_[argc_++] = const_cast<char*>("--input");
    argv_[argc_++] = const_cast<char*>("input.txt");
    argv_[argc_++] = const_cast<char*>("--command");
    argv_[argc_++] = const_cast<char*>("encrypt");
    argv_[argc_++] = const_cast<char*>("--password");
    argv_[argc_++] = const_cast<char*>("1234");   
    argv_[argc_++] = const_cast<char*>("--output");
    argv_[argc_++] = const_cast<char*>("encrypted.txt");

    po_.Parse(argc_, argv_.data());
    ASSERT_EQ(po_.GetOutputFile(), "encrypted.txt");
}
TEST_F(ProgramOptionsTest, Parse_EmptyPassword_Exception) { 
    argv_[argc_++] = const_cast<char*>("./CryptoGuard");
    argv_[argc_++] = const_cast<char*>("--input");
    argv_[argc_++] = const_cast<char*>("input.txt");
    argv_[argc_++] = const_cast<char*>("--command");
    argv_[argc_++] = const_cast<char*>("encrypt");
    argv_[argc_++] = const_cast<char*>("--password");
    argv_[argc_++] = const_cast<char*>("--output");
    argv_[argc_++] = const_cast<char*>("encrypted.txt");

    ASSERT_THROW({
        po_.Parse(argc_, argv_.data());
    }, std::runtime_error);
}
TEST_F(ProgramOptionsTest, ParseGetPassword_Password_True) { 
    argv_[argc_++] = const_cast<char*>("./CryptoGuard");
    argv_[argc_++] = const_cast<char*>("--input");
    argv_[argc_++] = const_cast<char*>("input.txt");
    argv_[argc_++] = const_cast<char*>("--command");
    argv_[argc_++] = const_cast<char*>("encrypt");
    argv_[argc_++] = const_cast<char*>("--password");
    argv_[argc_++] = const_cast<char*>("1234");   
    argv_[argc_++] = const_cast<char*>("--output");
    argv_[argc_++] = const_cast<char*>("encrypted.txt");

    po_.Parse(argc_, argv_.data());
    ASSERT_EQ(po_.GetPassword(), "1234");
}

TEST_F(ProgramOptionsTest, Parse_Aliases_True){
    argv_[argc_++] = const_cast<char*>("./CryptoGuard");
    argv_[argc_++] = const_cast<char*>("-i");
    argv_[argc_++] = const_cast<char*>("input.txt");
    argv_[argc_++] = const_cast<char*>("-o");
    argv_[argc_++] = const_cast<char*>("encrypted.txt");
    argv_[argc_++] = const_cast<char*>("-p");
    argv_[argc_++] = const_cast<char*>("1234");
    argv_[argc_++] = const_cast<char*>("-c");
    argv_[argc_++] = const_cast<char*>("encrypt");

    po_.Parse(argc_, argv_.data());

    ASSERT_EQ(po_.GetInputFile(), "input.txt");
    ASSERT_EQ(po_.GetOutputFile(), "encrypted.txt");
    ASSERT_EQ(po_.GetPassword(), "1234");
    ASSERT_EQ(po_.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
}

TEST_F(ProgramOptionsTest, Parse_AliasesMix_True){
    argv_[argc_++] = const_cast<char*>("./CryptoGuard");
    argv_[argc_++] = const_cast<char*>("-i");
    argv_[argc_++] = const_cast<char*>("input.txt");
    argv_[argc_++] = const_cast<char*>("-o");
    argv_[argc_++] = const_cast<char*>("encrypted.txt");
    argv_[argc_++] = const_cast<char*>("-p");
    argv_[argc_++] = const_cast<char*>("1234");
    argv_[argc_++] = const_cast<char*>("--command");
    argv_[argc_++] = const_cast<char*>("encrypt");

    po_.Parse(argc_, argv_.data());

    ASSERT_EQ(po_.GetInputFile(), "input.txt");
    ASSERT_EQ(po_.GetOutputFile(), "encrypted.txt");
    ASSERT_EQ(po_.GetPassword(), "1234");
    ASSERT_EQ(po_.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
}

TEST_F(ProgramOptionsTest, Parse_NoOptions_Exception){
    // print help info if no arguments
    argv_[argc_++] = const_cast<char*>("./CryptoGuard");
    
    ASSERT_THROW({
        po_.Parse(argc_, argv_.data());
    }, std::runtime_error);
}

TEST_F(ProgramOptionsTest, Parse_DoubleArgInit_Exception){
    argv_[argc_++] = const_cast<char*>("./CryptoGuard");
    argv_[argc_++] = const_cast<char*>("-i");
    argv_[argc_++] = const_cast<char*>("input1.txt");
    argv_[argc_++] = const_cast<char*>("-o");
    argv_[argc_++] = const_cast<char*>("encrypted.txt");
    argv_[argc_++] = const_cast<char*>("-p");
    argv_[argc_++] = const_cast<char*>("1234");
    argv_[argc_++] = const_cast<char*>("--command");
    argv_[argc_++] = const_cast<char*>("encrypt");
    argv_[argc_++] = const_cast<char*>("-i");
    argv_[argc_++] = const_cast<char*>("input2.txt");

    ASSERT_THROW({
        po_.Parse(argc_, argv_.data());
    }, std::runtime_error);
}
TEST_F(ProgramOptionsTest, Parse_CheckSumOutputPassword_Exception) { 
    argv_[argc_++] = const_cast<char*>("./CryptoGuard");
    argv_[argc_++] = const_cast<char*>("-o");
    argv_[argc_++] = const_cast<char*>("encrypted.txt");
    argv_[argc_++] = const_cast<char*>("-p");
    argv_[argc_++] = const_cast<char*>("1234");
    argv_[argc_++] = const_cast<char*>("--command");
    argv_[argc_++] = const_cast<char*>("checksum");

    ASSERT_THROW({
        po_.Parse(argc_, argv_.data());
    }, std::runtime_error);
}