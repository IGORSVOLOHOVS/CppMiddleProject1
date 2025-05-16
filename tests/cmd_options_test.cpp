#include <exception>
#include <gtest/gtest.h>

#include "cmd_options.h"

using namespace CryptoGuard;

TEST(ProgramOptions, Help) { 
    ProgramOptions po;

    int argc = 2;
    char *argv[] = { "./CryptoGuard","--help"};

    ASSERT_TRUE(po.Parse(argc, argv)); 
}
TEST(ProgramOptions, Command) { 
    // empty command - return false
    {
        ProgramOptions po;
        int argc = 2;
        char *argv[] = { "./CryptoGuard","--command"};
        try {
            po.Parse(argc, argv);
            FAIL() << "FAIL !!!";
        }
        catch(std::exception const & err) {
            EXPECT_EQ(err.what(),std::string("the required argument for option '--command' is missing"));
        }
        catch(...) {
            FAIL() << "FAIL !!!";
        }
    } 

    // empty command - return false
    {
        ProgramOptions po;
        int argc = 3;
        char *argv[] = { "./CryptoGuard","--command", "encrypt"};

        ASSERT_TRUE(po.Parse(argc, argv));
        ASSERT_EQ(po.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
    } 

    // empty command - return false
    {
        ProgramOptions po;
        int argc = 3;
        char *argv[] = { "./CryptoGuard","--command", "decrypt"};

        ASSERT_TRUE(po.Parse(argc, argv));
        ASSERT_EQ(po.GetCommand(), ProgramOptions::COMMAND_TYPE::DECRYPT);
    } 

    // encrypt command - return true
    {
        ProgramOptions po;
        int argc = 3;
        char *argv[] = { "./CryptoGuard","--command", "checksum"};

        ASSERT_TRUE(po.Parse(argc, argv));
        ASSERT_EQ(po.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
    } 

    // diff command type - return false
    {
        ProgramOptions po;
        int argc = 3;
        char *argv[] = { "./CryptoGuard","--command", "getpassword"};

        ASSERT_FALSE(po.Parse(argc, argv));
    } 
 }
TEST(ProgramOptions, Input) { 
    // empty input - return false
    {
        ProgramOptions po;
        int argc = 2;
        char *argv[] = { "./CryptoGuard","--input"};
        try {
            po.Parse(argc, argv);
            FAIL() << "FAIL !!!";
        }
        catch(std::exception const & err) {
            EXPECT_EQ(err.what(),std::string("the required argument for option '--input' is missing"));
        }
        catch(...) {
            FAIL() << "FAIL !!!";
        }
    } 

    // input filename - return true
    {
        ProgramOptions po;
        int argc = 3;
        char *argv[] = { "./CryptoGuard","--input", "input.txt"};

        ASSERT_TRUE(po.Parse(argc, argv));
        ASSERT_EQ(po.GetInputFile(), "input.txt");
    }
}
TEST(ProgramOptions, Output) { 
    // empty output - return false
    {
        ProgramOptions po;
        int argc = 2;
        char *argv[] = { "./CryptoGuard","--output"};
        try {
            po.Parse(argc, argv);
            FAIL() << "FAIL !!!";
        }
        catch(std::exception const & err) {
            EXPECT_EQ(err.what(),std::string("the required argument for option '--output' is missing"));
        }
        catch(...) {
            FAIL() << "FAIL !!!";
        }
    } 

    // output filename - return true
    {
        ProgramOptions po;
        int argc = 3;
        char *argv[] = { "./CryptoGuard","--output", "encrypted.txt"};

        ASSERT_TRUE(po.Parse(argc, argv));
        ASSERT_EQ(po.GetOutputFile(), "encrypted.txt");
    }
}
TEST(ProgramOptions, Password) { 
    // empty password - return false
    {
        ProgramOptions po;
        int argc = 2;
        char *argv[] = { "./CryptoGuard","--password"};
        try {
            po.Parse(argc, argv);
            FAIL() << "FAIL !!!";
        }
        catch(std::exception const & err) {
            EXPECT_EQ(err.what(),std::string("the required argument for option '--password' is missing"));
        }
        catch(...) {
            FAIL() << "FAIL !!!";
        }
    } 

    // password - return true
    {
        ProgramOptions po;
        int argc = 3;
        char *argv[] = { "./CryptoGuard","--password", "1234"};

        ASSERT_TRUE(po.Parse(argc, argv));
        ASSERT_EQ(po.GetPassword(), "1234");
    }
}

TEST(ProgramOptions, Aliases){
    // check aliases
    {    
        ProgramOptions po;
        int argc = 9;
        char *argv[] = { 
            "./CryptoGuard", 
            "-i","input.txt",
            "-o","encrypted.txt",
            "-p","1234",
            "-c","encrypt"
        };

        ASSERT_TRUE(po.Parse(argc, argv));

        ASSERT_EQ(po.GetInputFile(), "input.txt");
        ASSERT_EQ(po.GetOutputFile(), "encrypted.txt");
        ASSERT_EQ(po.GetPassword(), "1234");
        ASSERT_EQ(po.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
    }

    // check aliases (-o) + full arg type (--command)
    {    
        ProgramOptions po;
        int argc = 9;
        char *argv[] = { 
            "./CryptoGuard", 
            "-i","input.txt",
            "-o","encrypted.txt",
            "-p","1234",
            "--command","encrypt"
        };

        ASSERT_TRUE(po.Parse(argc, argv));

        ASSERT_EQ(po.GetInputFile(), "input.txt");
        ASSERT_EQ(po.GetOutputFile(), "encrypted.txt");
        ASSERT_EQ(po.GetPassword(), "1234");
        ASSERT_EQ(po.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
    }    
}

TEST(ProgramOptions, NoOptions){
    // no options - return false
    {
        ProgramOptions po;
        int argc = 1;
        char *argv[] = { "./CryptoGuard"};

        ASSERT_FALSE(po.Parse(argc, argv));
    } 
}

TEST(ProgramOptions, DoubleArgInit){
    // ./CryptoGuard -i input1.txt     -o encrypted.txt -p 1234 -c encrypt -i input2.txt - take first input input1.txt 
    {    
        ProgramOptions po;
        int argc = 11;
        char *argv[] = { 
            "./CryptoGuard", 
            "-i","input1.txt",
            "-o","encrypted.txt",
            "-p","1234",
            "--command","encrypt",
            "-i","input2.txt"
        };

        ASSERT_TRUE(po.Parse(argc, argv));

        ASSERT_EQ(po.GetInputFile(), "input1.txt");
        ASSERT_EQ(po.GetOutputFile(), "encrypted.txt");
        ASSERT_EQ(po.GetPassword(), "1234");
        ASSERT_EQ(po.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
    }    
}

TEST(ProgramOptions, NotAllCommands){
    // ./CryptoGuard -i input.txt --command checksum - return true
    {    
        ProgramOptions po;
        int argc = 5;
        char *argv[] = { 
            "./CryptoGuard", 
            "-i","input.txt",
            "--command","checksum"
        };

        ASSERT_TRUE(po.Parse(argc, argv));

        ASSERT_EQ(po.GetInputFile(), "input.txt");
        ASSERT_EQ(po.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
    }    
}

TEST(ProgramOptions, Parse){
    // 
    {    
        // ...
    }    
}