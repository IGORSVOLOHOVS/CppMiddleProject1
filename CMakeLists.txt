cmake_minimum_required(VERSION 3.30)
project(CryptoGuard VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
# clang-tidy reads this: without it the fetched headers are not found.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wfatal-errors)
endif()
if(MSVC)
    # Some sources hold UTF-8 comments. Without /utf-8 cl.exe reads them in the machine's ANSI code page.
    add_compile_options(/utf-8)
endif()

# Conan supplies Boost and GoogleTest to the MSVC and dev-container builds. Conan Center has no mingw
# binaries, so recipe.ps1 turns this on and takes both by URL and hash.
option(CRYPTO_GUARD_FETCH_DEPENDENCIES "Fetch Boost and GoogleTest instead of finding them" OFF)

function(warn_as_errors target)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
endfunction()

find_package(OpenSSL REQUIRED)
# The mingw toolchain compiled its static OpenSSL with zlib, so a static link needs that as well.
if(MINGW AND OPENSSL_USE_STATIC_LIBS)
    set(CRYPTO_GUARD_ZLIB z)
endif()

if(CRYPTO_GUARD_FETCH_DEPENDENCIES)
    # An archive and its hash, not a git clone: nothing here can ask for a credential on the runner.
    include(FetchContent)
    set(BOOST_INCLUDE_LIBRARIES program_options)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(
        Boost
        URL https://github.com/boostorg/boost/releases/download/boost-1.86.0/boost-1.86.0-cmake.tar.xz
        URL_HASH SHA256=2c5ec5edcdff47ff55e27ed9560b0a0b94b07bd07ed9928b476150e16b0efc57
        SYSTEM
        EXCLUDE_FROM_ALL
    )
    FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.13.0.tar.gz
        URL_HASH SHA256=ad7fdba11ea011c1d925b3289cf4af2c66a352e18d4c7264392fead75e919363
        SYSTEM
        EXCLUDE_FROM_ALL
    )
    FetchContent_MakeAvailable(Boost googletest)
    set(CRYPTO_GUARD_BOOST Boost::program_options)
    set(CRYPTO_GUARD_GTEST GTest::gtest GTest::gtest_main)
else()
    find_package(Boost REQUIRED COMPONENTS program_options)
    find_package(GTest REQUIRED)
    set(CRYPTO_GUARD_BOOST ${Boost_LIBRARIES})
    set(CRYPTO_GUARD_GTEST GTest::GTest GTest::Main)
endif()

# Every source but main.cpp goes into a static library the program and the tests share.
file(GLOB SRC_FILES "${CMAKE_SOURCE_DIR}/src/*.cpp")
file(GLOB HEADER_FILES "${CMAKE_SOURCE_DIR}/include/*.h")
list(REMOVE_ITEM SRC_FILES "${CMAKE_SOURCE_DIR}/src/main.cpp")

add_library(${PROJECT_NAME}_imp STATIC ${SRC_FILES} ${HEADER_FILES})
target_include_directories(${PROJECT_NAME}_imp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(${PROJECT_NAME}_imp SYSTEM PUBLIC ${OPENSSL_INCLUDE_DIR} ${Boost_INCLUDE_DIRS})
# Boost is PUBLIC: cmd_options.h includes <boost/program_options.hpp>, so consumers need its
# requirements too. With PRIVATE they compile without BOOST_ALL_NO_LIB, and MSVC's auto-linking
# then asks for a library name Conan does not lay out.
target_link_libraries(${PROJECT_NAME}_imp
    PRIVATE OpenSSL::SSL OpenSSL::Crypto ${OPENSSL_LIBRARIES} ${CRYPTO_GUARD_ZLIB}
    PUBLIC ${CRYPTO_GUARD_BOOST})
warn_as_errors(${PROJECT_NAME}_imp)

add_executable(${PROJECT_NAME} "${CMAKE_SOURCE_DIR}/src/main.cpp")
target_link_libraries(${PROJECT_NAME} PRIVATE ${PROJECT_NAME}_imp)
warn_as_errors(${PROJECT_NAME})

file(GLOB TEST_SRC_FILES "${CMAKE_SOURCE_DIR}/tests/*.cpp")

add_executable(${PROJECT_NAME}_tests "${TEST_SRC_FILES}")
target_link_libraries(${PROJECT_NAME}_tests PRIVATE ${PROJECT_NAME}_imp ${CRYPTO_GUARD_GTEST})
target_include_directories(${PROJECT_NAME}_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
warn_as_errors(${PROJECT_NAME}_tests)

enable_testing()
add_test(NAME CryptoGuard_Tests COMMAND ${PROJECT_NAME}_tests)
# The manual list is judged where every other file is judged (section 9): on the lab's route, which has pytest.
if(CRYPTO_GUARD_FETCH_DEPENDENCIES)
    add_test(
        NAME manual_list
        COMMAND python -m pytest tests/test_manual_list.py -q -p no:cacheprovider
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )
endif()
