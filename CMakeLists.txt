# CMake build for Trilogy.
#
# The Makefile remains the primary build on UNIX. This file exists mainly so
# Trilogy can be built with MSVC on Windows, but it works on any platform:
#
#   cmake -S . -B build -DOPENSSL_ROOT_DIR=<path to OpenSSL>
#   cmake --build build --config Release
#
cmake_minimum_required(VERSION 3.16)

project(trilogy LANGUAGES C)

option(TRILOGY_BUILD_TESTS "Build the test suite (needs a MySQL server to run)" OFF)
option(TRILOGY_BUILD_EXAMPLES "Build the example programs (need getopt, so not MSVC)" OFF)

find_package(OpenSSL REQUIRED)

file(GLOB_RECURSE TRILOGY_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")

add_library(trilogy STATIC ${TRILOGY_SOURCES})
add_library(trilogy::trilogy ALIAS trilogy)

target_include_directories(trilogy PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/inc")
target_link_libraries(trilogy PUBLIC OpenSSL::SSL OpenSSL::Crypto)

if(WIN32)
    target_link_libraries(trilogy PUBLIC ws2_32 crypt32)
endif()

if(MSVC)
    # MSVC needs C11 mode for designated initializers and compound literals.
    set_target_properties(trilogy PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON)
    target_compile_definitions(trilogy PRIVATE _CRT_SECURE_NO_WARNINGS _CRT_NONSTDC_NO_DEPRECATE)
    target_compile_options(trilogy PRIVATE /W3)
else()
    set_target_properties(trilogy PROPERTIES C_STANDARD 99 C_EXTENSIONS ON)
    target_compile_options(trilogy PRIVATE -Wall -Wextra -pedantic -Wsign-conversion -Wno-missing-field-initializers)
endif()

if(TRILOGY_BUILD_EXAMPLES)
    add_executable(trilogy_query example/trilogy_query.c)
    target_link_libraries(trilogy_query PRIVATE trilogy)
endif()

if(TRILOGY_BUILD_TESTS)
    file(GLOB_RECURSE TRILOGY_TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/test/*.c")
    add_executable(trilogy_test ${TRILOGY_TEST_SOURCES})
    target_include_directories(trilogy_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/test")
    target_link_libraries(trilogy_test PRIVATE trilogy)
    if(MSVC)
        set_target_properties(trilogy_test PROPERTIES C_STANDARD 11)
        target_compile_definitions(trilogy_test PRIVATE _CRT_SECURE_NO_WARNINGS _CRT_NONSTDC_NO_DEPRECATE)
    else()
        set_target_properties(trilogy_test PROPERTIES C_STANDARD 99 C_EXTENSIONS ON)
    endif()
endif()
