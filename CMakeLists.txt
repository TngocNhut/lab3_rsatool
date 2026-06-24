cmake_minimum_required(VERSION 3.20)

project(lab3_rsatool
    VERSION 1.0.0
    DESCRIPTION "Lab 3 - RSA-OAEP and Hybrid Encryption with Crypto++"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(rsatool
    src/main.cpp
    src/file_utils.cpp
    src/encoding.cpp
    src/rsa_keys.cpp
    src/rsa_oaep.cpp
    src/hybrid.cpp
)

target_include_directories(rsatool
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(rsatool
    PRIVATE
        cryptopp
)

if (MSVC)
    target_compile_options(rsatool PRIVATE /W4)
else()
    target_compile_options(rsatool PRIVATE -Wall -Wextra -Wpedantic)
endif()

enable_testing()
