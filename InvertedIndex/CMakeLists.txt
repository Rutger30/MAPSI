cmake_minimum_required(VERSION 3.10)
project(InvertedIndex)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(SOURCES
    src/main.cc
    src/server.cc
    src/client.cc
    src/common.cc
)

include_directories(${CMAKE_SOURCE_DIR})

add_executable(InvertedIndex ${SOURCES})

find_package(SEAL REQUIRED)

target_link_libraries(InvertedIndex SEAL::seal -lsodium)

