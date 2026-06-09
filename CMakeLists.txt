cmake_minimum_required(VERSION 3.20)
project(syscall-lib LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(syscall INTERFACE)
target_include_directories(syscall INTERFACE include)

option(BUILD_TESTS "Build test project" ON)
if(BUILD_TESTS)
    add_subdirectory(test)
endif()
