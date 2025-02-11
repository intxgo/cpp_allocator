cmake_minimum_required(VERSION 3.10)
project(App VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_executable(App main.cpp)

target_compile_features(App PUBLIC cxx_std_17)