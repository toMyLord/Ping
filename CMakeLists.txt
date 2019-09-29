cmake_minimum_required(VERSION 3.10)
project(MyPing)

set(CMAKE_CXX_STANDARD 14)

add_executable(MyPing main.cpp src/ping.cpp src/ping.h)