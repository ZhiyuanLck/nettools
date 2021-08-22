cmake_minimum_required(VERSION 3.10)

project(nettools)

add_compile_definitions(BOOST_ASIO_ENABLE_HANDLER_TRACKING)
add_compile_options(-g -Wall -O2 -std=c++17)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

find_package(fmt)
find_package(Boost 1.53.0 COMPONENTS system thread REQUIRED)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include ${Boost_INCLUDE_DIR})

add_subdirectory(src)
