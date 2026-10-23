cmake_minimum_required(VERSION 3.10)

project(SynFin LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(Boost 1.74 REQUIRED COMPONENTS program_options)
include_directories(${Boost_INCLUDE_DIRS})

find_package(jsoncpp REQUIRED)

add_executable(synfin synfin.cpp)

target_link_libraries(synfin ${Boost_LIBRARIES} pcap jsoncpp_lib)