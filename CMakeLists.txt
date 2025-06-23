cmake_minimum_required(VERSION 3.10)

project(TcpPcapAnalyzer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(Boost 1.74 REQUIRED COMPONENTS program_options)
include_directories(${Boost_INCLUDE_DIRS})

find_package(jsoncpp REQUIRED)

add_executable(TCP_Analysis TCP_Analysis.cpp)

target_link_libraries(TCP_Analysis ${Boost_LIBRARIES} pcap jsoncpp_lib)