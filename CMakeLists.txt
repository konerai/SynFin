cmake_minimum_required(VERSION 3.10)

project(SynFin LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Link the C/C++ runtime into the binary so it runs without matching libraries installed.
option(SYNFIN_STATIC "Link the runtime statically" OFF)

find_package(Threads REQUIRED)

add_executable(synfin synfin.cpp)

target_link_libraries(synfin Threads::Threads)

if(SYNFIN_STATIC)
    if(MINGW)
        target_link_libraries(synfin -static)
    else()
        target_link_libraries(synfin -static-libstdc++ -static-libgcc)
    endif()
endif()
