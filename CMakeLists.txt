cmake_minimum_required(VERSION 3.15)

# The version shown by `synfin --version` and in the Windows file properties.
project(SynFin VERSION 0.4.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Link the C/C++ runtime into the binary so it runs without matching libraries installed.
option(SYNFIN_STATIC "Link the runtime statically" OFF)

if(MSVC AND SYNFIN_STATIC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

find_package(Threads REQUIRED)

add_executable(synfin synfin.cpp)

target_compile_definitions(synfin PRIVATE SYNFIN_VERSION="${PROJECT_VERSION}")
target_link_libraries(synfin Threads::Threads)

if(WIN32)
    enable_language(RC)
    set(SYNFIN_ICON "${CMAKE_CURRENT_SOURCE_DIR}/windows/synfin.ico")
    configure_file(windows/synfin.rc.in "${CMAKE_CURRENT_BINARY_DIR}/synfin.rc" @ONLY)
    target_sources(synfin PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/synfin.rc")
    target_link_libraries(synfin shell32)
endif()

if(MSVC)
    target_compile_options(synfin PRIVATE /utf-8 /W4)
endif()

if(SYNFIN_STATIC AND NOT MSVC)
    if(MINGW)
        target_link_libraries(synfin -static)
    else()
        target_link_libraries(synfin -static-libstdc++ -static-libgcc)
    endif()
endif()
