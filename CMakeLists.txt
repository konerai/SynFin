cmake_minimum_required(VERSION 3.15)

# The version shown by `synfin --version` and in the Windows file properties.
project(SynFin VERSION 0.5.0 LANGUAGES CXX)

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
        target_link_options(synfin PRIVATE $<$<CONFIG:Release>:-s>)  # strip symbols
    else()
        target_link_libraries(synfin -static-libstdc++ -static-libgcc)
    endif()
endif()

# The Windows GUI (synfin-gui.exe): Dear ImGui on Direct3D 11 with the analyzer built in.
if(WIN32)
    option(SYNFIN_GUI "Build the Windows GUI" ON)
endif()

if(WIN32 AND SYNFIN_GUI)
    set(IMGUI_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/imgui")
    add_executable(synfin-gui WIN32
        windows/synfin_gui.cpp
        "${IMGUI_DIR}/imgui.cpp"
        "${IMGUI_DIR}/imgui_draw.cpp"
        "${IMGUI_DIR}/imgui_tables.cpp"
        "${IMGUI_DIR}/imgui_widgets.cpp"
        "${IMGUI_DIR}/backends/imgui_impl_win32.cpp"
        "${IMGUI_DIR}/backends/imgui_impl_dx11.cpp")
    target_include_directories(synfin-gui PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/windows" "${IMGUI_DIR}" "${IMGUI_DIR}/backends")
    target_compile_definitions(synfin-gui PRIVATE
        SYNFIN_VERSION="${PROJECT_VERSION}" IMGUI_DISABLE_OBSOLETE_FUNCTIONS UNICODE _UNICODE)

    set(SYNFIN_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
    if(MSVC)
        set(SYNFIN_MANIFEST_LINE "")
        target_sources(synfin-gui PRIVATE windows/synfin_gui.manifest)
    else()
        set(SYNFIN_MANIFEST_LINE "1 24 \"${CMAKE_CURRENT_SOURCE_DIR}/windows/synfin_gui.manifest\"")
    endif()
    configure_file(windows/synfin_gui.rc.in "${CMAKE_CURRENT_BINARY_DIR}/synfin_gui.rc" @ONLY)
    target_sources(synfin-gui PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/synfin_gui.rc")

    target_link_libraries(synfin-gui Threads::Threads d3d11 d3dcompiler dwmapi ole32 shell32 uuid imm32 gdi32 user32)
    if(MSVC)
        target_compile_options(synfin-gui PRIVATE /utf-8)
    endif()
    if(MINGW)
        target_link_options(synfin-gui PRIVATE -municode)  # entry point is wWinMain
    endif()
    if(SYNFIN_STATIC AND MINGW)
        target_link_libraries(synfin-gui -static)
        target_link_options(synfin-gui PRIVATE $<$<CONFIG:Release>:-s>)
    endif()
endif()
