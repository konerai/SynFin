# Cross-compiles SynFin for 64-bit Windows with llvm-mingw (https://github.com/mstorsjo/llvm-mingw)
# from Linux; its bin/ directory must be on PATH:
#   cmake -B build-win -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-llvm-mingw-x86_64.cmake -DSYNFIN_STATIC=ON
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(TOOLCHAIN_PREFIX x86_64-w64-mingw32)
set(CMAKE_C_COMPILER ${TOOLCHAIN_PREFIX}-clang)
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}-clang++)
set(CMAKE_RC_COMPILER ${TOOLCHAIN_PREFIX}-windres)
