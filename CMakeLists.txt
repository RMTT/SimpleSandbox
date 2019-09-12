cmake_minimum_required(VERSION 3.0)

project(imcoder-judger)

set(CMAKE_C_STANDARD 11)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build/lib)


include_directories(src/core/logger)
include_directories(src/core/compile)
include_directories(src/core/execute)
include_directories(src/common)
add_subdirectory(src)

add_executable(judger test.c)
target_link_libraries(judger imcoder_core)
target_link_libraries(judger seccomp)