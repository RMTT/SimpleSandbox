cmake_minimum_required(VERSION 2.8)

project(imcoder-judger)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build/lib)

include_directories(src/core/logger)
add_subdirectory(src/core)

add_executable(judger test.c)
target_link_libraries(judger core)