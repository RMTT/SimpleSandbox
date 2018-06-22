cmake_minimum_required(VERSION 2.8)

project(imcoder-judger)

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build/bin)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build/lib)

aux_source_directory(src DIR_SRCS)

add_executable(judger test.cpp)