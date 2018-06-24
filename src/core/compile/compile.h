//
// Created by mt on 6/22/18.
//

#ifndef IMCODER_JUDGER_COMPILE_H
#define IMCODER_JUDGER_COMPILE_H

#include <seccomp.h>

/**
 * this function will set the common filter to compile environment
 * @param ctx the filter context of compile environment */
extern void init_compile_seccomp_filter(scmp_filter_ctx *ctx);


/**
 * compile the target file
 * @param compiler_path the path of the compiler,should be a binary executable file
 * @param log_file the path of log file
 * @param argv compile argument
 * @param result store the compile result*/
extern void compile(const char *compiler_path, const char *log_file, char *argv[], int *result);

#endif //IMCODER_JUDGER_COMPILE_H
