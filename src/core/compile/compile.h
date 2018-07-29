//
// Created by mt on 6/22/18.
//

#ifndef IMCODER_JUDGER_COMPILE_H
#define IMCODER_JUDGER_COMPILE_H

#include <seccomp.h>
#include <stdbool.h>

/**
 * this function will set the common filter to compile environment
 * @param ctx the filter context of compile environment */
extern void init_compile_seccomp_filter(scmp_filter_ctx *ctx);


/**
 * this struct used to save the compile result
 * @param status_code if true,represent the compile successful complete,otherwise,is false
 * @param message if compile failed,the message will save the error message*/
struct compile_result {
    bool status;
    char *message;
};

/**
 * this struct used to config the compile environment
 * @param compiler_path the path of compiler
 * @param log_file the path of log file
 * @param argv the arguments of compile*/
struct compile_config {
    char *compiler_path;
    char *log_file;
    char *argv[];
};

/**
 * compile the target file
 * @param compiler_path the path of the compiler,should be a binary executable file
 * @param log_file the path of log file
 * @param argv compile argument
 * @param result store the compile result*/
extern void
compile(const struct compile_config *config, struct compile_result *result);

#endif //IMCODER_JUDGER_COMPILE_H
