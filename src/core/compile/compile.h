//
// Created by mt on 6/22/18.
//

#ifndef IMCODER_JUDGER_COMPILE_H
#define IMCODER_JUDGER_COMPILE_H

#include <seccomp.h>

/**
 * the common config of compile
 * @param uid the user who execute the compile command
 * @param gid the group if of the user,maybe NULL
 * @param log_file the log file*/
struct compile_config {
    int uid;
    int gid;
    char *log_file;;
};


/**
 * compile the target file
 * @param compiler_path the path of the compiler,should be a binary executable file
 * @param config see above compile_config
 * @param argv compile argument */
extern void compile(const char *compiler_path, struct compile_config *config, char *argv[], char *envp[]);


/**
 * this function will set the common filter to compile environment
 * @param ctx the filter context of compile environment */
extern void init_compile_seccomp_filter(scmp_filter_ctx *ctx);

#endif //IMCODER_JUDGER_COMPILE_H
