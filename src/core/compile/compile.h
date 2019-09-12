//
// Created by mt on 6/22/18.
//

#ifndef IMCODER_JUDGER_COMPILE_H
#define IMCODER_JUDGER_COMPILE_H

#include <seccomp.h>
#include <stdbool.h>

#define MAX_COMPILE_ARGS 256
#define MAX_MESSAGE_LEN 256

/**
 * this function will set the common filter to compile environment
 * @param ctx the filter context of compile environment */
extern void init_compile_seccomp_filter(scmp_filter_ctx *ctx);


/**
 * this struct used to save the compile result
 * @param status_code if true,represent the compile successful complete,otherwise,is false
 * @param message if compile failed,the message will save the error message*/
struct compile_result {
    int status;
    char *message;
};

/**
 * this struct used to config the compile environment
 * @param uid the uid of user that compile source file
 * @param compiler_path the path of compiler
 * @param log_file the path of log file
 * @param tmp_file the path of tmp file,tmp file used to save the output of compiler
 * @param argv the arguments of compile*/
struct compile_config {
    short arg_count;
    char *compiler_path;
    char *log_file;
    char *tmp_file;
    char *argv[MAX_COMPILE_ARGS];
};

/**
 * construct the struct compile_config
 * @param ccfg the pointer to pointer of original compile_config
 * @param compiler_path point to compiler
 * @param log_path point to log file
 * @param binary_path point to binary file
 */
extern void
compile_init(struct compile_config **ccfg, const char *compiler_path, const char *log_path, const char *binary_path);

/**
 * init the struct compile_result
 * @param cres  the pointer to pointer of original compile_result
 */
extern void compile_result_init(struct compile_result **cres);
/**
 * Add argument to compiler
 * @param ccfg the pointer to compile_config
 * @param arg the argument will be added
 */
extern void compile_add_argv(struct compile_config *ccfg, const char *arg);

/**
 * compile the target file
 * @param compiler_path the path of the compiler,should be a binary executable file
 * @param log_file the path of log file
 * @param argv compile argument
 * @param result store the compile result*/
extern void compile(const struct compile_config *config, struct compile_result *result);

#define SUCCESS_COMPILE 100
#define FAIL_COMPILE 101

#endif //IMCODER_JUDGER_COMPILE_H
