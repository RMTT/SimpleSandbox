//
// Created by mt on 6/24/18.
//

#ifndef IMCODER_JUDGER_EXECUTE_H
#define IMCODER_JUDGER_EXECUTE_H

#include <seccomp.h>
#include "error.h"

/**
 * the struct used to describe execute config
 * if the argument is zero,means unlimit it
 * @param uid the user to execute user code
 * @param gid the group of the user that execute user code
 * @param max_cpu_tim the max time of the program can execute
 * @param max_memory the max memory that the program can use
 * @param max_process_number
 * @param max_output_size the max output size of the program
 * @param exec_path the program path
 * @param input_path the input file path
 * @param log_path the log file path
 */
struct execute_config {
    uid_t uid;
    gid_t gid;
    int max_cpu_time;
    long max_memory;
    long max_stack;
    int max_process_number;
    long max_output_size;
    char *exec_path;
    char *input_path;
    char *output_path;
    char *log_path;
};

#define UNLIMIT 0

/**
 * the struct to describe the execute result
 * @param cpu_time the time that the program used
 * @param memory the memory that the program used
 * @param signal
 * @param exit_code*/
struct execute_result {
    int cpu_time;
    int memory;
    int signal;
    int exit_code;
};

/**
 * initialize the execute seccomp filter
 * @param ctx the scmp_filter_ctx should be initialized
 * @return if add filter success,will return 0,otherwise return -1*/
extern int init_execute_seccomp_filter(scmp_filter_ctx *ctx);

/**
 * this function will execute the program that configured in the config,and store the resources usage to the result
 * @param config execute config,see above struct execute_config
 * @param argv the arguments when execute the program
 * @param envp the environment variable
 * @param result store the runtime resources usage */
extern void execute(struct execute_config *config, char *argv[], char *envp[], struct execute_result *result);


/**
 * this function used to initialize the result
 * @param result the struct result will be initialized*/
extern void init_result(struct execute_result *result);

#define EXIT_WITH_FATAL_ERROR_CHILD(code, message)\
exit_with_error(code, LOG_LEVEL_FATAL, message, config->log_path, "execute.c");

#define EXIT_WITH_FATAL_ERROR(code, message)\
result->exit_code = 1;\
log_write(ERROR_SECCOMP_RULE, "execute.c", config->log_path, message, "a");\
return;

#endif //IMCODER_JUDGER_EXECUTE_H
