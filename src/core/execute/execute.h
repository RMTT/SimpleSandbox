//
// Created by mt on 6/24/18.
//

#ifndef IMCODER_JUDGER_EXECUTE_H
#define IMCODER_JUDGER_EXECUTE_H

#include <seccomp.h>
#include "error.h"


#define MAX_ARG_NUM 256
#define MAX_ENV_NUM 256

#define MAX_MESSAGE_LEN 256

#define SUCCESS_EXECUTE 201
#define FAIL_EXECUTE 202
#define EXCEED_MEMORY_LIMIT 203
#define EXCEED_CPU_TIME_LIMIT 204
#define EXCEED_OUTPUT_SIZE_LIMIT 205
#define SYSTEM_ERROR 206
#define RUNTIME_ERROR 207

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
    int max_cpu_time;
    long max_memory;
    long max_stack;
    int max_process_number;
    int arg_count;
    int env_count;
    long max_output_size;
    char *exec_path;
    char *input_path;
    char *output_path;
    char *log_path;
    char *argv[MAX_ARG_NUM];
    char *envp[MAX_ENV_NUM];
};

extern void
execute_init(struct execute_config **ecfg, int max_cpu_time, long max_memory, long max_stack, int max_processor_number,
             int max_output_size);

extern void execute_set_exec(struct execute_config *ecfg, const char *arg);

extern void execute_set_input(struct execute_config *ecfg, const char *arg);

extern void execute_set_output(struct execute_config *ecfg, const char *arg);

extern void execute_set_log(struct execute_config *ecfg, const char *arg);

extern void execute_add_arg(struct execute_config *ecfg, const char *arg);

extern void execute_add_env(struct execute_config *ecfg, const char *arg);


#define UNLIMIT RLIM_INFINITY

/**
 * the struct to describe the execute result
 * @param cpu_time the time that the program used
 * @param memory the memory that the program used
 * @param exit_code*/
struct execute_result {
    int status;
    int signal;
    long int used_time;
    long int used_memory;
    char *message;
};

extern void execute_result_init(struct execute_result **eres);

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
extern void execute(const struct execute_config *config, struct execute_result *result);


/**
 * this function used to initialize the result
 * @param result the struct result will be initialized*/
extern void init_result(struct execute_result *result);

#define EXIT_WITH_FATAL_ERROR(level, message)\
log_write(level, "execute.c", config->log_path, message, "a");\
raise(SIGUSR1);\

#endif //IMCODER_JUDGER_EXECUTE_H
