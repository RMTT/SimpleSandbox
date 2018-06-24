//
// Created by mt on 6/24/18.
//

#ifndef IMCODER_JUDGER_EXECUTE_H
#define IMCODER_JUDGER_EXECUTE_H

#include <seccomp.h>

/**
 * the struct used to describe execute config
 * @param max_cpu_tim the max time of the program can execute
 * @param max_memory the max memory that the program can use
 * @param max_process_number
 * @param max_output_size the max output size of the program
 * @param exec_path the program path
 * @param input_path the input file path
 * @param log_path the log file path
 * @param argv the arguments when execute the program*/
struct execute_config {
    int max_cpu_time;
    long max_memory;
    long max_stack;
    int max_process_number;
    long max_output_size;
    char *exec_path;
    char *input_path;
    char *output_path;
    char *log_path;
    char *agv[];
};


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
 * @param log_file the log file*/
extern void init_execute_seccomp_filter(scmp_filter_ctx *ctx, const char *log_file);

/**
 * this function will execute the program that configured in the config,and store the resources usage to the result
 * @param config execute config,see above struct execute_config
 * @param result store the runtime resources usage*/
extern void execute(struct execute_config *config, struct execute_result *result);

#endif //IMCODER_JUDGER_EXECUTE_H
