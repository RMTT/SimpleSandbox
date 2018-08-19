#include <seccomp.h>
#include <stdlib.h>
#include "execute.h"
#include "error.h"
#include "logger.h"
#include <stdio.h>
#include <fcntl.h>
#include <memory.h>
#include <unistd.h>
#include <sys/resource.h>
#include <wait.h>
#include "user_authority.h"

int init_execute_seccomp_filter(scmp_filter_ctx *ctx) {
    *ctx = seccomp_init(SCMP_ACT_ALLOW);

    int systemcall_blacklist[] = {
            SCMP_SYS(clone), SCMP_SYS(fork), SCMP_SYS(vfork),
            SCMP_SYS(kill)
    };

    int whitelist_length = sizeof(systemcall_blacklist) / sizeof(systemcall_blacklist[0]);

    /* add the rule that do not need control */
    for (int i = 0; i < whitelist_length; i++)
        if (seccomp_rule_add(*ctx, SCMP_ACT_KILL, systemcall_blacklist[i], 0) != 0)
            return -1;
    return 0;
}


void init_result(struct execute_result *result) {
    memset(result, 0, sizeof(struct execute_result));
}

void execute(const struct execute_config *config, struct execute_result *result) {
    if (__require_root_authority() != 0) {
        result->status = ERROR_NOT_ROOT;
        log_fatal("compile.c", config->log_path, "please use the root user to execute the program", "a");
        return;
    }

    init_result(result);


    scmp_filter_ctx ctx;
    int rs = init_execute_seccomp_filter(&ctx);
    if (rs == -1) {
        result->status = ERROR_SECCOMP_INIT;
        log_fatal("execute.c", config->log_path, "add seccomp filter failed", "a");
        result->message = "add seccomp filter failed";
    }

    /* add the filter that must control the argument*/

    // limit the execve
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve),
                         1, SCMP_A0(SCMP_CMP_NE, (scmp_datum_t) config->exec_path)) != 0) {
        result->status = ERROR_SECCOMP_LOAD;
        log_fatal("execute.c", config->log_path, "add seccomp filter failed", "a");
        result->message = "add seccomp filter failed";
    }

    // do not allow "w" and "rw" using open
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 1, SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_WRONLY, O_WRONLY)) !=
        0) {
        result->status = ERROR_SECCOMP_LOAD;
        log_fatal("execute.c", config->log_path, "add seccomp filter failed", "a");
        result->message = "add seccomp filter failed";
    }
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 1, SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_RDWR, O_RDWR)) != 0) {
        result->status = ERROR_SECCOMP_LOAD;
        log_fatal("execute.c", config->log_path, "add seccomp filter failed", "a");
        result->message = "add seccomp filter failed";
    }
    // do not allow "w" and "rw" using openat
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(openat), 1,
                         SCMP_CMP(2, SCMP_CMP_MASKED_EQ, O_WRONLY, O_WRONLY)) != 0) {
        result->status = ERROR_SECCOMP_LOAD;
        log_fatal("execute.c", config->log_path, "add seccomp filter failed", "a");
        result->message = "add seccomp filter failed";
    }
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(openat), 1, SCMP_CMP(2, SCMP_CMP_MASKED_EQ, O_RDWR, O_RDWR)) !=
        0) {
        result->status = ERROR_SECCOMP_LOAD;
        log_fatal("execute.c", config->log_path, "add seccomp filter failed", "a");
        result->message = "add seccomp filter failed";
    }

    // start process thread
    pid_t child = fork();

    if (child == -1) {
        result->status = ERROR_FORK;
        log_fatal("execute.c", config->log_path, "fork error", "a");
        result->message = "fork error";
    } else if (child == 0) {
        /** limit the resources */

        // limit the stack size
        if (config->max_stack != UNLIMIT) {
            struct rlimit rl;
            rl.rlim_cur = rl.rlim_max = (rlim_t) config->max_stack;

            if (setrlimit(RLIMIT_STACK, &rl) != 0) {
                EXIT_WITH_FATAL_ERROR(ERROR_SET_RLIMIT, LOG_LEVEL_FATAL, "limit the stack size failed");
            }
        }

        // limit the cpu time
        if (config->max_cpu_time != UNLIMIT) {
            struct rlimit rl;
            rl.rlim_cur = rl.rlim_max = (rlim_t) config->max_cpu_time;
            if (setrlimit(RLIMIT_CPU, &rl) != 0) {
                EXIT_WITH_FATAL_ERROR(ERROR_SET_RLIMIT, LOG_LEVEL_FATAL, "limit the cpu time failed");
            }
        }

        // limit the memory
        if (config->max_memory != UNLIMIT) {
            struct rlimit rl;
            rl.rlim_cur = rl.rlim_max = (rlim_t) config->max_memory;
            if (setrlimit(RLIMIT_AS, &rl) != 0) {
                EXIT_WITH_FATAL_ERROR(ERROR_SET_RLIMIT, LOG_LEVEL_FATAL, "limit the memory failed");
            }
        }

        // limit the process number
        if (config->max_process_number != UNLIMIT) {
            struct rlimit rl;
            rl.rlim_cur = rl.rlim_max = (rlim_t) config->max_process_number;
            if (setrlimit(RLIMIT_NPROC, &rl) != 0) {
                EXIT_WITH_FATAL_ERROR(ERROR_SET_RLIMIT, LOG_LEVEL_FATAL, "limit the process number error");
            }
        }

        // limit the out put size
        if (config->max_output_size != UNLIMIT) {
            struct rlimit rl;
            rl.rlim_cur = rl.rlim_max = (rlim_t) config->max_output_size;
            if (setrlimit(RLIMIT_FSIZE, &rl) != 0) {
                EXIT_WITH_FATAL_ERROR(ERROR_SET_RLIMIT, LOG_LEVEL_FATAL, "limit the output size");
            }
        }

        // check the input path
        if (config->input_path != NULL) {
            FILE *input_file = fopen(config->input_path, "r");
            if (input_file == NULL) {
                EXIT_WITH_FATAL_ERROR(ERROR_FILE_OPEN, LOG_LEVEL_FATAL, "can not open the input file");
            }

            if (dup2(fileno(input_file), fileno(stdin)) == -1) {
                EXIT_WITH_FATAL_ERROR(ERROR_FILE_DUP2, LOG_LEVEL_FATAL, "can not redirect the input file");
            }
        }

        // check the output path
        if (config->output_path != NULL) {
            FILE *output_file = fopen(config->output_path, "w");
            if (output_file == NULL) {
                EXIT_WITH_FATAL_ERROR(ERROR_FILE_OPEN, LOG_LEVEL_FATAL, "can not open the output file");
            }

            if (dup2(fileno(output_file), fileno(stdout)) == -1) {
                EXIT_WITH_FATAL_ERROR(ERROR_FILE_DUP2, LOG_LEVEL_FATAL, "can not redirect the stdout");
            }
        }

        // change user
        if (setuid(config->uid) != 0) {
            EXIT_WITH_FATAL_ERROR(ERROR_SET_UID, LOG_LEVEL_FATAL, "set uid failed");
        }


        // change group
        if (setgid(config->gid) != 0) {
            EXIT_WITH_FATAL_ERROR(ERROR_SET_GID, LOG_LEVEL_FATAL, "set gid failed");
        }

        // load and release the seccomp filter
        if (seccomp_load(ctx) != 0) {
            EXIT_WITH_FATAL_ERROR(ERROR_SECCOMP_LOAD, LOG_LEVEL_FATAL, "load seccomp filter failed");
        }
        seccomp_release(ctx);

        execve(config->exec_path, config->argv, config->envp);

        exit(SUCCESS_COMPLETE);
    } else {

        int status;
        struct rusage resources;

        if (wait4(child, &status, WSTOPPED, &resources) == -1) {
            kill(child, SIGKILL);
            result->status = ERROR_KILL_PROCESS;
            log_error("execute.c", config->log_path, "can not get the result of child process and can not kill it",
                      "a");
            result->message = "can not get the result of child process and can not kill it";
        }

        int child_exit_status = WIFEXITED(status);

        result->signal = WTERMSIG(status);
        result->memory = resources.ru_maxrss;
        result->used_time = resources.ru_utime.tv_sec * 1000 + resources.ru_utime.tv_usec / 1000;

        if (child_exit_status) {
            int child_return_status = WEXITSTATUS(status);
            printf("exit code : %d\n", child_return_status);


            if (child_return_status == SUCCESS_COMPLETE) {
                result->status = SUCCESS_EXECUTE;
                result->message = "successful execute";
            } else {

            }
        } else {
            result->status = SYSTEM_ERROR;
            result->message = "system error";
        }
    }
}