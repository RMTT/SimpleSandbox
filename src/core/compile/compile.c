//
// Created by mt on 6/22/18.
//

#include <seccomp.h>
#include "compile.h"
#include <stdlib.h>
#include <unistd.h>
#include "error.h"
#include "logger.h"
#include <stdio.h>
#include <wait.h>
#include <signal.h>
#include "logger.h"
#include <memory.h>
#include <fcntl.h>
#include "user_authority.h"

void init_compile_seccomp_filter(scmp_filter_ctx *ctx) {
    *ctx = seccomp_init(SCMP_ACT_ALLOW);
}


void compile(const struct compile_config *config, struct compile_result *result) {

/*    if (__require_root_authority() != 0) {
        result->status = ERROR_NOT_ROOT;
        result->message = "please use the root user to execute the program";
        log_fatal("compile.c", config->log_file, "please use the root user to execute the program", "a");
        return;
    }*/

    scmp_filter_ctx ctx;
    init_compile_seccomp_filter(&ctx);

    if (ctx == NULL) {
        log_fatal("compile.c", config->log_file, "init seccomp failed", "a");
        result->status = ERROR_SECCOMP_INIT;
        result->message = "init seccomp failed";
        return;
    }

    if (seccomp_load(ctx) != 0) {
        log_fatal("compile.c", config->log_file, "load seccomp failed", "a");
        result->status = ERROR_SECCOMP_LOAD;
        result->message = "load seccomp failed";
        return;
    }

    seccomp_release(ctx);

    __pid_t pid = fork();

    if (pid == -1) {
        log_fatal("compile.c", config->log_file, "child process create failed", "a");
        result->status = ERROR_CREATE_PROCESS;
        result->message = "child process create failed";
        return;
    } else if (pid == 0) {
        FILE *tmp_file = fopen(config->tmp_file, "w");

        if (dup2(fileno(tmp_file), fileno(stderr)) == -1)
            exit_with_error(ERROR_FILE_DUP2, LOG_LEVEL_FATAL, "can not redirect to the tmp file", config->log_file,
                            "compile.c");

        execvp(config->compiler_path, config->argv);
        exit(SUCCESS_COMPLETE);
    } else {
        int status;
        if (wait4(pid, &status, WSTOPPED, NULL) == -1) {
            int rs = kill(pid, SIGKILL);
            if (rs != 0) {
                log_error("compile.c", config->log_file, "compile thread have some error,but can not kill it", "a");
                result->status = ERROR_KILL_PROCESS;
                result->message = "compile thread have some error,but can not kill it";
            }
        }

        int child_exit_status = WIFEXITED(status);

        if (child_exit_status) {
            int child_return_status = WEXITSTATUS(status);
            if (child_return_status == SUCCESS_COMPLETE) {
                result->status = SUCCESS_COMPILE;
                result->message = "compile successful";
            } else {
                result->status = FAIL_COMPILE;
                result->message = "compile failed";
            }
        } else {
            result->status = FAIL_COMPILE;
            result->message = "compile failed";
        }
    }
}

void
compile_init(struct compile_config **ccfg, const char *compiler_path, const char *log_path, const char *tmp_path) {
    *ccfg = malloc(sizeof(struct compile_config));
    (*ccfg)->compiler_path = malloc(strlen(compiler_path));
    memcpy((*ccfg)->compiler_path, compiler_path, strlen(compiler_path));

    (*ccfg)->log_file = malloc(strlen(log_path));
    memcpy((*ccfg)->log_file, log_path, strlen(log_path));

    (*ccfg)->tmp_file = malloc(strlen(tmp_path));
    memcpy((*ccfg)->tmp_file, tmp_path, strlen(tmp_path));

    (*ccfg)->arg_count = 0;
}


void compile_add_argv(struct compile_config *ccfg, const char *arg) {
    ccfg->argv[ccfg->arg_count] = malloc(strlen(arg));
    memcpy(ccfg->argv[ccfg->arg_count], arg, strlen(arg));
    ++ccfg->arg_count;
}

void compile_result_init(struct compile_result **cres) {
    *cres = malloc(sizeof(struct compile_result));
    (*cres)->message = malloc(MAX_MESSAGE_LEN);
}


