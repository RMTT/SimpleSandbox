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

void init_compile_seccomp_filter(scmp_filter_ctx *ctx) {
    *ctx = seccomp_init(SCMP_ACT_ALLOW);
}


void compile(const struct compile_config *config, struct compile_result *result) {
    scmp_filter_ctx ctx = malloc(sizeof(int));
    init_compile_seccomp_filter(&ctx);

    // TODO solve invalid next size
    if (ctx == NULL) {
        log_error("compile.c", config->log_file, "seccomp set failed", "a");
        result->status = false;
        return;
    }

    if (seccomp_load(ctx) != 0) {
        log_error("compile.c", config->log_file, "load seccomp failed", "a");
        result->status = false;
        return;
    }

    seccomp_release(ctx);

    pid_t pid = fork();

    if (pid == -1) {
        log_error("compile.c", config->log_file, "child process create failed", "a");
        result->status = false;
        return;
    } else if (pid == 0) {
        execvp(config->compiler_path, config->argv);
        exit(SUCCESS_COMPLETE);
    } else {
        int status;
        if (wait4(pid, &status, WSTOPPED, NULL) == -1) {
            int rs = kill(pid, SIGKILL);
            if (rs != 0) {
                log_error("compile.c", config->log_file, "compile thread have some error,but can not kill it", "a");
                result->status = false;
                return;
            }
        }

        int child_exit_status = WIFEXITED(status);

        if (child_exit_status) {
            int child_return_status = WEXITSTATUS(status);
            if (child_return_status == 0) {
                result->status = true;
            }
        } else {
            result->status = false;
        }
    }
}

