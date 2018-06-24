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
#include <memory.h>
#include "compile_config.h"

void init_compile_seccomp_filter(scmp_filter_ctx *ctx) {
    *ctx = seccomp_init(SCMP_ACT_ALLOW);
}


void compile(const char *compiler_path, const char *log_file, char *argv[], int *result) {
    scmp_filter_ctx ctx = NULL;
    init_compile_seccomp_filter(&ctx);

    if (ctx == NULL)
        exit_with_error(ERROR_SECCOMP_INIT, LOG_LEVEL_FATAL, "seccomp set failed", log_file, "compile.c");

    seccomp_load(ctx);
    seccomp_release(ctx);

    pid_t pid = fork();

    if (pid == -1)
        exit_with_error(ERROR_FORK, LOG_LEVEL_FATAL, "child process create failed", log_file, "compile.c");
    else if (pid == 0) {
        char *argn[] = {compiler_path};
        int v_index = 0;
        while (argv[v_index] != NULL) {
            argn[v_index + 1] = argv[v_index];
            v_index++;
        }
        argn[v_index + 1] = NULL;
        int rs = execvp(compiler_path, argn);
        exit(rs);
    } else {
        int status;
        if (wait4(pid, &status, WSTOPPED, NULL) == -1) {
            int rs = kill(pid, SIGKILL);
            if (rs != 0)
                exit_with_error(ERROR_KILL, LOG_LEVEL_FATAL, "kill process failed", log_file,
                                "compile.c");
        }

        if (status != 0) {
            *result = -1;
            exit_with_error(ERROR_COMPILE, LOG_LEVEL_ERROR, "compile error", log_file, "compile.c");
        } else
            *result = 0;
    }
}

