//
// Created by mt on 6/22/18.
//

#include <seccomp.h>
#include "compile.h"
#include <stdlib.h>
#include <zconf.h>
#include "error.h"
#include "logger.h"
#include <stdio.h>
#include <wait.h>
#include <signal.h>

void init_compile_seccomp_filter(scmp_filter_ctx *ctx) {
    *ctx = seccomp_init(SCMP_ACT_ALLOW);
}


void compile(const char *compiler_path, struct compile_config *config, char *argv[], char *envp[]) {
    scmp_filter_ctx ctx = NULL;
    init_compile_seccomp_filter(&ctx);

    if (ctx == NULL)
        exit_with_error(1, LOG_LEVEL_FATAL, "seccomp set failed", config->log_file, "compile.c");

    seccomp_load(ctx);
    seccomp_release(ctx);
    setuid((__uid_t) config->uid);
    setgid((__gid_t) config->gid);

    pid_t pid = fork();

    if (pid == -1)
        exit_with_error(1, LOG_LEVEL_FATAL, "child process create failed", config->log_file, "compile.c");
    else if (pid == 0) {
        int rs = execve(compiler_path, argv, envp);
        printf("%d\n", rs);
        exit(rs);
    } else {
        int status;
        if (wait4(pid, &status, WSTOPPED, NULL) == -1) {
            int rs = kill(pid, SIGKILL);
            if (rs != 0)
                exit_with_error(1, LOG_LEVEL_FATAL, "kill process failed", config->log_file,
                                "compile.c");
        }
    }
}

