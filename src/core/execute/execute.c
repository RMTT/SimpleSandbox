#include <seccomp.h>
#include <stdlib.h>
#include "execute.h"
#include "error.h"
#include "logger.h"

void init_execute_seccomp_filter(scmp_filter_ctx *ctx, const char *log_file) {
    *ctx = seccomp_init(SCMP_ACT_KILL);

    int systemcall_whitelist[] = {
            SCMP_SYS(read), SCMP_SYS(access), SCMP_SYS(fstat),
            SCMP_SYS(close), SCMP_SYS(write), SCMP_SYS(mmap)
    };


    int whitelist_length = sizeof(systemcall_whitelist) / sizeof(systemcall_whitelist[0]);



    /* add the rule that do not need control*/
    for (int i = 0; i < whitelist_length; i++)
        if (seccomp_rule_add(*ctx, SCMP_ACT_ALLOW, systemcall_whitelist[i], 0) != 0)
            exit_with_error(ERROR_SECCOMP_RULE, LOG_LEVEL_FATAL, "add seccomp filter faild", log_file, "execute.c");
}


void execute(struct execute_config *config, struct execute_result *result) {
    scmp_filter_ctx ctx;
    init_execute_seccomp_filter(&ctx, config->log_path);


    /* add the filter that must control the argument*/
    //if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve),
    //SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t) config->exec_path)) != 0)
    //    exit_with_error(ERROR_SECCOMP_RULE, LOG_LEVEL_FATAL, "add seccomp filter faild", config->log_path, "execute.c");
    // TODO: limit the argument of execve,but the char* maybe can not convert to u64int
}