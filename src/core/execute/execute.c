#include <seccomp.h>
#include <stdlib.h>
#include "execute.h"
#include "error.h"
#include "logger.h"

int init_execute_seccomp_filter(scmp_filter_ctx *ctx, const char *log_file) {
    *ctx = seccomp_init(SCMP_ACT_KILL);

    int systemcall_whitelist[] = {
            SCMP_SYS(read), SCMP_SYS(access), SCMP_SYS(fstat),
            SCMP_SYS(close), SCMP_SYS(write), SCMP_SYS(mmap),
            SCMP_SYS(socket)
    };


    int whitelist_length = sizeof(systemcall_whitelist) / sizeof(systemcall_whitelist[0]);



    /* add the rule that do not need control*/
    for (int i = 0; i < whitelist_length; i++)
        if (seccomp_rule_add(*ctx, SCMP_ACT_ALLOW, systemcall_whitelist[i], 0) != 0)
            return -1;
    return 0;
}


void execute(struct execute_config *config, struct execute_result *result) {
    scmp_filter_ctx ctx;
    int rs = init_execute_seccomp_filter(&ctx, config->log_path);
    if (rs == -1) {
        EXIT_WITH_FATAL_ERROR(ERROR_SECCOMP_RULE);
    }


    /* add the filter that must control the argument*/

    // limit the execve
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve),
                         1, SCMP_A0(SCMP_CMP_NE, (scmp_datum_t) config->exec_path)) != 0)
        EXIT_WITH_FATAL_ERROR(ERROR_SECCOMP_RULE);

    // limit

}