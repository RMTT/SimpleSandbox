//
// Created by mt on 6/22/18.
//

#include <seccomp.h>
#include "compile.h"

void init_compile_seccomp_filter(scmp_filter_ctx *ctx) {
    *ctx = seccomp_init(SCMP_ACT_ALLOW);
}


int compile(char *file, char *output_file, char *compile_command, struct compile_config *config) {
    scmp_filter_ctx ctx;
    init_compile_seccomp_filter(*ctx);
}

