//
// Created by Mt on 9/12/19.
//

#include <stdio.h>
#include "compile.h"
#include "execute.h"
#include <stdlib.h>

int main() {

    /************************  compile ************************/
    struct compile_config *ccfg;
    struct compile_result *cres;
    compile_result_init(&cres);
    compile_init(&ccfg, "/usr/bin/g++", "/home/rmt/log/judger.log", "/home/rmt/log/tmp");
    compile_add_argv(ccfg, "/usr/bin/g++");
    compile_add_argv(ccfg, "/home/rmt/SandBox/tests/a+b.cpp");
    compile_add_argv(ccfg, "-o");
    compile_add_argv(ccfg, "/home/rmt/bin/judger");
    compile(ccfg, cres);
    printf("%s\n", cres->message);

    /************************  execute ************************/
    struct execute_config *ecfg;
    struct execute_result *eres = malloc(sizeof(struct execute_result));
    execute_init(&ecfg, 100, 1024 * 1024 * 10, 1024 * 1024 * 10, 1, 1024 * 1024 * 1024);
    execute_set_exec(ecfg, "/home/rmt/bin/judger");
    execute_set_input(ecfg, "/home/rmt/SandBox/tests/input/1.in");
    execute_set_output(ecfg, "/home/rmt/1.out");
    execute_set_log(ecfg, "/home/rmt/log/judger.log");
    execute_add_arg(ecfg, "/home/rmt/bin/judger");
    execute_result_init(&eres);
    execute(ecfg, eres);
    printf("%s\n", eres->message);
    printf("time used: %ld ms\n", eres->used_time);
    printf("memory used: %ld kb\n", eres->used_memory);
    return 0;
}