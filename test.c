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

    return 0;
}