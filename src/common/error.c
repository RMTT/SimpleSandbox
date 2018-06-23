//
// Created by mt on 6/23/18.
//

#include <stdlib.h>
#include "error.h"
#include "logger.h"

void exit_with_error(int code, int level, char *message, char *log_file, char *source_file) {
    log_write(level, source_file, log_file, message, "a");
    exit(code);
}
