//
// Created by mt on 6/23/18.
//

#ifndef IMCODER_JUDGER_ERROR_H
#define IMCODER_JUDGER_ERROR_H

/**
 * this function be used to handle error and write log
 * @param code error code
 * @param level fatal error or common error
 * @param log_file the log file
 * @param source_file the file that occur error*/
extern void exit_with_error(int code, int level, char *message, char *log_file, char *source_file);

#endif //IMCODER_JUDGER_ERROR_H
