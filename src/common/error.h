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

#define SUCCESS_COMPLETE 0

#define ERROR_KILL_PROCESS  1314 + 1
#define ERROR_COMPILE 1314 + 2
#define ERROR_FORK 1314 + 3
#define ERROR_SECCOMP_INIT 1314 + 4
#define ERROR_SECCOMP_RULE 1314 + 5
#define ERROR_SECCOMP_LOAD 1314 + 6
#define ERROR_SET_UID 1314 + 7
#define ERROR_SET_GID 1314 + 8
#define ERROR_SET_RLIMIT 1314 + 9
#define ERROR_FILE_OPEN  1314 + 10
#define ERROR_FILE_DUP2 1314 + 11
#define ERROR_NOT_ROOT 1314 + 12
#define ERROR_CREATE_PROCESS 1314 + 13


#endif //IMCODER_JUDGER_ERROR_H
