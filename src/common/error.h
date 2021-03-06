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

#define ERROR_KILL_PROCESS  1
#define ERROR_COMPILE 2
#define ERROR_FORK 3
#define ERROR_SECCOMP_INIT 4
#define ERROR_SECCOMP_RULE 5
#define ERROR_SECCOMP_LOAD 6
#define ERROR_SET_UID 7
#define ERROR_SET_GID 8
#define ERROR_SET_RLIMIT 9
#define ERROR_FILE_OPEN  10
#define ERROR_FILE_DUP2 11
#define ERROR_NOT_ROOT 12
#define ERROR_CREATE_PROCESS 13


#define SYSTEM_ERROR_SIGNAL SIGUSR1
#define SUCCESS_PROCEED_SIGNAL SIGUSR2


#endif //IMCODER_JUDGER_ERROR_H
