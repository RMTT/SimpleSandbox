//
// Created by mt on 6/22/18.
//

#ifndef IMCODER_JUDGER_LOGGER_H
#define IMCODER_JUDGER_LOGGER_H

/**
 * the level of log
 * from 0 to 4,gradual increase in severity*/
#define LOG_LEVEL_FATAL 0
#define LOG_LEVEL_ERROR 1
#define LOG_LEVEL_WARNING 2
#define LOG_LEVEL_INFO 3
#define LOG_LEVEL_DEBUG 4

char *LOG_LEVEL[] = {"FATAL_ERROR", "ERROR", "WARNING", "INFO", "DEBUG"};

/**
 * write log
 * @param level the level of log
 * @param source_file the file of occur error
 * @param the line of source file
 * @param message the error message*/
void log_write(int level, char *source_file, int line, char *message);

#endif //IMCODER_JUDGER_LOGGER_H
