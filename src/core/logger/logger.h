//
// Created by mt on 6/22/18.
//

#ifndef IMCODER_JUDGER_LOGGER_H
#define IMCODER_JUDGER_LOGGER_H


#define MAX_LOG_SIZE 200

/**
 * the level of log
 * from 0 to 4,gradual increase in severity*/
#define LOG_LEVEL_FATAL 0
#define LOG_LEVEL_ERROR 1
#define LOG_LEVEL_WARNING 2
#define LOG_LEVEL_INFO 3
#define LOG_LEVEL_DEBUG 4

extern const char const *LOG_LEVEL[];

/**
 * write log
 * @param level the level of log
 * @param source_file the file of occur error
 * @param log_file the log file
 * @param message the error message
 * @param write_mod the type of write to file */
extern void
log_write(int level, const char *source_file, const char *log_file, const char *message, const char *write_mod);

#define log(source_file, log_file, message, write_mod)\
log_write(LOG_LEVEL_WARNING, source_file,log_file,message, write_mod)

#define log_debug(source_file, log_file, message, write_mod)\
log_write(LOG_LEVEL_DEBUG, source_file,log_file,message, write_mod)

#define log_info(source_file, log_file, message, write_mod)\
log_write(LOG_LEVEL_INFO, source_file,log_file,message, write_mod)

#define log_warning(source_file, log_file, message, write_mod)\
log_write(LOG_LEVEL_WARNING, source_file,log_file,message, write_mod)

#define log_error(source_file, log_file, message, write_mod)\
log_write(LOG_LEVEL_ERROR, source_file,log_file,message, write_mod)

#define log_fatal(source_file, log_file, message, write_mod)\
log_write(LOG_LEVEL_FATAL, source_file,log_file,message, write_mod)

#endif //IMCODER_JUDGER_LOGGER_H
