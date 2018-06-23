//
// Created by mt on 6/22/18.
//

#include "logger.h";
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <memory.h>

void log_write(int level, char *source_file, char *log_file, char *message, char *write_mod) {
    FILE *logfile = fopen(log_file, write_mod);
    if (logfile == NULL) {
        fprintf(stderr, "can not open log file %s", log_file);
        return;
    }

    char datetime[21];
    time_t now = NULL;
    time(&now);
    strftime(datetime, 99, "%Y-%m-%d %H:%M:%S", localtime(&now));

    char *buffer[MAX_LOG_SIZE];
    int fd = fileno(logfile);

    int log_size = snprintf(buffer, MAX_LOG_SIZE, "[%s %s]: %s on %s\n", LOG_LEVEL[level], datetime, source_file,
                            message);

    struct flock lock;
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_END;

    if (fcntl(fd, F_SETLKW, lock)) {
        if (write(fd, buffer, (size_t) log_size) == -1)
            fprintf(stderr, "the log [%s] write failed", buffer);
    }
    fclose(logfile);
}
