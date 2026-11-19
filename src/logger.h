/* logger.h - event logging (FR8). Prints to the screen and, if opened, also to a log file. */
#ifndef LOGGER_H
#define LOGGER_H

enum { LOG_INFO = 0, LOG_WARN, LOG_SECURITY, LOG_ERROR };

int  log_open(const char *path);                 /* creates the folder if needed; returns 0 on success */
void log_write(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void log_close(void);

#define LOGI(...) log_write(LOG_INFO,     __VA_ARGS__)
#define LOGW(...) log_write(LOG_WARN,     __VA_ARGS__)
#define LOGS(...) log_write(LOG_SECURITY, __VA_ARGS__)
#define LOGE(...) log_write(LOG_ERROR,    __VA_ARGS__)
#endif
