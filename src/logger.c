/* logger.c - thread-safe logger: one line per event, with time stamp and level.
 * Owner   : Ishita (module M1 support)
 */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "logger.h"

static FILE *g_file = NULL;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

int log_open(const char *path)
{
    char dir[256];
    snprintf(dir, sizeof dir, "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash) { *slash = 0; mkdir(dir, 0755); }
    g_file = fopen(path, "a");
    return g_file ? 0 : -1;
}

void log_write(int level, const char *fmt, ...)
{
    static const char *name[] = {"INFO", "WARN", "SECURITY", "ERROR"};
    char ts[16], msg[1024];
    time_t t = time(NULL);
    struct tm tmv;
    localtime_r(&t, &tmv);
    strftime(ts, sizeof ts, "%H:%M:%S", &tmv);

    va_list ap; va_start(ap, fmt); vsnprintf(msg, sizeof msg, fmt, ap); va_end(ap);

    pthread_mutex_lock(&g_mu);
    printf("[%s] [%-8s] %s\n", ts, name[level], msg);
    fflush(stdout);
    if (g_file) {
        char date[16];
        strftime(date, sizeof date, "%Y-%m-%d", &tmv);
        fprintf(g_file, "%s %s [%s] %s\n", date, ts, name[level], msg);
        fflush(g_file);
    }
    pthread_mutex_unlock(&g_mu);
}

void log_close(void)
{
    pthread_mutex_lock(&g_mu);
    if (g_file) { fclose(g_file); g_file = NULL; }
    pthread_mutex_unlock(&g_mu);
}
