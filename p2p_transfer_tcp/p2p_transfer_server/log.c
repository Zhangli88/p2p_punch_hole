#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>

static const char* LEVEL_NAMES[] = {"DEBUG", "INFO", "NOTICE", "WARN", "ERROR", "FATAL"};

static int enable_console = 1;
static FILE *log_stream = NULL;
static int log_level = EN_PRINT_INFO;

int configure_log(int lvl, const char* file, int use_console) {
    FILE *stream = NULL;
    int res = 0;

    if (lvl > EN_PRINT_ERROR)
        lvl = EN_PRINT_ERROR;
    else if (lvl < EN_PRINT_DEBUG)
        lvl = EN_PRINT_DEBUG;
    log_level = lvl;
    enable_console = use_console;
    if (file != NULL) {
        stream = fopen(file, "a");
        if (stream == NULL) {
			XL_DEBUG(EN_PRINT_ERROR, "error opening log file, err: %s", strerror(errno));
            res = 1;
        } else {
            log_stream = stream;
        }
    }

    return res;
}

void destroy_log()
{
	if (log_stream != NULL)
	{
		fclose(log_stream);
	}
}

void logging(int lvl, const char *file, const char *func, const int line, const char *fmt, ...) {
    va_list ap;
    char buffer[512], *ptr = buffer;
    int size, cap = 512;
    time_t ts;
    struct tm *tmp;

    if (lvl < log_level) {
        return;
    }

    ts = time(NULL);
    tmp = localtime(&ts);
    size = strftime(ptr, cap, "[%Y-%m-%d %H:%M:%S]", tmp);
    ptr += size;
    cap -= size;
    size = snprintf(ptr, cap, "[%6s][%s:%d][%s] ",
                    LEVEL_NAMES[lvl], file, line, func);
    ptr += size;
    cap -= size;

    va_start(ap, fmt);
    size = vsnprintf(ptr, cap, fmt, ap);
    va_end(ap);

    *(ptr + size) = '\n';
    *(ptr + size + 1) = '\0';

    if (enable_console) {
        if (lvl >= EN_PRINT_WARN) {
            fputs(buffer, stderr);
        } else {
            fputs(buffer, stdout);
        }
    }

    if (log_stream != NULL) {
		fputs(buffer, log_stream);
        fflush(log_stream);
    }
}
