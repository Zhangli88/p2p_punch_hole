#ifndef __LOG_H_
#define __LOG_H_

enum _log_level {
	EN_PRINT_DEBUG,
	EN_PRINT_INFO,
	EN_PRINT_NOTICE,
	EN_PRINT_WARN,
	EN_PRINT_ERROR,
	EN_PRINT_FATAL,
};

int configure_log(int level, const char* file, int use_console);
void destroy_log();

void logging(int lvl, const char *file, const char *func, const int line, const char *fmt, ...);

#define XL_DEBUG(lvl, fmt, ...) logging(lvl, __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)

#endif /* __LOG_H_ */
