#ifndef ____LOGGER_H__
#define ____LOGGER_H__
#include <stdarg.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#define ERR_FD STDERR_FILENO
#define OUT_FD STDOUT_FILENO

#define STRINGIFY(x) #x
#define TO_STR(x) STRINGIFY(x)
#define ERR_SRC __FILE__ ":" TO_STR(__LINE__) 
//void outerr_rst (void);
void _die (int _fd__, const char *err_src, const char *fmt, ...);
void _dbg(int _fd__, const char *err_src, const char *fmt, ...);
void _warn(int _fd__, const char *err_src, const char *fmt, ...);
void _inf (int _fd__, const char *fmt, ...);
void loini(void);

#define wrner(fmt, args...) _warn(ERR_FD,ERR_SRC,fmt, ## args)
#define dienow(fmt, args...) _die(ERR_FD,ERR_SRC,fmt, ## args)
#define dbger(fmt, args...) _dbg(ERR_FD,ERR_SRC,fmt, ## args)
#define infrmer(fmt, args...) _inf(OUT_FD,fmt, ## args)
#endif

