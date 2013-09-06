#include "logger.h"


extern int errno;

static void out (int ofd, const char *fmt, va_list ap)
{
	char buf[1024];
	bzero(buf,1024);
	vsprintf(buf,fmt,ap);
	strcat(buf,"\n");
	write(ofd, buf, strlen(buf));
}
static void err (int efd, const char *err_src, const char *fmt, va_list ap)
{
	int errno_save = 0;
	char buf[1024];
	errno_save = errno;
	bzero(buf,1024);
	vsprintf(buf,fmt,ap);
#ifdef UGLY_DEBUG
	sprintf(buf+strlen(buf), " (err_code=%d, err_msg=\'%s\', source=%s)\n",errno_save, strerror(errno_save),
		(err_src!=NULL)?err_src:"unknown_source");
#else
	strcat(buf, "\n");
#endif
	write(efd, buf, strlen(buf));
}

void _dbg (int efd, const char *err_src, const char *fmt, ...)
{
#ifdef DEBUG_MODE
	va_list ap;
	va_start (ap,fmt);
	err(efd,err_src,fmt,ap);
	va_end(ap);
#endif
	return;

}
/*
void outerr_rst (void)
{
	int i = 0;
	int rc = 0;
	char erfile[64];
	char outfile[64];
	bzero(erfile, 64);
	sprintf(erfile, "logs/%d.err",getpid());
	sprintf(outfile,"logs/%d.out",getpid());
	for (i = 0; i < FD_SETSIZE; i++) close(i);
	errno = 0;
	open("/dev/null", O_RDONLY);
	rc = open(outfile, O_WRONLY|O_CREAT|O_TRUNC,0666);
	fprintf(stdout, "%s: rc=%d err=%s", OUT_LOGFILE, rc, strerror(errno));
	open(erfile, O_WRONLY|O_CREAT|O_TRUNC, 0666);
	fprintf(stdout, "%s: rc=%d err=%s", ERR_LOGFILE, rc, strerror(errno));
}
*/
static int st_err;
static int st_out;

void loini (void)
{
	return;
}

void _inf (int ofd, const char *fmt, ...)
{
	va_list ap;
	va_start(ap,fmt);
	out(ofd,fmt,ap);
	va_end(ap);
	return;
}

void _warn (int efd, const char *err_src, const char *fmt, ...)
{
	va_list ap;
	va_start (ap,fmt);
	err(efd,err_src,fmt,ap);
	va_end(ap);
	return;
}


void _die (int _fd__, const char *err_src, const char *fmt, ...)
{
	va_list ap;
	va_start (ap, fmt);
	err(_fd__,err_src,fmt,ap);
	va_end(ap);
	exit(EXIT_FAILURE);
}

