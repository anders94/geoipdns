#ifndef QLOG_H
#define QLOG_H

#include "uint16.h"

extern void qlog(const char *,uint16,const char *,const char *,const char *,const char *);
extern void dlog(const char *);
//extern char * fqdn_read (char *, int *, int *, const char *);
extern char *fqdn_read(char *, const char *);
#endif
