#ifndef IP4_H
#define IP4_H

extern unsigned int ip4_scan(const char *,unsigned char *);
extern unsigned int ip4_fmt(char *,const char *);

extern void ip4_num(unsigned int *u,unsigned char ip[4]);

#define IP4_FMT 20

typedef struct {
	unsigned int subnet;
	unsigned char mask;
} ip4_cidr_t;

int ip4_deaggregate (unsigned int ,unsigned int, ip4_cidr_t **, unsigned int *);

#endif
