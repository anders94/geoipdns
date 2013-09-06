#include "uint16.h"
#include "logger.h"
#include "alloc.h"
#include "str.h"
#include <string.h>
#include <stdlib.h>
#include "ip4.h"
#include "open.h"
#include "tai.h"
#include "cdb.h"
#include "byte.h"
#include "case.h"
#include "dns.h"
#include "seek.h"
#include "response.h"
#include "ipdb.h"
#include "env.h"
#include "scan.h"
#include "prot.h"
#include "strerr.h"
#include "stralloc.h"
#include "qlog.h"
#include "uint64.h"
#define FATAL "ipdbops: fatal: "

int ipdb_key4build(key,ipuint,mask,mid,uid)
	unsigned char key[15];
	unsigned int ipuint;
	unsigned char mask;
	uint32 mid;
	uint32 uid;
{
	int i;
	unsigned int netmask = 0;
	key[0] = '\0';
	key[1] = '%';
	uint32_pack(key+2,mid);
	uint32_pack(key+6,uid);
	key[10] = (ipuint >> 24) & 0xff;
	key[11] = (ipuint >> 16) & 0xff;
	key[12] = (ipuint >> 8) & 0xff;
	key[13] = ipuint & 0xff;
	key[14] = mask;
	return 1;

}

int ipdb_key4lookup(key,ipuint,mask,mid,uid)
	unsigned char key[15];
	unsigned int ipuint;
	unsigned char mask;
	uint32 mid;
	uint32 uid;
{
	int i;
	unsigned int netmask = 0;
	key[0] = '\0';
	key[1] = '%';
	uint32_pack(key+2,mid);
	uint32_pack(key+6,uid);
	for (i = 0; i < mask; i++) netmask |= 1 << (31 - i);
	ipuint = ipuint & netmask;
	key[10] = (ipuint >> 24) & 0xff;
	key[11] = (ipuint >> 16) & 0xff;
	key[12] = (ipuint >> 8) & 0xff;
	key[13] = ipuint & 0xff;
	key[14] = mask;
	return 1;
}

/*
int ipdb_key_from_uint(key,ipuint,mask,applymask,mid,uid)
	unsigned char key[15];
	unsigned int ipuint;
	unsigned char mask;
	int applymask;
	uint32 mid;
	uint32 uid;
{
	int i;
	unsigned int netmask = 0;
	key[0] = '\0';
	key[1] = '%';
	uint32_pack(key+2,mid);
	uint32_pack(key+6,uid);
	//key[2] = mapid;
	if (applymask) {
		for (i = 0; i < mask; i++) netmask |= 1 << (31 - i);
		ipuint = ipuint & netmask;
	}
	key[10] = (ipuint >> 24) & 0xff;
	key[11] = (ipuint >> 16) & 0xff;
	key[12] = (ipuint >> 8) & 0xff;
	key[13] = ipuint & 0xff;
	key[14] = mask;
	return 1;
}
int ipdb_key_from_str(key,ipstr,mask,applymask,uid,mapid)
	unsigned char key[15];
	const char *ipstr;
	unsigned char mask;
	int applymask;
	uint32  uid;
	uint32 mapid;
{
	unsigned char ip[4];
	unsigned int j;
	ip4_scan(ipstr,ip);
	ip4_num(&j,ip);
	return ipdb_key_from_uint(key,j,mask,applymask,uid,mapid);
}

int ipdb_key_from_bytes(key,ip,mask,applymask,uid,mapid)
	unsigned char key[15];
	unsigned char ip[4];
	unsigned char mask;
	int applymask;
	uint32 uid;
	uint32 mapid;
{
	unsigned int j;
	ip4_num(&j,ip);
	return ipdb_key_from_uint(key, j,mask,applymask,uid,mapid);
}
*/
#define IPDB_TRYLOOKUP(m) do {\
	ipdb_key4lookup(key,ipint,m,mid,uid);\
	r = cdb_find(c,key,15); \
	if (r == -1) return 0; \
	if (r == 1) {\
		if (cdb_read(c,cc,4,cdb_datapos(c)) == -1) { \
			return 0; \
		} else { \
			uint32_unpack(cc,clientloc); \
			return 1; \
		}  \
	} \
	} while (0);

int ipdb_get(c,ip,clientloc,mid,uid)
	struct cdb *c;
	unsigned char ip[4];
	uint32 *clientloc;
	uint32 mid;
	uint32 uid;
{
	unsigned char key[15];
	//unsigned char intmask;
	unsigned int ipint = 0;
	int r = -1;
	char cc[4];
	ip4_num(&ipint,ip);
IPDB_TRYLOOKUP(24);
IPDB_TRYLOOKUP(28);
IPDB_TRYLOOKUP(29);
IPDB_TRYLOOKUP(27);
IPDB_TRYLOOKUP(32);
IPDB_TRYLOOKUP(23);
IPDB_TRYLOOKUP(26);
IPDB_TRYLOOKUP(30);
IPDB_TRYLOOKUP(25);
IPDB_TRYLOOKUP(22);
IPDB_TRYLOOKUP(19);
IPDB_TRYLOOKUP(21);
IPDB_TRYLOOKUP(20);
IPDB_TRYLOOKUP(16);
IPDB_TRYLOOKUP(18);
IPDB_TRYLOOKUP(31);
IPDB_TRYLOOKUP(17);
IPDB_TRYLOOKUP(15);
IPDB_TRYLOOKUP(14);
IPDB_TRYLOOKUP(13);
IPDB_TRYLOOKUP(12);
IPDB_TRYLOOKUP(11);
IPDB_TRYLOOKUP(10);
IPDB_TRYLOOKUP(9);
IPDB_TRYLOOKUP(8);
IPDB_TRYLOOKUP(7);
IPDB_TRYLOOKUP(6);
IPDB_TRYLOOKUP(5);
IPDB_TRYLOOKUP(4);
IPDB_TRYLOOKUP(3);
IPDB_TRYLOOKUP(2);
IPDB_TRYLOOKUP(1);

	/* nothing found, then go with defloc XX */
	//dbger("LOC not found for (mid=%u,uid=%u)\n",mid,uid);
	return 1;
}

