#include "ip4.h"
#include <string.h>
#include <stdlib.h>
#include "alloc.h"
#include <stdio.h>
#include <unistd.h>
#define FULL_MASK 4294967295
int ip4_deaggregate2 (unsigned int hostmin, unsigned int hostmax, ip4_cidr_t **subnets,unsigned int *slen)
{
	unsigned int step;
	unsigned int mask = 0;
	unsigned int i = 0;
	unsigned int base = hostmin;
	while (base <= hostmax) {
		step = 32;
		while ( (base | ( 1 << step)) != base) {
			if ((base | (((~0) & FULL_MASK) >> (31-step))) > hostmax) break;
			step++;
		}
		mask = 32 - step;
		if (*slen == 0) {
			*subnets = (ip4_cidr_t *)alloc(sizeof(ip4_cidr_t));
			if (!*subnets) return -1;
			(*subnets)[0].subnet = 0;
			(*subnets)[0].mask = 0;
		} else {
			if (alloc_re(subnets, (*slen)*sizeof(ip4_cidr_t), ((*slen) + 1)*sizeof(ip4_cidr_t)) == 0) return -1;
		}
		(*subnets)[*slen].subnet = base;
		(*subnets)[*slen].mask = mask;
		base += 1 << step;
		(*slen)++;
	}
	return 1;

}
int ip4_deaggregate (unsigned int hostmin, unsigned int hostmax, ip4_cidr_t **subnets,unsigned int *slen)
{
	unsigned int step;
	unsigned int mask = 0;
	unsigned int i = 0;
	unsigned int base = hostmin;
	while (base <= hostmax) {
		step = 0;
		while ( (base | ( 1 << step)) != base) {
			if ((base | (((~0) & FULL_MASK) >> (31-step))) > hostmax) break;
			step++;
		}
		mask = 32 - step;
		if (*slen == 0) {
			*subnets = (ip4_cidr_t *)alloc(sizeof(ip4_cidr_t));
			if (!*subnets) return -1;
			(*subnets)[0].subnet = 0;
			(*subnets)[0].mask = 0;
		} else {
			if (alloc_re(subnets, (*slen)*sizeof(ip4_cidr_t), ((*slen) + 1)*sizeof(ip4_cidr_t)) == 0) return -1;
		}
		(*subnets)[*slen].subnet = base;
		(*subnets)[*slen].mask = mask;
		base += 1 << step;
		(*slen)++;
	}
	return 1;
}
