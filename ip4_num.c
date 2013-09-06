#include <unistd.h>
void ip4_num(unsigned int *u,unsigned char ip[4])
{ 
	*u |= ip[0]<<24;
	*u |= ip[1]<<16;
	*u |= ip[2]<<8;
	*u |= ip[3];
}

