/* Public domain. */
#ifndef USE_SFHASH
#warning "USE_CDBHASH"
#include "cdb.h"

uint32 cdb_hashadd(uint32 h,unsigned char c)
{
  h += (h << 5);
  return h ^ c;
}

uint32 cdb_hash(const char *buf,unsigned int len)
{
  uint32 h;

  h = CDB_HASHSTART;
  while (len) {
    h = cdb_hashadd(h,*buf++);
    --len;
  }
  return h;
}

#else
#warning "USE_SFHASH"
#include "uint32.h"
#include "uint16.h"
#include "uint8.h"

#if (defined(__GNUC__) && defined(__i386__)) || defined(__WATCOMC__) \
	|| defined(_MSC_VER) || defined (__BORLANDC__) || defined (__TURBOC__)
	#define GET16B(d) (*((const uint16 *) (d)))
#else
	#define GET16B(d) ((((uint32)(((const uint8 *)(d))[1])) << 8) \
	+(uint32)(((const uint8 *)(d))[0]) )
#endif
uint32 cdb_hash (const char *key, uint32 keylen)
{
	uint32 hkey = 5381;
	uint32 tmp;
	uint32 rem;
	if (keylen <= 0 || key == 0) return 0;
	rem = keylen & 3;
	keylen >>= 2;
	for (;keylen> 0; keylen--) {
		hkey += GET16B(key);
		tmp = (GET16B(key+2) << 11) ^ hkey;
		hkey = (hkey << 16) ^ tmp;
		key += 2*sizeof(uint16);
		hkey += hkey >> 11;
	}
	switch (rem) {
		case 3:
			hkey += GET16B (key);
			hkey ^= hkey << 16;
			hkey ^= key[sizeof (uint16)] << 18;
			hkey += hkey >> 11;
			break;
		case 2:
			hkey += GET16B (key);
			hkey ^= hkey << 11;
			hkey += hkey >> 17;
			break;
		case 1:
			hkey += *key;
			hkey ^= hkey << 10;
			hkey += hkey >> 1;
	}
	hkey ^= hkey << 3;
	hkey += hkey >> 5;
	hkey ^= hkey << 4;
	hkey += hkey >> 17;
	hkey ^= hkey << 25;
	hkey += hkey >> 6;
	return hkey;
}
#endif
/*
int main (int argc, char **argv)
{
    if (argc != 2) exit(1);
    printf("sfhash(%s)=%u\n", argv[1],sfhash(argv[1],strlen(argv[1])));
}

*/
