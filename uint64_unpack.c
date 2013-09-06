#include "uint64.h"

void uint64_unpack(const unsigned char s[8],uint64 *u)
{
  uint64 x;

  x = (unsigned char) s[7];
  x <<= 8; x += (unsigned char) s[6];
  x <<= 8; x += (unsigned char) s[5];
  x <<= 8; x += (unsigned char) s[4];
  x <<= 8; x += (unsigned char) s[3];
  x <<= 8; x += (unsigned char) s[2];
  x <<= 8; x += (unsigned char) s[1];
  x <<= 8; x += (unsigned char) s[0];
  *u = x;
}

void uint64_unpack_big(const unsigned char s[8],uint64 *u)
{
  uint64 x;

  x = (unsigned char) s[0];
  x <<= 8; x += (unsigned char) s[1];
  x <<= 8; x += (unsigned char) s[2];
  x <<= 8; x += (unsigned char) s[3];
  x <<= 8; x += (unsigned char) s[4];
  x <<= 8; x += (unsigned char) s[5];
  x <<= 8; x += (unsigned char) s[6];
  x <<= 8; x += (unsigned char) s[7];
  *u = x;
}
