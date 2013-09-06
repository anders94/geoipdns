#include "scan.h"

unsigned int scan_ushort(register const char *s,register unsigned short *u)
{
  register unsigned int pos = 0;
  register unsigned short result = 0;
  register unsigned short c;
  while ((c = (unsigned short) (unsigned char) (s[pos] - '0')) < 10) {
    result = result * 10 + c;
    ++pos;
  }
  *u = result;
  return pos;
}
