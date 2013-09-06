
char * fqdn_read(out,q)
//char * fqdn_read(out,label_idx,len,q)
	char *out;
/*
	int *label_idx;
	int *len;
*/
	const char *q;
{
	int *len;
	int label_idx[32];
	char ch;
	int maxlen ;
	char ch2;
	int cur_len = 0;
	register int i = 0;
	register int j = 0;
	len=alloc(4);
	byte_zero(len,4);
	*len=255;
	maxlen=*len;
  if (!*q) {
		out[0] = '.';
		label_idx[0] = -1;
		*len = 1;
		return out;
  } else {
		label_idx[0] = 0;
    for (;;) {
      ch = *q++;
			cur_len+=ch;
			if (cur_len >= maxlen) return (char *)0;
      while (ch--) {
        ch2 = *q++;
        if ((ch2 >= 'A') && (ch2 <= 'Z'))
	  			ch2 += 32;
        if (((ch2 >= 'a') && (ch2 <= 'z')) || ((ch2 >= '0') && (ch2 <= '9')) || (ch2 == '-') || (ch2 == '_')) {
					out[j++] = ch2;
        } else {
					out[j] = '\\';j++;
					out[j+1] = '0' + ((ch2 >> 6) & 7);
					out[j+2] = '0' + ((ch2 >> 3) & 7);
					out[j+3] = '0' + (ch2 & 7);
					j+=4;
				}
      }
      if (!*q) break;
			out[j++] = '.';
			i+=1;
			if (i == 32) break;
			label_idx[i] = j;
			cur_len+=1;
    }
	}
	out[j]='\0';
	*len = cur_len;
	return out;
}
