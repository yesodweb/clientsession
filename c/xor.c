#include <stdlib.h>
#include <stdio.h>
#include <string.h>

unsigned char * xor(int keylen, unsigned char *key, int datalen,
		    unsigned char *buff)
{
	int i, j;
	char *dest = malloc(datalen);

	if (keylen == 0) {
		memcpy(dest, buff, datalen);
		return dest;
	}

	for (i = j = 0; i < datalen; ++i, ++j) {
		if (j >= keylen) j = 0;
		dest[i] = buff[i] ^ key[j];
	}

	return dest;
}
