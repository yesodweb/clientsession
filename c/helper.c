#include <stdlib.h>

typedef unsigned char uchar;
typedef unsigned int uint;
#define Nb 4			// number of columns in the state & expanded key
#define Nr 10			// number of rounds in encryption

void ExpandKey(uchar *key, uchar *expkey);
void Encrypt (uchar *in, uchar *expkey, uchar *out);
void Decrypt (uchar *in, uchar *expkey, uchar *out);

/* len must be a multiple of 16 */
uchar * encrypt(uint len, uchar *in, uchar *key)
{
	uchar expkey[4 * Nb * (Nr + 1)];
	uchar *out = malloc(len);
	uint i;

	ExpandKey(key, expkey);

	for (i = 0; i < len; i += 16) {
		Encrypt(in + i, expkey, out + i);
	}

	return out;
}

uchar * decrypt(uint len, uchar *in, uchar *key)
{
	uchar expkey[4 * Nb * (Nr + 1)];
	uchar *out = malloc(len);
	uint i;

	ExpandKey(key, expkey);

	for (i = 0; i < len; i += 16) {
		Decrypt(in + i, expkey, out + i);
	}

	return out;
}
