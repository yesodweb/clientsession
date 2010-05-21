#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef unsigned char uchar;
typedef unsigned int uint;
#define Nb 4			// number of columns in the state & expanded key
#define Nr 10			// number of rounds in encryption

void ExpandKey(uchar *key, uchar *expkey);
void Encrypt (uchar *in, uchar *expkey, uchar *out);
void Decrypt (uchar *in, uchar *expkey, uchar *out);

void get_hash(uint *out, uchar *in, uint len)
{
	uint32_t hash = 0;

	for (; len--; ++in) {
		hash = (hash >> 1) + ((hash & 1) << 31);
		hash += *in;
	}

	*out = hash;
}

/* http://base64.sourceforge.net/b64.c.  LICENCE:        Copyright (c) 2001
 * Bob Trower, Trantor Standard Systems Inc. */

static const char cb64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64_enc(char *out, uchar *in, uint len)
{
	while (len) {
		uchar buffin[3];
		buffin[0] = *(in++);
		if (--len) {
			buffin[1] = *(in++);
			if (--len) {
				buffin[2] = *(in++);
				--len;
			} else {
				buffin[2] = 0;
			}
		} else {
			buffin[1] = 0;
			buffin[2] = 0;
		}

		*(out++) = cb64[buffin[0] >> 2];
		*(out++) = cb64[ (buffin[0] & 0x03) << 4
			       | (buffin[1] & 0xf0) >> 4];
		*(out++) = cb64[ (buffin[1] & 0x0f) << 2
			       | (buffin[2] & 0xc0) >> 6];
		*(out++) = cb64[buffin[2] & 0x3f];
	}
}

int parse_char(uchar *out, char in)
{
	if ('A' <= in && in <= 'Z') {
		*out = in - 'A';
	} else if ('a' <= in && in <= 'z') {
		*out = in - 'a' + 26;
	} else if ('0' <= in && in <= '9') {
		*out = in - '0' + 52;
	} else if (in == '+') {
		*out = 62;
	} else if (in == '/') {
		*out = 63;
	} else {
		return 0;
	}
	return 1;
}

int base64_dec(uchar *out, char *in, uint len)
{
	for (; len; in += 4, out += 3, len -= 4) {
		uchar tmp[4];
		int i = 0;
		for (i = 0; i < 4; ++i) {
			if (! parse_char(tmp + i, in[i])) return 0;
		}
		out[0] = tmp[0] << 2 | tmp[1] >> 4;
		out[1] = tmp[1] << 4 | tmp[2] >> 2;
		out[2] = ((tmp[2] << 6) & 0xc0) | tmp[3];
	}
	return 1;
}

char * encrypt(uint32_t len, uchar *in, uchar *key, uint *outlen)
{
	uchar expkey[4 * Nb * (Nr + 1)];
	uchar *out;
	uint i;
	uint totlen, encoded_len;
	uchar *tmp;
	uchar buff[16];

	/* 4 bytes for the hash, 4 bytes for the length, then the string.
	 * Need to align to 16 bytes.
	 */
	totlen = len + 8;
	totlen += 16 - (totlen % 16);
	tmp = alloca(totlen);
	bzero(tmp, totlen);
	get_hash((uint*) tmp, in, len);
	memcpy(tmp + 4, &len, 4);
	memcpy(tmp + 8, in, len);

	ExpandKey(key, expkey);
	for (i = 0; i < totlen; i += 16) {
		//Encrypt(tmp + i, expkey, buff);

		//memcpy(tmp + 1, buff, 16);
	}

	encoded_len = (totlen + 2 - ((totlen + 2) % 3)) / 3 * 4;
	out = malloc(encoded_len + 1);
	out[encoded_len] = 0;
	base64_enc(out, tmp, totlen);

	*outlen = encoded_len;
	return out;
}

uchar * decrypt(uint len, char *in, uchar *key, uint *out_len)
{
	uchar expkey[4 * Nb * (Nr + 1)];
	uchar *out;
	uint i;
	uchar buff[16];
	uint outlen;
	uint hash, orig_hash;
	uint orig_len;

	if (! len % 4) return 0;
	outlen = len / 4 * 3;
	out = alloca(outlen);

	if (! base64_dec(out, in, len)) {
		return 0;
	}

	ExpandKey(key, expkey);

	for (i = 0; i < len; i += 16) {
		//Decrypt(out + i, expkey, buff);

		//memcpy(out + i, buff, 16);
	}

	orig_hash = *((uint*) out);
	orig_len = *(out + 4);
	get_hash(&hash, out + 8, orig_len);
	if (orig_hash != hash) {
		return 0;
	}

	uchar *realout = malloc(orig_len + 1);
	realout[orig_len] = 0;
	memcpy(realout, out + 8, orig_len);

	*out_len = orig_len;
	return realout;
}
