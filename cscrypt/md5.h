/*
 * To compute the message digest of a chunk of bytes, declare an
 * MD5Context structure, pass it to __md5_Init, call __md5_Update as
 * needed on buffers full of bytes, and then call __md5_Final, which
 * will fill a supplied 16-byte array with the digest.
 */
#ifndef _CSCRYPT_MD5_H
#define _CSCRYPT_MD5_H


#ifdef  __cplusplus
extern "C" {
#endif

#include <inttypes.h>

#define MD5_DIGEST_LENGTH 16

struct MD5Context {
	uint32_t buf[4];
	uint32_t bits[2];
	unsigned char in[64];
};

void __md5_Init(struct MD5Context *ctx);
void __md5_Update(struct MD5Context *ctx, const unsigned char *buf, unsigned int len);
void __md5_Final(unsigned char digest[MD5_DIGEST_LENGTH], struct MD5Context *ctx);

unsigned char *MD5(const unsigned char *input, unsigned long len, unsigned char *output_hash);

char * __md5_crypt(const char *text_pass, const char *salt, char *crypted_passwd);

#ifdef  __cplusplus
}
#endif

#endif
