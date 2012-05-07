#include "../oscam-config.h"

#if defined(WITH_SSL) || defined(WITH_LIBCRYPTO)
#  include <openssl/aes.h>
#  include <openssl/sha.h>
#  include <openssl/bn.h>
#else
#  include "aes.h"
#  include "sha1.h"
#  include "bn.h"
#endif

#include "des.h"

#ifndef HEADER_CSCRYPT_H
#define HEADER_CSCRYPT_H

#ifdef  __cplusplus
extern "C" {
#endif

#define MD5_DIGEST_LENGTH 16
char * __md5_crypt(const char *, const char *, char *);
unsigned char *MD5(const unsigned char *, unsigned long, unsigned char *);
unsigned long crc32(unsigned long, const unsigned char *, unsigned int);

#ifdef  __cplusplus
}
#endif

#endif
