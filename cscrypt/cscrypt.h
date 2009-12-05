#ifdef HAVE_AES
#include <openssl/aes.h>
#else
#include "aes/aes.h"
#endif

#ifdef HAVE_SHA
#  include <openssl/sha.h>
#else
#  include "sha1.h"
#endif

#include "des.h"
#include "bn.h"

#ifndef HEADER_CSCRYPT_H
#define HEADER_CSCRYPT_H

#ifdef  __cplusplus
extern "C" {
#endif

#if !defined(OS_SOLARIS7) && !defined (OS_AIX42)
#include <sys/cdefs.h>
#endif

#if !defined(__P)
#define __P(a)	a
#endif

#if defined(OS_SOLARIS) || defined (OS_AIX)
#define u_int32_t unsigned long
#endif

#define MD5_DIGEST_LENGTH 16
char * __md5_crypt(const char *, const char *);
unsigned char *MD5(const unsigned char *, unsigned long, unsigned char *);
unsigned long crc32(unsigned long, const unsigned char *, unsigned int);

#ifdef  __cplusplus
}
#endif

#endif
