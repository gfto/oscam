#ifndef HEADER_CSCRYPT_H
#define HEADER_CSCRYPT_H

#include "../oscam-config.h"
#include "../oscam-config-funcs.h"

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
#include "md5.h"

#ifdef  __cplusplus
extern "C" {
#endif

unsigned long crc32(unsigned long, const unsigned char *, unsigned int);

#ifdef  __cplusplus
}
#endif

#endif
