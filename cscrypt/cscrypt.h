#ifndef HEADER_CSCRYPT_H
#define HEADER_CSCRYPT_H

#include <sys/types.h>
#include <stdint.h>
#include <stddef.h>

#include "../config.h"

#if defined(WITH_SSL) || defined(WITH_LIBCRYPTO)
#  include <openssl/aes.h>
#  include <openssl/sha.h>
#  include <openssl/bn.h>
#else
#  include "aes.h"
#  include "sha1.h"
#  include "bn.h"
#endif

#endif
