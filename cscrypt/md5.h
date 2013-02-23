#ifndef _CSCRYPT_MD5_H
#define _CSCRYPT_MD5_H

#define MD5_DIGEST_LENGTH 16

unsigned char *MD5(const unsigned char *input, unsigned long len, unsigned char *output_hash);
char * __md5_crypt(const char *text_pass, const char *salt, char *crypted_passwd);

#endif
