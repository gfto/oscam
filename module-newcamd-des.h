#ifndef MODULE_NEWCAMD_DES_H_
#define MODULE_NEWCAMD_DES_H_

	int nc_des_encrypt(unsigned char *buffer, int len, unsigned char *deskey);
	int nc_des_decrypt(unsigned char *buffer, int len, unsigned char *deskey);
	unsigned char *nc_des_login_key_get(unsigned char *key1, unsigned char *key2, int len, unsigned char *des16);

#endif
