#ifndef CSCRYPT_DES_H_
#define CSCRYPT_DES_H_

	// sets parity for a 8-byte des key
	void des_set_odd_parity(uint8_t* key);
	
	// checks parity for a 8-byte des key
	// returns 0 if parity is not ok
	// returns 1 if parity is ok
	int8_t check_parity(const uint8_t* key);
	
	// matches the given 8-byte des key against known weak keys
	// return 0 if key is not weak
	// return 1 if key is weak
	int8_t des_is_weak_key(const uint8_t* key);

	// expands the given 8-byte des key "key" 
	// into "shedule", which must be of type "uint32_t schedule[32]"
	// always returns 0
	int8_t des_set_key(const uint8_t* key, uint32_t* schedule);

	// crypts 8 bytes of "data" with key shedule "ks"
	// encrypt = 1 -> encrypt
	// encrypt = 0 -> decrypt
	void des(uint8_t* data, const uint32_t* schedule, int8_t encrypt);

	// these functions take a 8-byte des key and crypt data of any length ("len")
	void des_ecb_encrypt(uint8_t* data, const uint8_t* key, int32_t len);
	void des_ecb_decrypt(uint8_t* data, const uint8_t* key, int32_t len);

	void des_cbc_encrypt(uint8_t* data, const uint8_t* iv, const uint8_t* key, int32_t len);
	void des_cbc_decrypt(uint8_t* data, const uint8_t* iv, const uint8_t* key, int32_t len);
	
	void des_ede2_cbc_encrypt(uint8_t* data, const uint8_t* iv, const uint8_t* key1, const uint8_t* key2, int32_t len);
	void des_ede2_cbc_decrypt(uint8_t* data, const uint8_t* iv, const uint8_t* key1, const uint8_t* key2, int32_t len);

#endif
