#ifndef MODULE_GBOX_HELPER_H_
#define MODULE_GBOX_HELPER_H_

#ifdef MODULE_GBOX
uint16_t gbox_get_caid(uint32_t caprovid);
uint32_t gbox_get_provid(uint32_t caprovid);
uint32_t gbox_get_caprovid(uint16_t caid, uint32_t prid);
uint32_t gbox_get_ecmchecksum(uchar *ecm, uint16_t ecmlen);
void gbox_encrypt(uchar *buffer, int bufsize, uint32_t key);
void gbox_decrypt(uchar *buffer, int bufsize, uint32_t localkey);
void gbox_compress(uchar *buf, int32_t unpacked_len, int32_t *packed_len);
void gbox_decompress(uchar *buf, int32_t *unpacked_len);
#endif

#endif
