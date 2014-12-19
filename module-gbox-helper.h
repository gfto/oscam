#ifndef MODULE_GBOX_HELPER_H_
#define MODULE_GBOX_HELPER_H_

#ifdef MODULE_GBOX
void gbox_encrypt(uchar *buffer, int bufsize, uint32_t key);
void gbox_decrypt(uchar *buffer, int bufsize, uint32_t localkey);
void gbox_compress(uchar *buf, int32_t unpacked_len, int32_t *packed_len);
void gbox_decompress(uchar *buf, int32_t *unpacked_len);
#endif

#endif
