//
// Common videoguard functions.
//
#include "globals.h"
#include "reader-common.h"
#include "reader-videoguard-common.h"

#define VG_EMMTYPE_MASK 0xC0
#define VG_EMMTYPE_G 0
#define VG_EMMTYPE_U 1
#define VG_EMMTYPE_S 2

typedef struct mailmsg_s
{
   uint16_t caid;
   uint32_t serial;
   uint16_t date;
   uint16_t id;
   uint8_t nsubs;
   uint16_t len;
   uint8_t mask;
   uint8_t written;
   char *message;
   char *subject;
} MAILMSG;

LLIST *vg_msgs = 0;

void set_known_card_info(struct s_reader * reader, const unsigned char * atr, const uint32_t *atr_size)
{
  /* Set to sensible default values */
  reader->card_baseyear = 1997;
  reader->card_tierstart = 0;
  reader->card_system_version = NDSUNKNOWN;
  reader->card_desc = "VideoGuard Unknown Card";

  NDS_ATR_ENTRY nds_atr_table[]={ // {atr}, atr len, base year, tier start, nds version, description
    /* known NDS1 atrs */
    {{ 0x3F, 0x78, 0x13, 0x25, 0x04, 0x40, 0xB0, 0x09, 0x4A, 0x50, 0x01, 0x4E, 0x5A },
       13, 1992, 0, NDS1, "VideoGuard Sky New Zealand (0969)"}, //160E
    {{ 0x3F, 0x78, 0x12, 0x25, 0x01, 0x40, 0xB0, 0x14, 0x4A, 0x50, 0x01, 0x53, 0x44 },
       13, 1997, 0, NDS1, "VideoGuard StarTV India (caid unknown)"}, //105.5E
    /* known NDS1+ atrs */
    {{ 0x3F, 0x7F, 0x13, 0x25, 0x04, 0x33, 0xB0, 0x02, 0x69, 0xFF, 0x4A, 0x50, 0xE0, 0x00, 0x00, 0x54,
       0x42, 0x00, 0x00, 0x00 },
       20, 1997, 0, NDS12, "VideoGuard China (0988)"},
    {{ 0x3F, 0x78, 0x13, 0x25, 0x03, 0x40, 0xB0, 0x20, 0xFF, 0xFF, 0x4A, 0x50, 0x00 },
       13, 1997, 0, NDS12, "VideoGuard DirecTV"},
    /* known NDS2 atrs */
    {{ 0x3F, 0xFD, 0x13, 0x25, 0x02, 0x50, 0x80, 0x0F, 0x33, 0xB0, 0x08, 0xFF, 0xFF, 0x4A, 0x50, 0x90,
       0x00, 0x00, 0x47, 0x4C, 0x01 },
       21, 2004, 0, NDS2, "VideoGuard Sky Brasil GL39 (0907)"},
    {{ 0x3F, 0x7F, 0x11, 0x25, 0x03, 0x33, 0xB0, 0x09, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00, 0x00, 0x46,
       0x44, 0x01, 0x00, 0x00 },
       20, 2000, 0, NDS2, "VideoGuard Foxtel Australia (090B)"}, //156E
    {{ 0x3F, 0xFF, 0x13, 0x25, 0x03, 0x10, 0x80, 0x33, 0xB0, 0x0E, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x49, 0x54, 0x02, 0x00, 0x00 },
       22, 1997, 0, NDS2, "VideoGuard Sky Italia (0919)"},
    {{ 0x3F, 0xFF, 0x14, 0x25, 0x03, 0x10, 0x80, 0x41, 0xB0, 0x01, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x5A, 0x4A, 0x01, 0x00, 0x00 },
       22, 2004, 0, NDS2, "VideoGuard Dolce Romania (092F)"},
    {{ 0x3F, 0xFF, 0x13, 0x25, 0x03, 0x10, 0x80, 0x54, 0xB0, 0x01, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x41, 0x55, 0x01, 0x00, 0x00 },
       22, 1997, 0, NDS2, "VideoGuard OnoCable Espana (093A)"},
    {{ 0x3F, 0xFD, 0x13, 0x25, 0x02, 0x50, 0x80, 0x0F, 0x33, 0xB0, 0x13, 0x69, 0xFF, 0x4A, 0x50, 0xD0,
       0x80, 0x00, 0x49, 0x54, 0x03 },
       21, 1997, 0, NDS2, "VideoGuard Sky Italia (093B)"},
    {{ 0x3F, 0x7D, 0x11, 0x25, 0x02, 0x41, 0xB0, 0x03, 0x69, 0xFF, 0x4A, 0x50, 0xF0, 0x80, 0x00, 0x56,
       0x54, 0x03 },
       18, 2000, 0, NDS2, "VideoGuard Viasat (093E)"},
    {{ 0x3F, 0xFF, 0x13, 0x25, 0x02, 0x40, 0xB0, 0x12, 0x69, 0xFF, 0x4A, 0x50, 0x90, 0x47, 0x4C, 0x00,
       0x00, 0x00, 0x00, 0x00 },
       20, 2000, 0, NDS2, "VideoGuard Sky Brasil GL23 (0942)"},
    {{ 0x3F, 0xFF, 0x13, 0x25, 0x02, 0x50, 0x80, 0x0F, 0x54, 0xB0, 0x03, 0xFF, 0xFF, 0x4A, 0x50, 0x80,
       0x00, 0x00, 0x00, 0x00, 0x47, 0x4C, 0x05 },
       23, 2009, 0, NDS2, "VideoGuard Sky Brasil GL54 (0943)"},
    {{ 0x3F, 0xFD, 0x13, 0x25, 0x02, 0x50, 0x00, 0x0F, 0x33, 0xB0, 0x0F, 0x69, 0xFF, 0x4A, 0x50, 0xD0,
       0x00, 0x00, 0x53, 0x59, 0x02 },
       21, 1997, 0, NDS2, "VideoGuard BSkyB (0963)"},
    {{ 0x3F, 0xFF, 0x13, 0x25, 0x03, 0x10, 0x80, 0x33, 0xB0, 0x10, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x4E, 0x5A, 0x01, 0x00, 0x00 },
       22, 1992, 0, NDS2, "VideoGuard Sky New Zealand (096A)"}, //160E
    {{ 0x3F, 0xFD, 0x11, 0x25, 0x02, 0x50, 0x80, 0x0F, 0x41, 0xB0, 0x03, 0x69, 0xFF, 0x4A, 0x50, 0xF0,
       0x80, 0x00, 0x46, 0x44, 0x03 },
       21, 2000, 0, NDS2, "VideoGuard Foxtel Australia (096C)"}, //156E
    {{ 0x3F, 0xFF, 0x11, 0x25, 0x03, 0x10, 0x80, 0x41, 0xB0, 0x06, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x41, 0x5A, 0x01, 0x00, 0x11 },
       22, 2004, 50, NDS2, "VideoGuard Astro Malaysia (09AC)"},
    {{ 0x3F, 0xFF, 0x14, 0x25, 0x03, 0x10, 0x80, 0x41, 0xB0, 0x07, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x80,
       0x00, 0x58, 0x34, 0x01, 0x00, 0x14 },
       22, 1997, 0, NDS2, "VideoGuard Cingal Philippines (09B4)"},
    {{ 0x3F, 0xFF, 0x14, 0x25, 0x03, 0x10, 0x80, 0x41, 0xB0, 0x02, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x80,
       0x00, 0x58, 0x38, 0x01, 0x00, 0x14 },
       22, 1997, 0, NDS2, "VideoGuard TopTV (09B8)"},
    {{ 0x3F, 0xFD, 0x13, 0x25, 0x02, 0x50, 0x80, 0x0F, 0x54, 0xB0, 0x04, 0x69, 0xFF, 0x4A, 0x50, 0xD0,
       0x80, 0x00, 0x49, 0x54, 0x03 },
       21, 1997, 0, NDS2, "VideoGuard Sky Italia (09CD)"},
    {{ 0x3F, 0xFF, 0x13, 0x25, 0x03, 0x10, 0x80, 0x33, 0xB0, 0x11, 0x69, 0xFF, 0x4A, 0x50, 0x50, 0x00,
       0x00, 0x47, 0x54, 0x01, 0x00, 0x00 },
       22, 1997, 0, NDS2, "VideoGuard YES DBS Israel"},
    {{ 0x3F, 0x7F, 0x11, 0x25, 0x03, 0x33, 0xB0, 0x09, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00, 0x00, 0x56,
       0x54, 0x01, 0x00, 0x00 },
       20, 2000, 0, NDS2, "VideoGuard Viasat Scandinavia"},
    {{ 0x3F, 0xFF, 0x11, 0x25, 0x03, 0x10, 0x80, 0x41, 0xB0, 0x07, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x50, 0x31, 0x01, 0x00, 0x11 },
       22, 2004, 0, NDS2, "VideoGuard Sky Germany"},
    {{ 0x3F, 0xFF, 0x14, 0x25, 0x03, 0x10, 0x80, 0x41, 0xB0, 0x01, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x5A, 0x48, 0x01, 0x00, 0x00 },
       22, 2004, 0, NDS2, "VideoGuard DSMART Turkey"},
    {{ 0x3F, 0xFF, 0x14, 0x25, 0x03, 0x10, 0x80, 0x54, 0xB0, 0x01, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x4B, 0x57, 0x01, 0x00, 0x00 },
       22, 2004, 0, NDS2, "VideoGuard Kabel BW (098E)"},
    {{ 0x3F, 0xFF, 0x14, 0x25, 0x03, 0x10, 0x80, 0x33, 0xB0, 0x10, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x5A, 0x43, 0x01, 0x00, 0x00 },
       22, 2004, 0, NDS2, "VideoGuard totalTV Serbia (091F)"},
    {{ 0x3F, 0xFF, 0x14, 0x25, 0x03, 0x10, 0x80, 0x33, 0xB0, 0x10, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x5A, 0x45, 0x01, 0x00, 0x00 },
       22, 2004, 0, NDS2, "VideoGuard Get Kabel Norway"},
    {{ 0x3F, 0xFF, 0x14, 0x25, 0x03, 0x10, 0x80, 0x41, 0xB0, 0x07, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x80,
       0x00, 0x58, 0x36, 0x01, 0x00, 0x14 },
       22, 2004, 0, NDS2, "VideoGuard Teleclub (09B6)"},
    {{ 0x3F, 0xFD, 0x11, 0x25, 0x02, 0x50, 0x00, 0x03, 0x33, 0xB0, 0x15, 0x69, 0xFF, 0x4A, 0x50, 0xF0,
       0x80, 0x03, 0x4B, 0x4C, 0x03 },
       21, 2004, 0, NDS2, "VideoGuard Kabel Deutschland (09C7)"},
    {{ 0x3F, 0x7D, 0x13, 0x25, 0x02, 0x41, 0xB0, 0x03, 0x69, 0xFF, 0x4A, 0x50, 0xF0, 0x80, 0x00, 0x54,
       0x37, 0x03 },
       18, 2004, 0, NDS2, "VideoGuard Telecolumbus (09AF)"},
    // NDS Version Unknown as Yet
    {{ 0x3F, 0x7F, 0x13, 0x25, 0x02, 0x40, 0xB0, 0x12, 0x69, 0xFF, 0x4A, 0x50, 0x90, 0x41, 0x55, 0x00,
       0x00, 0x00, 0x00, 0x00 },
       20, 1997, 0, NDSUNKNOWN, "VideoGuard OnoCable Espana (0915)"},
    {{ 0x3F, 0xFF, 0x14, 0x25, 0x03, 0x10, 0x80, 0x41, 0xB0, 0x07, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x80,
       0x00, 0x58, 0x44, 0x01, 0x00, 0x14 },
       22, 1997, 0, NDSUNKNOWN, "VideoGuard Sky Vivacom (09BD)"}, //45E
    {{ 0x3F, 0x7F, 0x13, 0x25, 0x05, 0x40, 0xB0, 0x11, 0x69, 0xFF, 0x4A, 0x50, 0x00, 0x00, 0x00, 0x48,
       0x4B, 0x00, 0x01, 0x00 },
       20, 1997, 0, NDSUNKNOWN, "VideoGuard StarTV India (caid unknown)"}, //105.5E
    {{ 0 }, 0, 0, 0, 0, NULL}
  };

  int32_t i=0;
  while(nds_atr_table[i].desc) {
    if ((*atr_size == nds_atr_table[i].atr_len)
          && (memcmp (atr, nds_atr_table[i].atr, nds_atr_table[i].atr_len) == 0)) {
        reader->card_baseyear=nds_atr_table[i].base_year;
        reader->card_tierstart=nds_atr_table[i].tier_start;
        reader->card_system_version = nds_atr_table[i].nds_version;
        reader->card_desc = nds_atr_table[i].desc;
        break;
    }
    i++;
  }
}

static void cCamCryptVG_LongMult(uint16_t *pData, uint16_t *pLen, uint32_t mult, uint32_t carry);
static void cCamCryptVG_PartialMod(uint16_t val, uint32_t count, uint16_t *outkey, const uint16_t *inkey);
static void cCamCryptVG_RotateRightAndHash(unsigned char *p);
static void cCamCryptVG_Reorder16A(unsigned char *dest, const unsigned char *src);
static void cCamCryptVG_ReorderAndEncrypt(struct s_reader * reader, unsigned char *p);
static void cCamCryptVG_Process_D0(struct s_reader * reader, const unsigned char *ins, unsigned char *data);
static void cCamCryptVG_Process_D1(struct s_reader * reader, const unsigned char *ins, unsigned char *data, const unsigned char *status);
static void cCamCryptVG_Decrypt_D3(struct s_reader * reader, unsigned char *ins, unsigned char *data, const unsigned char *status);
static void cCamCryptVG_PostProcess_Decrypt(struct s_reader * reader, unsigned char *rxbuff);
static int32_t cAES_Encrypt(struct s_reader * reader, const unsigned char *data, int32_t len, unsigned char *crypt);
static void swap_lb (const unsigned char *buff, int32_t len);

int32_t cw_is_valid(unsigned char *cw, int32_t start)	//returns 1 if cw_is_valid, returns 0 if cw is all zeros
{
  int32_t i;
  for (i = start; i < start+8; i++)
    if (cw[i] != 0) {		//test if cw = 00
      return OK;
    }
  return ERROR;
}

void cAES_SetKey(struct s_reader * reader, const unsigned char *key)
{
  AES_set_encrypt_key(key,128,&(reader->ekey));
}

int32_t cAES_Encrypt(struct s_reader * reader, const unsigned char *data, int32_t len, unsigned char *crypt)
{
    len=(len+15)&(~15); // pad up to a multiple of 16
    int32_t i;
    for(i=0; i<len; i+=16) AES_encrypt(data+i,crypt+i,&(reader->ekey));
    return len;
}

static void swap_lb (const unsigned char *buff, int32_t len)
{

#if __BYTE_ORDER != __BIG_ENDIAN
  return;

#endif /*  */
  int32_t i;
  uint16_t *tmp;
  for (i = 0; i < len / 2; i++) {
    tmp = (uint16_t *) buff + i;
    *tmp = ((*tmp << 8) & 0xff00) | ((*tmp >> 8) & 0x00ff);
  }
}

inline void __xxor(unsigned char *data, int32_t len, const unsigned char *v1, const unsigned char *v2)
{
  uint32_t i;
  switch(len) { // looks ugly but the cpu don't crash!
    case 16:
      for(i = 8; i < 16; ++i ) {
        data[i] = v1[i] ^ v2[i];
      }
    case 8:
      for(i = 4; i < 8; ++i) {
        data[i] = v1[i] ^ v2[i];
      }
    case 4:
      for(i = 0; i < 4; ++i ) {
        data[i] = v1[i] ^ v2[i];
      }
      break;
    default:
      while(len--) *data++ = *v1++ ^ *v2++;
      break;
    }
}


void cCamCryptVG_SetSeed(struct s_reader * reader)
{
#if __BYTE_ORDER != __BIG_ENDIAN
  static const unsigned char key1[] = {
    0xb9, 0xd5, 0xef, 0xd5, 0xf5, 0xd5, 0xfb, 0xd5, 0x31, 0xd6, 0x43, 0xd6, 0x55, 0xd6, 0x61, 0xd6,
    0x85, 0xd6, 0x9d, 0xd6, 0xaf, 0xd6, 0xc7, 0xd6, 0xd9, 0xd6, 0x09, 0xd7, 0x15, 0xd7, 0x21, 0xd7,
    0x27, 0xd7, 0x3f, 0xd7, 0x45, 0xd7, 0xb1, 0xd7, 0xbd, 0xd7, 0xdb, 0xd7, 0x11, 0xd8, 0x23, 0xd8,
    0x29, 0xd8, 0x2f, 0xd8, 0x4d, 0xd8, 0x8f, 0xd8, 0xa1, 0xd8, 0xad, 0xd8, 0xbf, 0xd8, 0xd7, 0xd8
    };
  static const unsigned char key2[] = {
    0x01, 0x00, 0xcf, 0x13, 0xe0, 0x60, 0x54, 0xac, 0xab, 0x99, 0xe6, 0x0c, 0x9f, 0x5b, 0x91, 0xb9,
    0x72, 0x72, 0x4d, 0x5b, 0x5f, 0xd3, 0xb7, 0x5b, 0x01, 0x4d, 0xef, 0x9e, 0x6b, 0x8a, 0xb9, 0xd1,
    0xc9, 0x9f, 0xa1, 0x2a, 0x8d, 0x86, 0xb6, 0xd6, 0x39, 0xb4, 0x64, 0x65, 0x13, 0x77, 0xa1, 0x0a,
    0x0c, 0xcf, 0xb4, 0x2b, 0x3a, 0x2f, 0xd2, 0x09, 0x92, 0x15, 0x40, 0x47, 0x66, 0x5c, 0xda, 0xc9
    };
#else
  static const unsigned char key1[] = {
    0xd5, 0xb9, 0xd5, 0xef, 0xd5, 0xf5, 0xd5, 0xfb, 0xd6, 0x31, 0xd6, 0x43, 0xd6, 0x55, 0xd6, 0x61,
    0xd6, 0x85, 0xd6, 0x9d, 0xd6, 0xaf, 0xd6, 0xc7, 0xd6, 0xd9, 0xd7, 0x09, 0xd7, 0x15, 0xd7, 0x21,
    0xd7, 0x27, 0xd7, 0x3f, 0xd7, 0x45, 0xd7, 0xb1, 0xd7, 0xbd, 0xd7, 0xdb, 0xd8, 0x11, 0xd8, 0x23,
    0xd8, 0x29, 0xd8, 0x2f, 0xd8, 0x4d, 0xd8, 0x8f, 0xd8, 0xa1, 0xd8, 0xad, 0xd8, 0xbf, 0xd8, 0xd7
    };
  static const unsigned char key2[] = {
    0x00, 0x01, 0x13, 0xcf, 0x60, 0xe0, 0xac, 0x54, 0x99, 0xab, 0x0c, 0xe6, 0x5b, 0x9f, 0xb9, 0x91,
    0x72, 0x72, 0x5b, 0x4d, 0xd3, 0x5f, 0x5b, 0xb7, 0x4d, 0x01, 0x9e, 0xef, 0x8a, 0x6b, 0xd1, 0xb9,
    0x9f, 0xc9, 0x2a, 0xa1, 0x86, 0x8d, 0xd6, 0xb6, 0xb4, 0x39, 0x65, 0x64, 0x77, 0x13, 0x0a, 0xa1,
    0xcf, 0x0c, 0x2b, 0xb4, 0x2f, 0x3a, 0x09, 0xd2, 0x15, 0x92, 0x47, 0x40, 0x5c, 0x66, 0xc9, 0xda
  };
#endif
  memcpy(reader->cardkeys[1],key1,sizeof(reader->cardkeys[1]));
  memcpy(reader->cardkeys[2],key2,sizeof(reader->cardkeys[2]));
}

void cCamCryptVG_GetCamKey(struct s_reader * reader, unsigned char *buff)
{
  uint16_t *tb2=(uint16_t *)buff, c=1;
  memset(tb2,0,64);
  tb2[0]=1;
  int32_t i;
  for(i=0; i<32; i++) cCamCryptVG_LongMult(tb2,&c,reader->cardkeys[1][i],0);
  swap_lb (buff, 64);
}

static void cCamCryptVG_PostProcess_Decrypt(struct s_reader * reader, unsigned char *rxbuff)
{
  switch(rxbuff[0]) {
    case 0xD0:
      cCamCryptVG_Process_D0(reader,rxbuff,rxbuff+5);
      break;
    case 0xD1:
      cCamCryptVG_Process_D1(reader,rxbuff,rxbuff+5,rxbuff+rxbuff[4]+5);
      break;
    case 0xD3:
      cCamCryptVG_Decrypt_D3(reader,rxbuff,rxbuff+5,rxbuff+rxbuff[4]+5);
      break;
  }
}

static void cCamCryptVG_Process_D0(struct s_reader * reader, const unsigned char *ins, unsigned char *data)
{
  switch(ins[1]) {
    case 0xb4:
      swap_lb (data, 64);
      memcpy(reader->cardkeys[0],data,sizeof(reader->cardkeys[0]));
      break;
    case 0xbc:
    {
      swap_lb (data, 64);
      const uint16_t *key1=(const uint16_t *)reader->cardkeys[1];
      uint16_t key2[32];
      memcpy(key2,reader->cardkeys[2],sizeof(key2));
      int32_t count2;
      uint16_t iidata[32];
      for(count2=0; count2<32; count2++) {
        uint32_t rem=0, div=key1[count2];
        int32_t i;
        memcpy( (unsigned char*)&iidata, data, 64 );
        for(i=31; i>=0; i--) {
          uint32_t x=iidata[i] | (rem<<16);
          rem=(x%div)&0xffff;
          }
        uint32_t carry=1, t=val_by2on3(div) | 1;
        while(t) {
          if(t&1) carry=((carry*rem)%div)&0xffff;
          rem=((rem*rem)%div)&0xffff;
          t>>=1;
          }
        cCamCryptVG_PartialMod(carry,count2,key2,key1);
        }
      uint16_t idatacount=0;
      int32_t i;
      for(i=31; i>=0; i--) cCamCryptVG_LongMult(iidata,&idatacount,key1[i],key2[i]);
      memcpy( data, iidata, 64 );
      swap_lb (data, 64);
      unsigned char stateD1[16];
      cCamCryptVG_Reorder16A(stateD1,data);
      cAES_SetKey(reader,stateD1);
      break;
    }
  }
}

static void cCamCryptVG_Process_D1(struct s_reader * reader, const unsigned char *ins, unsigned char *data, const unsigned char *status)
{
  unsigned char iter[16], tmp[16];
  memset(iter,0,sizeof(iter));
  memcpy(iter,ins,5);
  xor16(iter,reader->stateD3A,iter);
  memcpy(reader->stateD3A,iter,sizeof(iter));

  int32_t datalen=status-data;
  int32_t datalen1=datalen;
  if(datalen<0) datalen1+=15;
  int32_t blocklen=datalen1>>4;
  int32_t i;
  int32_t iblock;
  for(i=0,iblock=0; i<blocklen+2; i++,iblock+=16) {
    unsigned char in[16];
    int32_t docalc=1;
    if(blocklen==i && (docalc=datalen&0xf)) {
      memset(in,0,sizeof(in));
      memcpy(in,&data[iblock],datalen-(datalen1&~0xf));
      }
    else if(blocklen+1==i) {
      memset(in,0,sizeof(in));
      memcpy(&in[5],status,2);
      }
    else
      memcpy(in,&data[iblock],sizeof(in));

    if(docalc) {
      xor16(iter,in,tmp);
      cCamCryptVG_ReorderAndEncrypt(reader,tmp);
      xor16(tmp,reader->stateD3A,iter);
      }
    }
  memcpy(reader->stateD3A,tmp,16);
}

static void cCamCryptVG_Decrypt_D3(struct s_reader * reader, unsigned char *ins, unsigned char *data, const unsigned char *status)
{
  if(ins[4]>16) ins[4]-=16;
  if(ins[1]==0xbe) memset(reader->stateD3A,0,sizeof(reader->stateD3A));

  unsigned char tmp[16];
  memset(tmp,0,sizeof(tmp));
  memcpy(tmp,ins,5);
  xor16(tmp,reader->stateD3A,reader->stateD3A);

  int32_t len1=ins[4];
  int32_t blocklen=len1>>4;
  if(ins[1]!=0xbe) blocklen++;

  unsigned char iter[16], states[16][16];
  memset(iter,0,sizeof(iter));
  int32_t blockindex;
  for(blockindex=0; blockindex<blocklen; blockindex++) {
    iter[0]+=blockindex;
    xor16(iter,reader->stateD3A,iter);
    cCamCryptVG_ReorderAndEncrypt(reader,iter);
    xor16(iter,&data[blockindex*16],states[blockindex]);
    if(blockindex==(len1>>4)) {
      int32_t c=len1-(blockindex*16);
      if(c<16) memset(&states[blockindex][c],0,16-c);
      }
    xor16(states[blockindex],reader->stateD3A,reader->stateD3A);
    cCamCryptVG_RotateRightAndHash(reader->stateD3A);
    }
  memset(tmp,0,sizeof(tmp));
  memcpy(tmp+5,status,2);
  xor16(tmp,reader->stateD3A,reader->stateD3A);
  cCamCryptVG_ReorderAndEncrypt(reader,reader->stateD3A);

  memcpy(reader->stateD3A,status-16,sizeof(reader->stateD3A));
  cCamCryptVG_ReorderAndEncrypt(reader,reader->stateD3A);

  memcpy(data,states[0],len1);
  if(ins[1]==0xbe) {
    cCamCryptVG_Reorder16A(tmp,states[0]);
    cAES_SetKey(reader,tmp);
    }
}

static void cCamCryptVG_ReorderAndEncrypt(struct s_reader * reader, unsigned char *p)
{
  unsigned char tmp[16];
  cCamCryptVG_Reorder16A(tmp,p);
  cAES_Encrypt(reader,tmp,16,tmp);
  cCamCryptVG_Reorder16A(p,tmp);
}

// reorder AAAABBBBCCCCDDDD to ABCDABCDABCDABCD
static void cCamCryptVG_Reorder16A(unsigned char *dest, const unsigned char *src)
{
  int32_t i;
  int32_t j;
  int32_t k;
  for(i=0,k=0; i<4; i++)
    for(j=i; j<16; j+=4,k++)
      dest[k]=src[j];
}

static void cCamCryptVG_LongMult(uint16_t *pData, uint16_t *pLen, uint32_t mult, uint32_t carry)
{
  int32_t i;
  for(i=0; i<*pLen; i++) {
    carry+=pData[i]*mult;
    pData[i]=(uint16_t)carry;
    carry>>=16;
    }
  if(carry) pData[(*pLen)++]=carry;
}

static void cCamCryptVG_PartialMod(uint16_t val, uint32_t count, uint16_t *outkey, const uint16_t *inkey)
{
  if(count) {
    uint32_t mod=inkey[count];
    uint16_t mult=(inkey[count]-outkey[count-1])&0xffff;
    uint32_t i;
    uint32_t ib1;
    for(i=0,ib1=count-2; i<count-1; i++,ib1--) {
      uint32_t t=(inkey[ib1]*mult)%mod;
      mult=t-outkey[ib1];
      if(mult>t) mult+=mod;
      }
    mult+=val;
    if((val>mult) || (mod<mult)) mult-=mod;
    outkey[count]=(outkey[count]*mult)%mod;
    }
  else
    outkey[0]=val;
}

static void cCamCryptVG_RotateRightAndHash(unsigned char *p)
{
  static const unsigned char table1[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5, 0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0, 0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc, 0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a, 0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0, 0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b, 0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85, 0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5, 0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17, 0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88, 0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c, 0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9, 0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6, 0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e, 0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94, 0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68, 0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
    };
  unsigned char t1=p[15];
  int32_t i;
  for(i=0; i<16; i++) {
    unsigned char t2=t1;
    t1=p[i]; p[i]=table1[(t1>>1)|((t2&1)<<7)];
    }
}

int32_t status_ok(const unsigned char *status)
{
    //cs_log("[videoguard-reader] check status %02x%02x", status[0],status[1]);
    return (status[0] == 0x90 || status[0] == 0x91)
           && (status[1] == 0x00 || status[1] == 0x01
               || status[1] == 0x20 || status[1] == 0x21
               || status[1] == 0x80 || status[1] == 0x81
               || status[1] == 0xa0 || status[1] == 0xa1);
}

void memorize_cmd_table (struct s_reader * reader, const unsigned char *mem, int32_t size){
  if(cs_malloc(&reader->cmd_table,sizeof(unsigned char) * size, -1))
  	memcpy(reader->cmd_table,mem,size);
}

int32_t cmd_table_get_info(struct s_reader * reader, const unsigned char *cmd, unsigned char *rlen, unsigned char *rmode)
{
  struct s_CmdTabEntry *pcte=reader->cmd_table->e;
  int32_t i;
  for(i=0; i< reader->cmd_table->Nentries; i++,pcte++)
    if(cmd[1]==pcte->cmd) {
      *rlen=pcte->len;
      *rmode=pcte->mode;
      return 1;
      }
  return 0;
}

int32_t cmd_exists(struct s_reader * reader, const unsigned char *cmd)
{
  struct s_CmdTabEntry *pcte=reader->cmd_table->e;
  int32_t i;
  for(i=0; i< reader->cmd_table->Nentries; i++,pcte++)
    if(cmd[1]==pcte->cmd) {
      return 1;
      }
  return 0;
}

int32_t read_cmd_len(struct s_reader * reader, const unsigned char *cmd)
{
  def_resp;
  unsigned char cmd2[5];
  memcpy(cmd2,cmd,5);
  cmd2[3]=0x80;
  cmd2[4]=1;
  // some card reply with L 91 00 (L being the command length).

  if(!write_cmd_vg(cmd2,NULL) || !status_ok(cta_res+1)) {
    cs_debug_mask(D_READER, "[videoguard-reader] failed to read %02x%02x cmd length (%02x %02x)",cmd[1],cmd[2],cta_res[1],cta_res[2]);
    return -1;
  }
  return cta_res[0];
}

int32_t do_cmd(struct s_reader * reader, const unsigned char *ins, const unsigned char *txbuff, unsigned char *rxbuff,
           unsigned char * cta_res)
{
  uint16_t cta_lr;
  unsigned char ins2[5];
  memcpy(ins2,ins,5);
  unsigned char len=0, mode=0;
  if(cmd_table_get_info(reader,ins2,&len,&mode)) {
    if(len==0xFF && mode==2) {
      if(ins2[4]==0) ins2[4]=len=read_cmd_len(reader,ins2);
      }
    else if(mode!=0) ins2[4]=len;
    }
  if(ins2[0]==0xd3) ins2[4]=len+16;
  len=ins2[4];
    unsigned char tmp[264];  
  	if(rxbuff == NULL) rxbuff=tmp;
  if(mode>1) {
    if(!write_cmd_vg(ins2,NULL) || !status_ok(cta_res+len)) return -1;
    memcpy(rxbuff,ins2,5);
    memcpy(rxbuff+5,cta_res,len);
    memcpy(rxbuff+5+len,cta_res+len,2);
    }
  else {
    if(!write_cmd_vg(ins2,txbuff) || !status_ok(cta_res)) return -2;
    memcpy(rxbuff,ins2,5);
    memcpy(rxbuff+5,txbuff,len);
    memcpy(rxbuff+5+len,cta_res,2);
    }
cCamCryptVG_PostProcess_Decrypt(reader,rxbuff);
  return len;
  
}

void rev_date_calc(const unsigned char *Date, int32_t *year, int32_t *mon, int32_t *day, int32_t *hh, int32_t *mm, int32_t *ss, int32_t base_year)
{
  *year=(Date[0]/12)+base_year;
  *mon=(Date[0]%12)+1;
  *day=Date[1] & 0x1f;
  *hh=Date[2]/8;
  *mm=(0x100*(Date[2]-*hh*8)+Date[3])/32;
  *ss=(Date[3]-*mm*32)*2;
}

void rev_date_calc_tm(const unsigned char *Date, struct tm *timeinfo , int32_t base_year)
{
	memset(&timeinfo, 0, sizeof(timeinfo));
	timeinfo->tm_year = (Date[0]/12) + base_year;
	timeinfo->tm_mon = (Date[0]%12) + 1;
	timeinfo->tm_mday = Date[1] & 0x1f;
	timeinfo->tm_hour = Date[2] / 8;
	timeinfo->tm_min = (0x100 * (Date[2] - timeinfo->tm_hour * 8) + Date[3]) / 32;
	timeinfo->tm_sec = (Date[3] - timeinfo->tm_min * 32) * 2;
}

void do_post_dw_hash(unsigned char *cw, unsigned char *ecm_header_data)
{
  int32_t i, ecmi, ecm_header_count;
  unsigned char buffer[0x80];
  unsigned char md5tmp[MD5_DIGEST_LENGTH];
  static const uint16_t Hash3[] = {0x0123,0x4567,0x89AB,0xCDEF,0xF861,0xCB52};
  static const unsigned char Hash4[] = {0x0B,0x04,0x07,0x08,0x05,0x09,0x0B,0x0A,0x07,0x02,0x0A,0x05,0x04,0x08,0x0D,0x0F};
  static const uint16_t NdTabB001[0x15][0x20] = {
    {0xEAF1, 0x0237, 0x29D0, 0xBAD2, 0xE9D3, 0x8BAE, 0x2D6D, 0xCD1B,
     0x538D, 0xDE6B, 0xA634, 0xF81A, 0x18B5, 0x5087, 0x14EA, 0x672E,
     0xF0FC, 0x055E, 0x62E5, 0xB78F, 0x5D09, 0x0003, 0xE4E8, 0x2DCE,
     0x6BE0, 0xAC4E, 0xF485, 0x6967, 0xF28C, 0x97A0, 0x01EF, 0x0100},
    {0xC539, 0xF5B9, 0x9099, 0x013A, 0xD4B9, 0x6AB5, 0xEA67, 0x7EB4,
     0x6C30, 0x4BF0, 0xB810, 0xB0B5, 0xB76D, 0xA751, 0x1AE7, 0x14CA,
     0x4F4F, 0x1586, 0x2608, 0x10B1, 0xE7E1, 0x48BE, 0x7DDD, 0x5ECB,
     0xCFBF, 0x323B, 0x8B31, 0xB131, 0x0F1A, 0x664B, 0x0140, 0x0100},
    {0x3C7D, 0xBDC4, 0xFEC7, 0x26A6, 0xB0A0, 0x6E55, 0xF710, 0xF9BF,
     0x0023, 0xE81F, 0x41CA, 0xBE32, 0xB461, 0xE92D, 0xF1AF, 0x409F,
     0xFC85, 0xFE5B, 0x7FCE, 0x17F5, 0x01AB, 0x4A46, 0xEB05, 0xA251,
     0xDC6F, 0xF0C0, 0x10F0, 0x1D51, 0xEFAA, 0xE9BF, 0x0100, 0x0100},
    {0x1819, 0x0CAA, 0x9067, 0x607A, 0x7576, 0x1CBC, 0xE51D, 0xBF77,
     0x7EC6, 0x839E, 0xB695, 0xF096, 0xDC10, 0xCB69, 0x4654, 0x8E68,
     0xD62D, 0x4F1A, 0x4227, 0x92AC, 0x9064, 0x6BD1, 0x1E75, 0x2747,
     0x00DA, 0xA6A6, 0x6CF1, 0xD151, 0xBE56, 0x3E33, 0x0128, 0x0100},
    {0x4091, 0x09ED, 0xD494, 0x6054, 0x1869, 0x71D5, 0xB572, 0x7BF1,
     0xE925, 0xEE2D, 0xEEDE, 0xA13C, 0x6613, 0x9BAB, 0x122D, 0x7AE4,
     0x5268, 0xE6C9, 0x50CB, 0x79A1, 0xF212, 0xA062, 0x6B48, 0x70B3,
     0xF6B0, 0x06D5, 0xF8AB, 0xECF5, 0x6255, 0xEDD8, 0x79D2, 0x290A},
    {0xD3CF, 0x014E, 0xACB3, 0x8F6B, 0x0F2C, 0xA5D8, 0xE8E0, 0x863D,
     0x80D5, 0x5705, 0x658A, 0x8BC2, 0xEE46, 0xD3AE, 0x0199, 0x0100,
     0x4A35, 0xABE4, 0xF976, 0x935A, 0xA8A5, 0xBAE9, 0x24D0, 0x71AA,
     0xB3FE, 0x095E, 0xAB06, 0x4CD5, 0x2F0D, 0x1ACB, 0x59F3, 0x4C50},
    {0xFD27, 0x0F8E, 0x191A, 0xEEE7, 0x2F49, 0x3A05, 0x3267, 0x4F88,
     0x38AE, 0xFCE9, 0x9476, 0x18C6, 0xF961, 0x4EF0, 0x39D0, 0x42E6,
     0xB747, 0xE625, 0xB68E, 0x5100, 0xF92A, 0x86FE, 0xE79B, 0xEE91,
     0x21D5, 0x4C3C, 0x683D, 0x5AD1, 0x1B49, 0xF407, 0x0194, 0x0100},
    {0x4BF9, 0xDC0D, 0x9478, 0x5174, 0xCB4A, 0x8A89, 0x4D6A, 0xFED8,
     0xF123, 0xA8CD, 0xEEE7, 0xA6D1, 0xB763, 0xF5E2, 0xE085, 0x01EF,
     0xE466, 0x9FA3, 0x2F68, 0x2190, 0x423F, 0x287F, 0x7F3F, 0x09F6,
     0x2111, 0xA963, 0xD0BB, 0x674A, 0xBA72, 0x45F9, 0xF186, 0xB8F5},
    {0x0010, 0xD1B9, 0xB164, 0x9E87, 0x1F49, 0x6950, 0x2DBF, 0x38D3,
     0x2EB0, 0x3E8E, 0x91E6, 0xF688, 0x7E41, 0x566E, 0x01B0, 0x0100,
     0x24A1, 0x73D8, 0xA0C3, 0xF71B, 0xA0A5, 0x2A06, 0xBA46, 0xFEC3,
     0xDD4C, 0x52CC, 0xF9BC, 0x3B7E, 0x3812, 0x0666, 0xB74B, 0x40F8},
    {0x28F2, 0x7C81, 0xFC92, 0x6FBD, 0x53D6, 0x72A3, 0xBBDF, 0xB6FC,
     0x9CE5, 0x2331, 0xD4F6, 0xC5BB, 0xE8BB, 0x6676, 0x02D9, 0x2F0E,
     0xD009, 0xD136, 0xCD09, 0x7551, 0x1826, 0x9D9B, 0x63EA, 0xFC63,
     0x68CD, 0x3672, 0xCB95, 0xD28E, 0xF1CD, 0x20CA, 0x014C, 0x0100},
    {0xE539, 0x55B7, 0x989D, 0x21C4, 0x463A, 0xE68F, 0xF8B5, 0xE5C5,
     0x662B, 0x35BF, 0x3C50, 0x0131, 0xF4BF, 0x38B2, 0x41BC, 0xB829,
     0x02B7, 0x6B8F, 0xA25C, 0xAFD2, 0xD84A, 0x2243, 0x53EB, 0xC6C9,
     0x2E14, 0x181F, 0x8F96, 0xDF0E, 0x0D4C, 0x30F6, 0xFFE1, 0x9DDA},
    {0x30B6, 0x777E, 0xDA3D, 0xAF77, 0x205E, 0xC90B, 0x856B, 0xB451,
     0x3BCC, 0x76C2, 0x8ACF, 0xDCB1, 0xA5E5, 0xDD64, 0x0197, 0x0100,
     0xE751, 0xB661, 0x0404, 0xDB4A, 0xE9DD, 0xA400, 0xAF26, 0x3F5E,
     0x904B, 0xA924, 0x09E0, 0xE72B, 0x825B, 0x2C50, 0x6FD0, 0x0D52},
    {0x2730, 0xC2BA, 0x9E44, 0x5815, 0xFC47, 0xB21D, 0x67B8, 0xF8B9,
     0x047D, 0xB0AF, 0x9F14, 0x741B, 0x4668, 0xBE54, 0xDE16, 0xDB14,
     0x7CB7, 0xF2B8, 0x0683, 0x762C, 0x09A0, 0x9507, 0x7F92, 0x022C,
     0xBA6A, 0x7D52, 0x0AF4, 0x1BC3, 0xB46A, 0xC4FD, 0x01C2, 0x0100},
    {0x7611, 0x66F3, 0xEE87, 0xEDD3, 0xC559, 0xEFD4, 0xDC59, 0xF86B,
     0x6D1C, 0x1C85, 0x9BB1, 0x3373, 0x763F, 0x4EBE, 0x1BF3, 0x99B5,
     0xD721, 0x978F, 0xCF5C, 0xAC51, 0x0984, 0x7462, 0x8F0C, 0x2817,
     0x4AD9, 0xFD41, 0x6678, 0x7C85, 0xD330, 0xC9F8, 0x1D9A, 0xC622},
    {0x5AE4, 0xE16A, 0x60F6, 0xFD45, 0x668C, 0x29D6, 0x0285, 0x6B92,
     0x92C2, 0x21DE, 0x45E0, 0xEF3D, 0x8B0D, 0x02CD, 0x0198, 0x0100,
     0x9E6D, 0x4D38, 0xDEF9, 0xE6F2, 0xF72E, 0xB313, 0x14F2, 0x390A,
     0x2D67, 0xC71E, 0xCB69, 0x7F66, 0xD3CF, 0x7F8A, 0x81D9, 0x9DDE},
    {0x85E3, 0x8F29, 0x36EB, 0xC968, 0x3696, 0x59F6, 0x7832, 0xA78B,
     0xA1D8, 0xF5CF, 0xAB64, 0x646D, 0x7A2A, 0xBAF8, 0xAA87, 0x41C7,
     0x5120, 0xDE78, 0x738D, 0xDC1A, 0x268D, 0x5DF8, 0xED69, 0x1C8A,
     0xBC85, 0x3DCD, 0xAE30, 0x0F8D, 0xEC89, 0x3ABD, 0x0166, 0x0100},
    {0xB8BD, 0x643B, 0x748E, 0xBD63, 0xEC6F, 0xE23A, 0x9493, 0xDD76,
     0x0A62, 0x774F, 0xCD68, 0xA67A, 0x9A23, 0xC8A8, 0xBDE5, 0x9D1B,
     0x2B86, 0x8B36, 0x5428, 0x1DFB, 0xCD1D, 0x0713, 0x29C2, 0x8E8E,
     0x5207, 0xA13F, 0x6005, 0x4F5E, 0x52E0, 0xE7C8, 0x6D1C, 0x3E34},
    {0x581D, 0x2BFA, 0x5E1D, 0xA891, 0x1069, 0x1DA4, 0x39A0, 0xBE45,
     0x5B9A, 0x7333, 0x6F3E, 0x8637, 0xA550, 0xC9E9, 0x5C6C, 0x42BA,
     0xA712, 0xC3EA, 0x3808, 0x0910, 0xAA4D, 0x5B25, 0xABCD, 0xE680,
     0x96AD, 0x2CEC, 0x8EBB, 0xA47D, 0x1690, 0xE8FB, 0x01C8, 0x0100},
    {0x73B9, 0x82BC, 0x9EBC, 0xB130, 0x0DA5, 0x8617, 0x9F7B, 0x9766,
     0x205D, 0x752D, 0xB05C, 0x2A17, 0xA75C, 0x18EF, 0x8339, 0xFD34,
     0x8DA2, 0x7970, 0xD0B4, 0x70F1, 0x3765, 0x7380, 0x7CAF, 0x570E,
     0x6440, 0xBC44, 0x0743, 0x2D02, 0x0419, 0xA240, 0x2113, 0x1AD4},
    {0x1EB5, 0xBBFF, 0x39B1, 0x3209, 0x705F, 0x15F4, 0xD7AD, 0x340B,
     0xC2A6, 0x25CA, 0xF412, 0x9570, 0x0F4F, 0xE4D5, 0x1614, 0xE464,
     0x911A, 0x0F0E, 0x07DA, 0xA929, 0x2379, 0xD988, 0x0AA6, 0x3B57,
     0xBF63, 0x71FB, 0x72D5, 0x26CE, 0xB0AF, 0xCF45, 0x011B, 0x0100},
    {0x9999, 0x98FE, 0xA108, 0x6588, 0xF90B, 0x4554, 0xFF38, 0x4642,
     0x8F5F, 0x6CC3, 0x4E8E, 0xFF7E, 0x64C2, 0x50CA, 0x0E7F, 0xAD7D,
     0x6AAB, 0x33C1, 0xE1F4, 0x6165, 0x7894, 0x83B9, 0x0A0C, 0x38AF,
     0x5803, 0x18C0, 0xFA36, 0x592C, 0x4548, 0xABB8, 0x1527, 0xAEE9}
  };


  //ecm_header_data = 01 03 b0 01 01
  if (!cw_is_valid(cw,0))         //if cw is all zero, keep it that way
  {
    return;
  }
  ecm_header_count = ecm_header_data[0];
  for (i = 0, ecmi = 1; i < ecm_header_count; i++)
  {
    if (ecm_header_data[ecmi + 1] != 0xb0)
    {
      ecmi += ecm_header_data[ecmi] + 1;
    }
    else
    {
      switch (ecm_header_data[ecmi + 2])
      {                         //b0 01
      case 1:
        {
          uint16_t hk[8], i, j, m = 0;
          for (i = 0; i < 6; i++)
            hk[2 + i] = Hash3[i];
          for (i = 0; i < 2; i++)
          {
            for (j = 0; j < 0x48; j += 2)
            {
              if (i)
              {
                hk[0] = ((hk[3] & hk[5]) | ((~hk[5]) & hk[4]));
              }
              else
              {
                hk[0] = ((hk[3] & hk[4]) | ((~hk[3]) & hk[5]));
              }
              if (j < 8)
              {
                hk[0] = (hk[0] + ((cw[j + 1] << 8) | cw[j]));
              }
              if (j == 8)
              {
                hk[0] = (hk[0] + 0x80);
              }
              hk[0] = (hk[0] + hk[2] + (0xFF & NdTabB001[ecm_header_data[ecmi + 3]][m >> 1] >> ((m & 1) << 3)));
              hk[1] = hk[2];
              hk[2] = hk[3];
              hk[3] = hk[4];
              hk[4] = hk[5];
              hk[5] = hk[6];
              hk[6] = hk[7];
              hk[7] = hk[2] + (((hk[0] << Hash4[m & 0xF]) | (hk[0] >> (0x10 - Hash4[m & 0xF]))));
              m = (m + 1) & 0x3F;
            }
          }
          for (i = 0; i < 6; i++)
          {
            hk[2 + i] += Hash3[i];
          }
          for (i = 0; i < 7; i++)
          {
            cw[i] = hk[2 + (i >> 1)] >> ((i & 1) << 3);
          }
          cw[3] = (cw[0] + cw[1] + cw[2]) & 0xFF;
          cw[7] = (cw[4] + cw[5] + cw[6]) & 0xFF;
          cs_ddump_mask(D_READER, cw, 8, "Postprocessed Case 1 DW:");
          break;
        }
      case 3:
        {
          memset(buffer, 0, sizeof(buffer));
          memcpy(buffer, cw, 8);
          memcpy(buffer + 8, &ecm_header_data[ecmi + 3], ecm_header_data[ecmi] - 2);
          MD5(buffer, 8 + ecm_header_data[ecmi] - 2, md5tmp);
          memcpy(cw, md5tmp, 8);
          cs_ddump_mask(D_READER, cw, 8, "Postprocessed Case 3 DW:");
          break;
        }
      case 2:
        {
          /* Method 2 left out */
          //memcpy(DW_OUTPUT, DW_INPUT, 8);
          break;
        }
      }
    }
  }
}

int32_t videoguard_get_emm_type(EMM_PACKET *ep, struct s_reader * rdr)
{

/*
Unique:
82 30 ad 70 00 XX XX XX 00 XX XX XX 00 XX XX XX 00 XX XX XX 00 00
d3 02 00 22 90 20 44 02 4a 50 1d 88 ab 02 ac 79 16 6c df a1 b1 b7 77 00 ba eb 63 b5 c9 a9 30 2b 43 e9 16 a9 d5 14 00
d3 02 00 22 90 20 44 02 13 e3 40 bd 29 e4 90 97 c3 aa 93 db 8d f5 6b e4 92 dd 00 9b 51 03 c9 3d d0 e2 37 44 d3 bf 00
d3 02 00 22 90 20 44 02 97 79 5d 18 96 5f 3a 67 70 55 bb b9 d2 49 31 bd 18 17 2a e9 6f eb d8 76 ec c3 c9 cc 53 39 00
d2 02 00 21 90 1f 44 02 99 6d df 36 54 9c 7c 78 1b 21 54 d9 d4 9f c1 80 3c 46 10 76 aa 75 ef d6 82 27 2e 44 7b 00

Unknown:
82 00 1C 81 02 00 18 90 16 42 01 xx xx xx xx xx
xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx
*/

	int32_t i;
	int32_t serial_count = ((ep->emm[3] >> 4) & 3) + 1;
	int32_t serial_len = (ep->emm[3] & 0x80) ? 3 : 4;
	uchar emmtype = (ep->emm[3] & VG_EMMTYPE_MASK) >> 6;

	switch(emmtype) {
		case VG_EMMTYPE_G:
			cs_debug_mask(D_EMM, "EMM: GLOBAL");
			ep->type=GLOBAL;
			return TRUE;

		case VG_EMMTYPE_U:
		case VG_EMMTYPE_S:
			cs_debug_mask(D_EMM, "EMM: %s", (emmtype == VG_EMMTYPE_U) ? "UNIQUE" : "SHARED");
			ep->type=emmtype;
			if (ep->emm[1] == 0) // detected UNIQUE EMM from cccam (there is no serial)
				return TRUE;

			for (i = 0; i < serial_count; i++) {
				if (!memcmp(&ep->emm[i * 4 + 4], rdr->hexserial + 2, serial_len)) {
					memcpy(ep->hexserial, &ep->emm[i * 4 + 4], serial_len);
					return TRUE;
				}
			}
			return FALSE; // if UNIQUE or SHARED but no serial match return FALSE

		default:
			//remote emm without serial
			cs_debug_mask(D_EMM, "EMM: UNKNOWN");
			ep->type=UNKNOWN;
			return TRUE;
	}
}

int32_t videoguard_do_emm(struct s_reader * reader, EMM_PACKET *ep, unsigned char CLA, void (*read_tiers)(), int32_t (*docmd)())
{
   unsigned char cta_res[CTA_RES_LEN];
   unsigned char ins42[5] = { CLA, 0x42, 0x00, 0x00, 0xFF };
   int32_t rc = ERROR;
   int32_t nsubs = ((ep->emm[3] & 0x30) >> 4) + 1;
   int32_t offs = 4;
   int32_t emmv2 = 0;
   int32_t position, ua_position = -1;
   int32_t serial_len = (ep->type == SHARED) ? 3: 4;
   int32_t vdrsc_fix = 0;

   if (ep->type == UNIQUE || ep->type == SHARED)
   {
      if (ep->emm[1] == 0x00)  // cccam sends emm-u without UA
      {
         nsubs = 1;
         ua_position = 0;
      }
      else
      {
         int32_t i;
         for (i = 0; i < nsubs; ++i)
         {
            if (memcmp(&ep->emm[4+i*4], &reader->hexserial[2], serial_len) == 0)
            {
               ua_position = i;
               break;
            }
         }
         offs += nsubs * 4;
      }
      if (ua_position == -1)
         return ERROR;
   }
   // if (ep->type == GLOBAL && memcmp(&ep->emm[4], &reader->hexserial[2], 4) == 0)  // workaround for vdr-sc client
   // {
   //    ep->type = UNIQUE;
   //    vdrsc_fix = 1;
   //    offs += 4;
   // }
   if (ep->emm[offs] == 0x00 && (ep->emm[offs+1] == 0x00 || ep->emm[offs+1] == 0x01))  // unmodified emm from dvbapi
   {
      emmv2 = ep->emm[offs+1];
      offs += 2 + 1 + emmv2;  // skip sub-emm len (2 bytes sub-emm len if 0x01);
   }
   for (position = 0; position < nsubs && offs+2 < ep->l; ++position)
   {
      if (ep->emm[offs] > 0x07)  // workaround for mgcamd and emmv2
         ++offs;
      if (ep->emm[offs] == 0x02 || ep->emm[offs] == 0x03 || ep->emm[offs] == 0x07)
      {
         if (ep->emm[offs] == 0x03 && (position == ua_position || vdrsc_fix))
         {
            videoguard_mail_msg(reader, &ep->emm[offs+2]);
            return OK;
         }
         offs += ep->emm[offs+1] + 2;
         if (!(offs < ep->l))
            return rc;
         if (ep->emm[offs] != 0)
         {
            if (ep->type == GLOBAL || vdrsc_fix || position == ua_position)
            {
               ins42[4] = ep->emm[offs];
               int32_t l = (*docmd)(reader, ins42, &ep->emm[offs+1], NULL, cta_res);
               if (l > 0 && status_ok(cta_res))
                  rc = OK;
               cs_debug_mask(D_EMM, "EMM request return code : %02X%02X", cta_res[0], cta_res[1]);
               if (status_ok(cta_res) && (cta_res[1] & 0x01))
                  (*read_tiers)(reader);
            }
            offs += ep->emm[offs] + 1;
         }
         offs += 2;
         if (vdrsc_fix) --position;
      }
      else
         return rc;
   }
   return rc;
}

void videoguard_get_emm_filter(struct s_reader * rdr, uchar *filter)
{
	int32_t idx = 2;
	int32_t n;

	filter[0]=0xFF;
	filter[1]=0;

	for (n = 0; n < 3; ++n)
	{
		filter[idx++]=EMM_UNIQUE;
		filter[idx++]=0;
		filter[idx+0]    = 0x82;
		filter[idx+0+16] = 0xFF;
		filter[idx+1]    = 0x40;
		filter[idx+1+16] = 0xC0;
		memcpy(filter+idx+2+4*n, rdr->hexserial+2, 4);
		memset(filter+idx+2+4*n+16, 0xFF, 4);
		idx +=32;
		filter[1]++;
	}
	// fourth serial position does not fit within the 16bytes demux filter

	for (n = 0; n < 3; ++n)
	{
		filter[idx++]=EMM_SHARED;
		filter[idx++]=0;
		filter[idx+0]    = 0x82;
		filter[idx+0+16] = 0xFF;
		filter[idx+1]    = 0x80;
		filter[idx+1+16] = 0xC0;
		memcpy(filter+idx+2+4*n, rdr->hexserial+2, 3);
		memset(filter+idx+2+4*n+16, 0xFF, 3);
		idx +=32;
		filter[1]++;
	}
	// fourth serial position does not fit within the 16bytes demux filter

	filter[idx++]=EMM_GLOBAL;
	filter[idx++]=0;
	filter[idx+0]    = 0x82;
	filter[idx+0+16] = 0xFF;
	filter[idx+1]    = 0x00;
	filter[idx+1+16] = 0xC0;
	filter[1]++;
	idx += 32;

	return;
}

static MAILMSG *find_msg(uint16_t caid, uint32_t serial, uint16_t date, uint16_t msg_id)
{
   MAILMSG *msg;
   LL_ITER it = ll_iter_create(vg_msgs);
   while ((msg = (MAILMSG *)ll_iter_next(&it)))
   {
      if (msg->caid == caid && msg->serial == serial && msg->date == date && msg->id == msg_id)
         return msg;
   }
   return 0;
}

static void write_msg(MAILMSG *msg, uint32_t baseyear)
{
   FILE *fp = fopen(cfg.mailfile, "a");
   if (fp == 0)
   {
      cs_log("Cannot open mailfile %s", cfg.mailfile);
      return;
   }

   uint16_t i;
   for (i = 0; i < msg->len - 1; ++i)
   {
      if (msg->message[i] == 0x00 && msg->message[i+1] == 0x32)
      {
         msg->subject = &msg->message[i+3];
         break;
      }
   }
   int32_t year = (msg->date >> 8) / 12 + baseyear;
   int32_t mon = (msg->date >> 8) % 12 + 1;
   int32_t day = msg->date & 0x1f;

   fprintf(fp, "%04X:%08X:%02d/%02d/%04d:%04X:\"%s\":\"%s\"\n", msg->caid, msg->serial, day, mon, year,
                                                                msg->id, msg->subject, msg->message);
   fclose(fp);
   free(msg->message);
   msg->message = msg->subject = 0;
   msg->written = 1;
}

static void msgs_init(uint32_t baseyear)
{
   vg_msgs = ll_create();
   FILE *fp = fopen(cfg.mailfile, "r");
   if (fp == 0)
      return;
   int32_t year, mon, day;
   char buffer[2048];
   while (fgets(buffer, sizeof(buffer), fp))
   {
      MAILMSG *msg;
      if (cs_malloc(&msg, sizeof(MAILMSG), -1) == 0)
      {
         fclose(fp);
         return;
      }
      sscanf(buffer, "%04hX:%08X:%02d/%02d/%04d:%04hX", &msg->caid, &msg->serial, &day, &mon, &year, &msg->id);
      year -= baseyear;
      msg->date = ((year * 12) + mon - 1) << 8 | day;
      msg->message = msg->subject = 0;
      msg->written = 1;
      ll_append(vg_msgs, msg);
   }
   fclose(fp);
}

void videoguard_mail_msg(struct s_reader *rdr, uint8_t *data)
{
   if (cfg.disablemail)
      return;

   if (vg_msgs == 0)
      msgs_init(rdr->card_baseyear);

   if (data[0] != 0xFF || data[1] != 0xFF)
      return;

   uint16_t msg_id = (data[2] << 8) | data[3];
   uint8_t index = data[4] & 0x0F;
   int32_t msg_size = data[5] * 10 + 2;
   uint16_t date = (data[9] << 8) | data[10];
   int32_t submsg_len = data[12] - 2;
   uint16_t submsg_idx = (data[13] << 8) | data[14];
   uint32_t serial = (rdr->hexserial[2]<<24) | (rdr->hexserial[3]<<16) | (rdr->hexserial[4]<<8) | rdr->hexserial[5];

   MAILMSG *msg = find_msg(rdr->caid, serial, date, msg_id);

   if (msg == 0)
   {
      if (cs_malloc(&msg, sizeof(MAILMSG), -1) == 0)
         return;
      msg->caid = rdr->caid;
      msg->serial = serial;
      msg->date = date;
      msg->id = msg_id;
      msg->nsubs = (data[4] & 0xF0) >> 4;
      msg->mask = 1 << index;
      msg->written = 0;
      msg->len = submsg_len;
      if (cs_malloc(&msg->message, msg_size, -1) == 0)
      {
         free(msg);
         return;
      }
      memset(msg->message, 0, msg_size);
      memcpy(&msg->message[submsg_idx], &data[15], submsg_len);
      msg->subject = 0;
      ll_append(vg_msgs, msg);
   }
   else
   {
      if (msg->written == 1 || msg->mask & (1 << index))
         return;
      msg->mask |= 1 << index;
      msg->len += submsg_len;
      memcpy(&msg->message[submsg_idx], &data[15], submsg_len);
   }
   if (msg->mask == (1 << msg->nsubs) - 1)
      write_msg(msg, rdr->card_baseyear);
}

