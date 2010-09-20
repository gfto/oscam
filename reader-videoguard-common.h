#ifndef __NDS_COMMON__
#define __NDS_COMMON

#include "globals.h"

#include <termios.h>
#include <unistd.h>
#ifdef OS_LINUX
#include <linux/serial.h>
#endif

#define write_cmd_vg(cmd, data) (card_write(reader, cmd, data, cta_res, &cta_lr) == 0)

#define VG_EMMTYPE_MASK 0xC0 
#define VG_EMMTYPE_G 0 
#define VG_EMMTYPE_U 1 
#define VG_EMMTYPE_S 2 

#define NDSUNKNOWN    0
#define NDSAUTO    0
#define NDS1    1
#define NDS12    12
#define NDS2    2

typedef struct nds_atr {
    uchar atr[MAX_ATR_LEN];
    ushort atr_len;
    int base_year;
    int nds_version;
    const char *desc;
} NDS_ATR_ENTRY;

AES_KEY dkey, ekey, Astro_Key;

unsigned char CW1[8], CW2[8];

extern int io_serial_need_dummy_char;

struct CmdTabEntry {
  unsigned char cla;
  unsigned char cmd;
  unsigned char len;
  unsigned char mode;
};

struct CmdTab {
  unsigned char index;
  unsigned char size;
  unsigned char Nentries;
  unsigned char dummy;
  struct CmdTabEntry e[1];
};

struct CmdTab *cmd_table;

extern int cw_is_valid(unsigned char *cw);
extern void cAES_SetKey(const unsigned char *key);
extern int cAES_Encrypt(const unsigned char *data, int len, unsigned char *crypt);
extern void swap_lb (unsigned char *buff, int len);

extern void __xxor(unsigned char *data, int len, const unsigned char *v1, const unsigned char *v2);
#define xor16(v1,v2,d) __xxor((d),16,(v1),(v2))
#define val_by2on3(x)  ((0xaaab*(x))>>16) //fixed point *2/3

extern void cCamCryptVG_SetSeed(unsigned char *Key1, unsigned char *Key2);
extern void cCamCryptVG_GetCamKey(unsigned char *buff);

extern void do_post_dw_hash(unsigned char *cw, unsigned char *ecm_header_data);
extern void Manage_Tag(unsigned char *Answer);
extern int status_ok(const unsigned char *status);

extern void memorize_cmd_table (const unsigned char *mem, int size);
extern int cmd_exists(const unsigned char *cmd);
extern int read_cmd_len(struct s_reader * reader, const unsigned char *cmd);
extern int do_cmd(struct s_reader * reader, const unsigned char *ins, const unsigned char *txbuff, unsigned char *rxbuff, unsigned char * cta_res);

extern void rev_date_calc(const unsigned char *Date, int *year, int *mon, int *day, int *hh, int *mm, int *ss, int base_year);
extern void set_known_card_info(struct s_reader * reader);

#endif // __NDS_COMMON__

