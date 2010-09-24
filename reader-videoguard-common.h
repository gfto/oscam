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
    int tier_start;
    int nds_version;
    const char *desc;
} NDS_ATR_ENTRY;

extern int cw_is_valid(unsigned char *cw, int start);
extern void cAES_SetKey(struct s_reader * reader, const unsigned char *key);
extern void swap_lb (const unsigned char *buff, int len);

extern void __xxor(unsigned char *data, int len, const unsigned char *v1, const unsigned char *v2);
#define xor16(v1,v2,d) __xxor((d),16,(v1),(v2))
#define val_by2on3(x)  ((0xaaab*(x))>>16) //fixed point *2/3

extern void cCamCryptVG_SetSeed(struct s_reader * reader, const unsigned char *Key1, const unsigned char *Key2);
extern void cCamCryptVG_GetCamKey(struct s_reader * reader, unsigned char *buff);

extern void do_post_dw_hash(unsigned char *cw, unsigned char *ecm_header_data);
extern void manage_tag(struct s_reader * reader, unsigned char *answer, unsigned char *cw);
extern int status_ok(const unsigned char *status);

extern void memorize_cmd_table (struct s_reader * reader, const unsigned char *mem, int size);
extern int cmd_exists(struct s_reader * reader, const unsigned char *cmd);
extern int read_cmd_len(struct s_reader * reader, const unsigned char *cmd);
extern int do_cmd(struct s_reader * reader, const unsigned char *ins, const unsigned char *txbuff, unsigned char *rxbuff,
                  unsigned char *cw, unsigned char * cta_res);
extern void rev_date_calc(const unsigned char *Date, int *year, int *mon, int *day, int *hh, int *mm, int *ss, int base_year);
extern void set_known_card_info(struct s_reader * reader);

#endif // __NDS_COMMON__

