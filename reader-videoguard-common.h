#ifndef __NDS_COMMON__
#define __NDS_COMMON__

#include "globals.h"

#include <termios.h>
#include <unistd.h>
#ifdef OS_LINUX
#include <linux/serial.h>
#endif

#define write_cmd_vg(cmd, data) (card_write(reader, cmd, data, cta_res, &cta_lr) == 0)

#define NDSUNKNOWN    0
#define NDSAUTO    0
#define NDS1    1
#define NDS12    12
#define NDS2    2

typedef struct nds_atr {
    uchar atr[MAX_ATR_LEN];
    uint16_t atr_len;
    int32_t base_year;
    int32_t tier_start;
    int32_t nds_version;
    const char *desc;
} NDS_ATR_ENTRY;

extern int32_t cw_is_valid(unsigned char *cw, int32_t start);
extern void cAES_SetKey(struct s_reader * reader, const unsigned char *key);

extern void __xxor(unsigned char *data, int32_t len, const unsigned char *v1, const unsigned char *v2);
#define xor16(v1,v2,d) __xxor((d),16,(v1),(v2))
#define val_by2on3(x)  ((0xaaab*(x))>>16) //fixed point *2/3

extern void cCamCryptVG_SetSeed(struct s_reader * reader);
extern void cCamCryptVG_GetCamKey(struct s_reader * reader, unsigned char *buff);
extern int32_t status_ok(const unsigned char *status);
extern void memorize_cmd_table (struct s_reader * reader, const unsigned char *mem, int32_t size);
extern int32_t cmd_table_get_info(struct s_reader * reader, const unsigned char *cmd, unsigned char *rlen, unsigned char *rmode);
extern int32_t cmd_exists(struct s_reader * reader, const unsigned char *cmd);
extern int32_t read_cmd_len(struct s_reader * reader, const unsigned char *cmd);
extern int32_t do_cmd(struct s_reader * reader, const unsigned char *ins, const unsigned char *txbuff, unsigned char *rxbuff,
                  unsigned char * cta_res);
extern void rev_date_calc(const unsigned char *Date, int32_t *year, int32_t *mon, int32_t *day, int32_t *hh, int32_t *mm, int32_t *ss, int32_t base_year);
extern void rev_date_calc_tm(const unsigned char *Date, struct tm *timeinfo , int32_t base_year);
extern void set_known_card_info(struct s_reader * reader, const unsigned char *atr, const uint32_t *atr_size);

int32_t videoguard_get_emm_type(EMM_PACKET *ep, struct s_reader * rdr);
void videoguard_get_emm_filter(struct s_reader * rdr, uchar *filter);
int32_t videoguard_do_emm(struct s_reader * reader, EMM_PACKET *ep, unsigned char CLA, void (*read_tiers)(), int32_t (*docmd)());
void videoguard_mail_msg(struct s_reader *rdr, uint8_t *data);

#endif // __NDS_COMMON__

