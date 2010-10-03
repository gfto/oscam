#define ADDRLEN      4    // Address length in EMM commands
#define MAX_PROV     16
#define SCT_LEN(sct) (3+((sct[1]&0x0f)<<8)+sct[2])
#define MAX_LEN      256

//Warning: OK = 0 and ERROR = 1 in csctapi !!!
#define SKIPPED 2
#define OK			1
#define ERROR 	0

#include "atr.h"

void reader_nagra();
void reader_irdeto();
void reader_cryptoworks();
void reader_viaccess();
void reader_conax();
void reader_seca();
void reader_videoguard1();
void reader_videoguard2();
void reader_videoguard12();
void reader_dre();
void reader_tongfang();

int check_emm_cardsystem(struct s_reader * rdr, EMM_PACKET *ep);
void reader_device_close(struct s_reader * reader);

#define write_cmd(cmd, data) \
{ \
        if (card_write(reader, cmd, data, cta_res, &cta_lr)) return ERROR; \
}

#define get_atr \
		unsigned char atr[64]; \
		unsigned int atr_size; \
		memset(atr, 0, sizeof(atr)); \
		ATR_GetRaw(&newatr, atr, &atr_size);

#define get_hist \
		unsigned char hist[64]; \
		unsigned int hist_size; \
		ATR_GetHistoricalBytes(&newatr, hist, &hist_size);

#define def_resp \
		unsigned char cta_res[CTA_RES_LEN]; \
		unsigned short cta_lr;
