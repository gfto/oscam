#define ADDRLEN      4    // Address length in EMM commands
#define MAX_PROV     16
#define SCT_LEN(sct) (3+((sct[1]&0x0f)<<8)+sct[2])
#define MAX_LEN      256

//Warning: OK = 0 and ERROR = 1 in csctapi !!!
#define SKIPPED 2
#define OK			1
#define ERROR 	0

#include "atr.h"

#define SC_IRDETO 1
#define SC_CRYPTOWORKS 2
#define SC_VIACCESS 3
#define SC_CONAX 4
#define SC_SECA 5
#define SC_VIDEOGUARD2 6
#define SC_DRE 7
#define SC_NAGRA 8
#define SC_TONGFANG 9
#define SC_VIDEOGUARD1 10
#define SC_VIDEOGUARD12 11

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
