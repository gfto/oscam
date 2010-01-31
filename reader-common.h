#define ADDRLEN      4    // Address length in EMM commands
#define MAX_PROV     16
#define SCT_LEN(sct) (3+((sct[1]&0x0f)<<8)+sct[2])
#define MAX_LEN      256

//Warning: OK = 0 and ERROR = 1 in csctapi !!!
#define SKIPPED 2
#define OK			1
#define ERROR 	0

#include "atr.h"


// reader-irdeto
int irdeto_card_init(ATR atr);
int irdeto_do_ecm(ECM_REQUEST *);
int irdeto_do_emm(EMM_PACKET *);
int irdeto_card_info(void);

// reader-viaccess
int viaccess_card_init(ATR atr);
int viaccess_do_ecm(ECM_REQUEST *);
int viaccess_do_emm(EMM_PACKET *);
int viaccess_card_info(void);

// reader-videoguard
int videoguard_card_init(ATR atr);
int videoguard_do_ecm(ECM_REQUEST *);
int videoguard_do_emm(EMM_PACKET *);
int videoguard_card_info(void);

// reader-cryptoworks
int cryptoworks_card_init(ATR atr);
int cryptoworks_do_ecm(ECM_REQUEST *);
int cryptoworks_do_emm(EMM_PACKET *);
int cryptoworks_card_info(void);
int CheckSctLen(const uchar *, int);

// reader-seca
int seca_card_init(ATR atr);
int seca_do_ecm(ECM_REQUEST *);
int seca_do_emm(EMM_PACKET *);
int seca_card_info(void);
 
// reader-nds
int nds_card_init(ATR atr, int);
int nds_do_ecm(ECM_REQUEST *);
int nds_do_emm(EMM_PACKET *);
int nds_card_info(void);

// reader nagra2/3
int nagra2_card_init(ATR atr);
int nagra2_do_ecm(ECM_REQUEST *er);
int nagra2_card_info(void);
int nagra2_do_emm(EMM_PACKET *);
void nagra2_post_process();
 
// reader-conax
int conax_card_init(ATR atr);
int conax_do_ecm(ECM_REQUEST *);
int conax_do_emm(EMM_PACKET *);
int conax_card_info(void);
 
// reader-dre
int dre_card_init(ATR atr);
int dre_do_ecm(ECM_REQUEST *);
int dre_do_emm(EMM_PACKET *);
int dre_card_info(void);

#define get_atr \
		unsigned char atr[64]; \
		unsigned int atr_size; \
		ATR_GetRaw(&newatr, atr, &atr_size);

#define get_hist \
		unsigned char hist[64]; \
		unsigned int hist_size; \
		ATR_GetHistoricalBytes(&newatr, hist, &hist_size);

