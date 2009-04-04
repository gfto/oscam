#include "ctapi.h"
#include "ctbcs.h"

#define ADDRLEN      4    // Address length in EMM commands
#define MAX_PROV     16
#define SCT_LEN(sct) (3+((sct[1]&0x0f)<<8)+sct[2])
#define MAX_LEN      256

#define CARD_INSERTED	1
#define CARD_NEED_INIT	2
#define CARD_FAILURE	4
