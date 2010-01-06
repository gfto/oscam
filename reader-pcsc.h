
#include "globals.h"

#ifdef HAVE_PCSC
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>
#ifdef OS_MACOSX
#include <PCSC/wintypes.h>
#else
#include <PCSC/reader.h>
#endif

#ifndef ERR_INVALID
#define ERR_INVALID -1
#endif
#ifndef OK
#define OK 0
#endif

int pcsc_reader_init(struct s_reader *pcsc_reader, char *device);
int pcsc_reader_do_api(struct s_reader *pcsc_reader, uchar *buf, uchar *cta_res, ushort *cta_lr,int l, int dbg);
int pcsc_activate_card(struct s_reader *pcsc_reader, uchar *atr, ushort *atr_size);
int pcsc_check_card_inserted(struct s_reader *pcsc_reader);

#endif
