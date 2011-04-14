
#include "../globals.h"

#ifdef HAVE_PCSC
  #ifdef OS_CYGWIN32
    #define __reserved
    #define __nullnullterminated
    #include <specstrings.h>
    #include <WinSCard.h>
  #else
    #include <PCSC/pcsclite.h> 
    #include <PCSC/winscard.h>
    #ifdef OS_MACOSX 
        #include <PCSC/wintypes.h> 
    #else 
        #include <PCSC/reader.h> 
    #endif 
  #endif

#ifndef ERR_INVALID
#define ERR_INVALID -1
#endif

#ifndef OK
#define OK 0
#endif

int32_t pcsc_reader_init(struct s_reader *pcsc_reader, char *device);
int32_t pcsc_reader_do_api(struct s_reader *pcsc_reader, const uchar *buf, uchar *cta_res, uint16_t *cta_lr,int32_t l);
int32_t pcsc_activate_card(struct s_reader *pcsc_reader, uchar *atr, uint16_t *atr_size);
int32_t pcsc_check_card_inserted(struct s_reader *pcsc_reader);

#endif
