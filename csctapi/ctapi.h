/*****************************************************************
/
/ File   :   ctapi.h
/ Author :   David Corcoran
/ Date   :   September 2, 1998
/ Purpose:   Defines CT-API functions and returns
/ License:   See file LICENSE
/ Note   :   modified by doz21
/
******************************************************************/

#ifndef _ctapi_h_
#define _ctapi_h_

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_APDULEN     1040

extern char CT_init (
      unsigned short Ctn,                  /* Terminal Number */
      unsigned short pn,                    /* Port Number */
      int reader_type,                      /* reader type (mouse, smartreader) */
      int mhz,
      int cardmhz
      );

extern char CT_close(
      unsigned short Ctn                  /* Terminal Number */
      );                 

extern char CT_data( 
       unsigned short ctn,                /* Terminal Number */
       unsigned char  *dad,               /* Destination */
       unsigned char  *sad,               /* Source */
       unsigned short lc,                 /* Length of command */
       unsigned char  *cmd,               /* Command/Data Buffer */
       unsigned short *lr,                /* Length of Response */
       unsigned char  *rsp                /* Response */
       );


#define OK               0               /* Success */
#define ERR_INVALID     -1               /* Invalid Data */
#define ERR_CT          -8               /* CT Error */
#define ERR_TRANS       -10              /* Transmission Error */
#define ERR_MEMORY      -11              /* Memory Allocate Error */
#define ERR_HTSI        -128             /* HTSI Error */

#define PORT_COM1	   0             /* COM 1 */
#define PORT_COM2	   1             /* COM 2 */
#define PORT_COM3	   2             /* COM 3 */
#define PORT_COM4	   3             /* COM 4 */
#define PORT_Printer       4             /* Printer Port (MAC) */
#define PORT_Modem         5             /* Modem Port (MAC)   */
#define PORT_LPT1	   6             /* LPT 1 */
#define PORT_LPT2	   7             /* LPT 2 */

    /* #define DAD */
#define CARD            0
#define CT              1
#define HOST            2

    /* #define port-types */
#define PORT_STD	PORT_COM1
#define PORT_SCI	PORT_COM2
#define PORT_DB2COM1	PORT_COM3
#define PORT_DB2COM2	PORT_COM4

#ifdef __cplusplus
}
#endif

#endif
