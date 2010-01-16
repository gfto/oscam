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
      unsigned short Ctn                  /* Terminal Number */
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

    /* #define DAD */
#define CARD            0
#define CT              1
#define HOST            2

#ifdef __cplusplus
}
#endif

#endif
