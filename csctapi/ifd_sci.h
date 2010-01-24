/*
    ifd_sci.h
    Header file for SCI  internal reader.
*/

//#ifdef SCI_DEV
#include "atr.h"
int Sci_Init ();
int Sci_GetStatus (int handle, int * status);
int Sci_Reset (ATR * atr);
int Sci_Activate ();
int Sci_Deactivate ();
//#endif

