/*
    ifd_sci.h
    Header file for SCI  internal reader.
*/

//#ifdef SCI_DEV
#include "../globals.h"
#include "atr.h"
int Sci_GetStatus (struct s_reader *reader, int * status);
int Sci_Reset (struct s_reader *reader, ATR * atr);
int Sci_Activate (struct s_reader *reader);
int Sci_Deactivate (struct s_reader *reader);
//#endif
