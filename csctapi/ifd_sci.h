/*
    ifd_sci.h
    Header file for SCI  internal reader.
*/

//#ifdef SCI_DEV
#include "../globals.h"
#include "atr.h"
int Sci_WriteSettings (struct s_reader * reader, BYTE T, unsigned long fs, unsigned long ETU, unsigned long WWT, unsigned long BWT, unsigned long CWT, unsigned long EGT, unsigned char P, unsigned char I);
int Sci_GetStatus (struct s_reader *reader, int * status);
int Sci_Reset (struct s_reader *reader, ATR * atr);
int Sci_Activate (struct s_reader *reader);
int Sci_Deactivate (struct s_reader *reader);
int Sci_FastReset (struct s_reader *reader);
//#endif
