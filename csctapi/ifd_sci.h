/*
    ifd_sci.h
    Header file for SCI  internal reader.
*/

#ifndef CSCTAPI_IFD_SCI_H_
#define CSCTAPI_IFD_SCI_H_

int32_t Sci_WriteSettings (struct s_reader * reader, unsigned char T, uint32_t fs, uint32_t ETU, uint32_t WWT, uint32_t BWT, uint32_t CWT, uint32_t EGT, unsigned char P, unsigned char I);
int32_t Sci_GetStatus (struct s_reader *reader, int32_t * status);
int32_t Sci_Reset (struct s_reader *reader, ATR * atr);
int32_t Sci_Activate (struct s_reader *reader);
int32_t Sci_Deactivate (struct s_reader *reader);
int32_t Sci_FastReset (struct s_reader *reader, ATR * atr);
int32_t Sci_Read_ATR(struct s_reader * reader, ATR * atr); // reads ATR on the fly: reading and some low levelchecking at the same time

#endif
