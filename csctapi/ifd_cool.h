/*
    ifd_cool.h
    Header file for Coolstream internal reader.
*/
#ifndef CSCTAPI_IFD_COOL_H_
#define CSCTAPI_IFD_COOL_H_

#include "atr.h"

int32_t cnxt_smc_open(void *cool_handle, int32_t *, void *, void *);
int32_t cnxt_smc_enable_flow_control(void *cool_handle);
int32_t cnxt_smc_get_state(void *cool_handle, int32_t *state);
int32_t cnxt_smc_get_clock_freq(void *cool_handle, uint32_t *clk);
int32_t cnxt_smc_reset_card(void *cool_handle, int timeout, void *, void *);
int32_t cnxt_smc_get_atr(void *cool_handle, unsigned char *buf, int32_t *buflen);
int32_t cnxt_smc_read_write(void *cool_handle, int32_t b, uint8_t *sent, uint32_t size, char *cardbuffer, uint32_t *cardbuflen, int32_t rw_timeout, int);
int32_t cnxt_smc_set_clock_freq(void *cool_handle, int32_t clk);
int32_t cnxt_smc_close(void *cool_handle);

int32_t Cool_Init (struct s_reader *reader);
int32_t Cool_Reset (struct s_reader *reader, ATR * atr);
int32_t Cool_Transmit (struct s_reader *reader, BYTE * buffer, uint32_t size);
int32_t Cool_Set_Transmit_Timeout(struct s_reader *reader, uint32_t set);
int32_t Cool_Receive (struct s_reader *reader, BYTE * buffer, uint32_t size);
int32_t Cool_SetClockrate (struct s_reader *reader, int32_t mhz);
int32_t Cool_FastReset (struct s_reader *reader);
int32_t Cool_FastReset_With_ATR (struct s_reader *reader, ATR * atr);
int32_t Cool_GetStatus (struct s_reader *reader, int32_t * in);
int32_t Cool_WriteSettings (struct s_reader *reader, uint32_t BWT, uint32_t CWT, uint32_t EGT, uint32_t BGT);
int32_t Cool_Close (struct s_reader *reader);

#endif
