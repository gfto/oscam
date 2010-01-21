/*
    ifd_phoenix.h
    Header file for Smartmouse/Phoenix reader.
*/

#include "atr.h"
int Phoenix_Init ();
int Phoenix_GetStatus (int * status);
int Phoenix_Reset (ATR ** atr);
int Phoenix_Transmit (BYTE * buffer, unsigned size, unsigned int block_delay, unsigned int char_delay);
int Phoenix_Receive (BYTE * buffer, unsigned size, unsigned int block_timeout, unsigned int char_timeout);
int Phoenix_SetBaudrate (unsigned long baudrate);
int Phoenix_Close ();

#ifdef USE_GPIO //felix: definition of gpio functions

void set_gpio(int level);
void set_gpio_input(void);
int get_gpio(void);

#endif
