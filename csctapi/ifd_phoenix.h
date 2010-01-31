/*
    ifd_phoenix.h
    Header file for Smartmouse/Phoenix reader.
*/


#ifdef USE_GPIO	//felix: definition of gpio functions
static void set_gpio(int level);
static void set_gpio_input(void);
static int get_gpio(void);
#endif


int Phoenix_Init (void);
int Phoenix_GetStatus (int * status);
int Phoenix_Reset (ATR * atr);
int Phoenix_Transmit (BYTE * buffer, unsigned size, unsigned int block_delay, unsigned int char_delay);
int Phoenix_Receive (BYTE * buffer, unsigned size, unsigned int timeout);
int Phoenix_SetBaudrate (unsigned long baudrate);
int Phoenix_Close (void);
