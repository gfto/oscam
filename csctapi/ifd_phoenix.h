/*
    ifd_phoenix.h
    Header file for Smartmouse/Phoenix reader.
*/


#ifdef USE_GPIO	//felix: definition of gpio functions
static void set_gpio(int level);
static void set_gpio_input(void);
static int get_gpio(void);
#endif


int Phoenix_Init (struct s_reader * reader);
int Phoenix_GetStatus (struct s_reader * reader, int * status);
int Phoenix_Reset (struct s_reader * reader, ATR * atr);
int Phoenix_Transmit (struct s_reader * reader, BYTE * buffer, unsigned size, unsigned int block_delay, unsigned int char_delay);
int Phoenix_Receive (struct s_reader * reader, BYTE * buffer, unsigned size, unsigned int timeout);
int Phoenix_SetBaudrate (struct s_reader * reader, unsigned long baudrate);
int Phoenix_Close (struct s_reader * reader);
void Phoenix_FastReset (struct s_reader * reader);
