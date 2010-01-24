/*
    ifd_phoenix.h
    Header file for Smartmouse/Phoenix reader.
*/


#define IFD_TOWITOKO_MAX_TRANSMIT 255
#define IFD_TOWITOKO_ATR_TIMEOUT   800
#define IFD_TOWITOKO_BAUDRATE            9600

#ifdef USE_GPIO	//felix: definition of gpio functions
static void set_gpio(int level);
static void set_gpio_input(void);
static int get_gpio(void);
#endif


int Phoenix_Init ();
int Phoenix_GetStatus (int * status);
int Phoenix_Reset (ATR * atr);
int Phoenix_Transmit (BYTE * buffer, unsigned size, unsigned int block_delay, unsigned int char_delay);
int Phoenix_Receive (BYTE * buffer, unsigned size, unsigned int block_timeout, unsigned int char_timeout);
int Phoenix_SetBaudrate (unsigned long baudrate);
int Phoenix_Close ();
