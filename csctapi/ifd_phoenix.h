/*
    ifd_phoenix.h
    Header file for Smartmouse/Phoenix reader.
*/


#ifdef USE_GPIO	//felix: definition of gpio functions
static void set_gpio(struct s_reader * reader, int32_t level);
static void set_gpio_input(struct s_reader * reader);
static int32_t get_gpio(struct s_reader * reader);
#endif


int32_t Phoenix_Init (struct s_reader * reader);
int32_t Phoenix_GetStatus (struct s_reader * reader, int32_t * status);
int32_t Phoenix_Reset (struct s_reader * reader, ATR * atr);
int32_t Phoenix_Transmit (struct s_reader * reader, BYTE * buffer, uint32_t size, uint32_t block_delay, uint32_t char_delay);
int32_t Phoenix_Receive (struct s_reader * reader, BYTE * buffer, uint32_t size, uint32_t timeout);
int32_t Phoenix_SetBaudrate (struct s_reader * reader, uint32_t baudrate);
int32_t Phoenix_Close (struct s_reader * reader);
int32_t Phoenix_FastReset (struct s_reader * reader, int32_t delay);
