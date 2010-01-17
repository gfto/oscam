/*
    ifd.h
    Add the header file of your interface devicehere.
*/

#include "ifd_cool.h"

typedef struct
{
  unsigned block_delay;		/* Delay (ms) after starting to transmit */
  unsigned char_delay;		/* Delay (ms) after transmiting sucesive chars */
  unsigned block_timeout;	/* Max timeout (ms) to receive firtst char */
  unsigned char_timeout;	/* Max timeout (ms) to receive sucesive characters */
}
IFD_Timings; //FIXME kill this
