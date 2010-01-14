/*
		ifd_phoenix.c
		This module provides IFD handling functions for Smartmouse/Phoenix reader.
*/

#include <stdio.h>
//#include <time.h>
//#include <string.h>
//#include "ioctls.h"
#include "../globals.h"
#include "atr.h"

#define OK 		1 
#define ERROR 0

int Phoenix_Init ()
{
	return OK;
}

int Phoenix_GetStatus (int * status)
{
	int in;
	unsigned int modembits=0;
	extern int oscam_card_detect; //FIXME kill global variable
	if (ioctl(reader[ridx].handle, TIOCMGET,&modembits)<0)
		return ERROR;
	switch(oscam_card_detect&0x7f)
	{
		case	0: in=(modembits & TIOCM_CAR);	break;
		case	1: in=(modembits & TIOCM_DSR);	break;
		case	2: in=(modembits & TIOCM_CTS);	break;
		case	3: in=(modembits & TIOCM_RNG);	break;
		default: in=0;		// dummy
	}
	if (!(oscam_card_detect&0x80))
		in=!in;
	*status = in;
	return OK;
}

int Phoenix_Reset (ATR ** atr)
{
	return OK;
}

int Phoenix_Transmit (BYTE * sent, unsigned size)
{ 
	return OK;
}

int Phoenix_Receive (BYTE * data, unsigned size)
{ 
	return OK;
}	

int Phoenix_SetBaudrate (int mhz)
{
	return OK;
}
