/*
		ifd_sci.c
		This module provides IFD handling functions for SCI internal reader.
*/

#include "ifd_sci.h"

#ifdef SCI_DEV

#include <stdio.h>
#include <time.h>
#include <sys/ioctl.h>
#include "sci_global.h"
#include "sci_ioctl.h"
#include "atr.h"
#include "string.h"
#ifdef SH4
#include <fcntl.h> 
#endif
#include "../globals.h"

#define IFD_TOWITOKO_ATR_TIMEOUT	 800

#define OK 		1 
#define ERROR 0

int Sci_Init ()
{
}

int Sci_GetStatus (int handle, int * status)
{
	int in;
	if (ioctl(handle, IOCTL_GET_IS_CARD_PRESENT, status)<0)
		return ERROR;
	return OK;
}

int Sci_Reset (ATR ** atr)
{
	unsigned char buf[SCI_MAX_ATR_SIZE];
	int n = 0;
	SCI_PARAMETERS params;
#ifdef SH4
	struct timeval tv, tv_spent;
	int atr_size = 2, TDi_exists = 0;
#endif
	
	(*atr) = NULL;

	memset(&params,0,sizeof(SCI_PARAMETERS));
	
	params.ETU = 372; 
	params.EGT = 3; //not sure why this value is chosen
#ifdef SH4		
	params.fs = 9; //not sure why this value is chosen
#else
	params.fs = 5;
#endif
	params.T = 0;
	
	if(ioctl(reader[ridx].handle, IOCTL_SET_PARAMETERS, &params)!=0)
		return ERROR;
	
	if(ioctl(reader[ridx].handle, IOCTL_SET_RESET)<0)
		return ERROR;

#ifdef SH4
	gettimeofday(&tv,0);
	memcpy(&tv_spent,&tv,sizeof(struct timeval));

	while(n<atr_size && (tv_spent.tv_sec-tv.tv_sec)<10)
 		{
		if(IO_Serial_Read(IFD_TOWITOKO_ATR_TIMEOUT, 1, buf+n))
			n++;
		gettimeofday(&tv_spent,0);
		if(n==2) // format character
		{
			// high nibble = TA1 , TB1 , TC1 , TD1
			if(buf[n-1] & 0x10)
				atr_size++;
			if(buf[n-1] & 0x20)
				atr_size++;
			if(buf[n-1] & 0x40)
				atr_size++;
			if(buf[n-1] & 0x80)
			{
				atr_size++;
				TDi_exists=atr_size;
			}
			atr_size+=(buf[n-1] & 0x0F); // historical bytes
		}
		if( (TDi_exists>0) && (n==TDi_exists) )
		{
			TDi_exists=0;
			// high nibble = TA1 , TB1 , TC1 , TD1
			if(buf[n-1] & 0x10)
				atr_size++;
			if(buf[n-1] & 0x20)
				atr_size++;
			if(buf[n-1] & 0x40)
				atr_size++;
			if(buf[n-1] & 0x80)
			{
				atr_size++;
				TDi_exists=atr_size;
			}
		}
	}			
#else
	while(n<SCI_MAX_ATR_SIZE && IO_Serial_Read(IFD_TOWITOKO_ATR_TIMEOUT, 1, buf+n))
	{
		n++;
	}

	if ((buf[0] !=0x3B) && (buf[0] != 0x3F) && (n>9 && !memcmp(buf+4, "IRDETO", 6))) //irdeto S02 reports FD as first byte on dreambox SCI, not sure about SH4 or phoenix
		buf[0] = 0x3B;
#endif
	
	if(n==0)
		return ERROR;

		
	(*atr) = ATR_New ();
	if(ATR_InitFromArray ((*atr), buf, n) == ATR_OK)
	{
		struct timespec req_ts;
		req_ts.tv_sec = 0;
		req_ts.tv_nsec = 50000000;
		nanosleep (&req_ts, NULL);
		if (ioctl(reader[ridx].handle, IOCTL_SET_ATR_READY)<0)
			return ERROR;
		return OK;
	}
	else
	{
		ATR_Delete (*atr);
		(*atr) = NULL;
		return ERROR;
	}
}

int Sci_Activate ()
{
#ifdef DEBUG_IFD
		printf ("IFD: Activating card\n");
#endif
#ifdef SCI_DEV
	if(reader[ridx].typ == R_INTERNAL)
	{
		int in;

#if defined(TUXBOX) && (defined(MIPSEL) || defined(PPC) || defined(SH4))
		if(ioctl(reader[ridx].handle, IOCTL_GET_IS_CARD_PRESENT, &in)<0)
#else
		if(ioctl(reader[ridx].handle, IOCTL_GET_IS_CARD_ACTIVATED, &in)<0)
#endif
			return ERROR;
			
		if(in)
		{
			struct timespec req_ts;
			req_ts.tv_sec = 0;
			req_ts.tv_nsec = 50000000;
			nanosleep (&req_ts, NULL);
			return OK;
		}
		else
			return ERROR;
	}
	else
#endif
	{
		return OK;
	}
}

int Sci_Deactivate ()
{
#ifdef DEBUG_IFD
		printf ("IFD: Deactivating card\n");
#endif

#ifdef SCI_DEV
	if(reader[ridx].typ == R_INTERNAL)
	{
		int in;
		
#if defined(TUXBOX) && (defined(MIPSEL) || defined(PPC) || defined(SH4))
		if(ioctl(reader[ridx].handle, IOCTL_GET_IS_CARD_PRESENT, &in)<0)
#else
		if(ioctl(reader[ridx].handle, IOCTL_GET_IS_CARD_ACTIVATED, &in)<0)
#endif
			return ERROR;
			
		if(in)
		{
			if(ioctl(reader[ridx].handle, IOCTL_SET_DEACTIVATE)<0)
				return ERROR;
		}
		
		
	}
#endif
	
	return OK;
}

#endif
