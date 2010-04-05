/*
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <stdio.h>
//#include <time.h>
//#include <string.h>
//#include "ioctls.h"
#include "../globals.h"
#include "atr.h"
#include <termios.h>
#include "ifd_sc8in1.h"
#include "io_serial.h"
#include "icc_async.h"

static struct termios stored_termio[8];//FIXME no globals please
static int current_slot; //FIXME should not be a global, but one per SC8in1
static unsigned char cardstatus; //FIXME not global but one per SC8in1  //if not static, the threads dont share same cardstatus!
static unsigned char sc8in1_clock[2];
static unsigned short is_mcr;

#define MAX_TRANSMIT			255

static int sc8in1_command(struct s_reader * reader, unsigned char * buff, unsigned short lenwrite, unsigned short lenread)
{
  struct termios termio, termiobackup;

  // backup data
  tcgetattr(reader->handle,&termio);
  memcpy(&termiobackup,&termio,sizeof(termio));

  // switch SC8in1 to command mode
  IO_Serial_DTR_Set(reader);

  // set communication parameters
  termio.c_oflag = 0;
  termio.c_lflag = 0;
  termio.c_cc[VTIME] = 1; // working
  termio.c_cflag = B9600|CS8|CREAD|CLOCAL;
  if (tcsetattr(reader->handle,TCSANOW,&termio) < 0) {
    cs_log("ERROR: SC8in1 Command error in set RS232 attributes\n");
    return ERROR;
  }
  cs_ddump_mask (D_DEVICE, buff, lenwrite, "IO: Sending: ");

  if(!write(reader->handle, buff, lenwrite)) {
    cs_log("ERROR: SC8in1 Command write error");
    return ERROR; //dont use IO_Serial_Write since mcr commands dont echo back 
  }

  tcdrain(reader->handle);
  if (IO_Serial_Read (reader, 1000, lenread, buff) == ERROR) {
    cs_log("SC8in1 Command read error");
    return ERROR;
  }

  // switch SC8in1 to normal mode
  //cs_sleepms(10); FIXME do I need this?
  IO_Serial_DTR_Clr(reader);

  // restore data
  memcpy(&termio,&termiobackup,sizeof(termio));
  if (tcsetattr(reader->handle,TCSANOW,&termio) < 0) {
    cs_log("ERROR: SC8in1 Command error in restore RS232 attributes\n");
    return ERROR;
  }
	return OK;
}

static int readsc8in1(struct s_reader * reader)
{
  // Reads the card status
  //
  // the bits in the return bytes:
  // bit0=1 means Slot1=Smartcard inside
  // bit1=1 means Slot2=Smartcard inside
  // bit2=1 means Slot3=Smartcard inside
  // bit3=1 means Slot4=Smartcard inside
  // bit4=1 means Slot5=Smartcard inside
  // bit5=1 means Slot6=Smartcard inside
  // bit6=1 means Slot7=Smartcard inside
  // bit7=1 means Slot8=Smartcard inside
  unsigned char buf[10];
  buf[0]=0x47;
	if (sc8in1_command(reader, buf, 1, 8) < 0) return (-1);
  if (buf[1]!=0x90) return(-1);

  // return result byte
  return(buf[2]);
}

int Sc8in1_Selectslot(struct s_reader * reader, int slot) {
  // selects the Smartcard Socket "slot"
  //
	if (slot == current_slot)
		return OK;
	cs_log("SC8in1: select slot %i", slot);
  int res;
  unsigned char tmp[128];
  struct termios termio;
	//cs_sleepms(10); //FIXME do I need this?
  // backup rs232 data
  tcgetattr(reader->handle,&termio);
	if (current_slot != 0)
  	memcpy(&stored_termio[current_slot-1],&termio,sizeof(termio));
	//
  // switch SC8in1 to command mode
  IO_Serial_DTR_Set(reader);
  // set communication parameters
  termio.c_cc[VTIME] = 1; // working
  termio.c_cflag = B9600|CS8|CREAD|CLOCAL;
  if (tcsetattr(reader->handle,TCSANOW,&termio) < 0) {
    cs_log("ERROR: SC8in1 selectslot set RS232 attributes\n");
    return ERROR;
  }
	tcflush(reader->handle, TCIOFLUSH);
  // selecd select slot command to SC8in1
  //tmp[0]=0x73; //MCR command
  tmp[0]=0x53;
  tmp[1]=slot&0x0F;
  IO_Serial_Write (reader, 0, 2, tmp);
	tcdrain(reader->handle);
	//tcflush(reader->handle, TCIOFLUSH);
  res=IO_Serial_Read (reader, 1000, 4, tmp); // ignore reader response of 4 bytes
	current_slot = slot;
  tcdrain(reader->handle);
  // switch SC8in1 to normal mode
  IO_Serial_DTR_Clr(reader);
  // restore rs232 data
  memcpy(&termio, &stored_termio[reader->slot-1], sizeof(termio));
  if (tcsetattr(reader->handle,TCSANOW,&termio) < 0) {
    cs_log("ERROR: SC8in1 selectslot restore RS232 attributes\n");
    return ERROR;
  }
	//cs_sleepms(10); //FIXME do I need this?
  return OK;
}

int Sc8in1_Init(struct s_reader * reader)
{
	//additional init, Phoenix_Init is also called for Sc8in1 !
	struct termios termio;
	int i;
	tcgetattr(reader->handle,&termio);
	for (i=0; i<8; i++)
		//init all stored termios to default comm settings after device init, before ATR
		memcpy(&stored_termio[i],&termio,sizeof(termio));
		unsigned char buff[] = { 0x74 };
		sc8in1_command(reader, buff, 1, 1);
		if (buff[0] == 4 || buff[0] == 8) {
			is_mcr = (unsigned short) buff[0];
			cs_log("SC8in1: device MCR%i detected", is_mcr);
		}
		else
			is_mcr = 0;
		tcflush(reader->handle, TCIOFLUSH); // a non MCR reader might give longer answer
	return OK;
}

int Sc8in1_Card_Changed(struct s_reader * reader) {
  // returns the SC8in1 Status
  // 0= no card was changed (inserted or removed)
  // -1= one ore more cards were changed (inserted or removed)
  int result;
  int lineData;
  ioctl(reader->handle, TIOCMGET, &lineData);
  result= (lineData & TIOCM_CTS) / TIOCM_CTS;
  return(result-1);
}

int Sc8in1_GetStatus (struct s_reader * reader, int * in)
{
	if (Sc8in1_Card_Changed(reader)|| *in == -1) { //FIXME what happens if slot 1 has no reader defined
		cs_debug("SC8in1: locking for Getstatus for slot %i",reader->slot);
		pthread_mutex_lock(&sc8in1);
		cs_debug("SC8in1: locked for Getstatus for slot %i",reader->slot);
		int i=readsc8in1(reader); //read cardstatus
		pthread_mutex_unlock(&sc8in1);
		cs_debug("SC8in1: unlocked for Getstatus for slot %i",reader->slot);
		if (i < 0)
			return ERROR;
		cardstatus = i;
	}
	//cs_log("Status: %02X, reader[ridx].slot=%i, 1<<slot-1=%02X bool=%i",result,reader[ridx].slot,1<<(reader[ridx].slot-1), result & 1<<(reader[ridx].slot-1));
	*in = (cardstatus & 1<<(reader->slot-1));
	return OK;
}

int MCR_SetClockrate (struct s_reader * reader, int mhz)
{
	unsigned short speed, shift, mask;
	switch (mhz) {
		case 357:
		case 358:
			speed = 0;
			break;
		case 368:
		case 369:
			speed = 1;
			break;
		case 600:
			speed = 2;
			break;
		case 800:
			speed = 3;
			break;
		default:
			speed = 0;
			cs_log("ERROR Sc8in1, cannot set clockspeed to %i", mhz);
			break;
	}
	if (reader->slot >= 5)
		shift = (reader->slot - 5) * 2;
	else
		shift = (reader->slot - 1) * 2;
	speed = speed << shift;
	mask = 3 << shift;

	if (reader->slot >= 5) {
		sc8in1_clock[0] &= mask;
		sc8in1_clock[0] |= speed;
	}
	else {
		sc8in1_clock[1] &= mask;
		sc8in1_clock[1] |= speed;
	}
	return OK;
}
