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

struct termios stored_termio[8];//FIXME no globals please
#define MAX_TRANSMIT			255

static int readsc8in1(struct s_reader * reader) {
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
  int res;
  unsigned char tmp[128];
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
    cs_log("ERROR: SC8in1 readsc8in1 set RS232 attributes\n");
    return(-1);
  }
  // get SC8in1 info
  tmp[0]=0x47;
  IO_Serial_Write (reader, 0, 1, tmp);
  tcdrain(reader->handle);
  res=IO_Serial_Read (reader, 1000, 8, tmp);

  if ( res==ERROR ) {
    cs_log("READSC8in1 read error");
    return(-1); // ERROR !
  }

  // switch SC8in1 to normal mode
  cs_sleepms(2);
  IO_Serial_DTR_Clr(reader);

  // restore data
  memcpy(&termio,&termiobackup,sizeof(termio));
  if (tcsetattr(reader->handle,TCSANOW,&termio) < 0) {
    cs_log("ERROR: SC8in1 readsc8in1 restore RS232 attributes\n");
    return(-1);
  }

  if (tmp[0]!=0x90) return(-1); // ERROR !

  // return result byte
  return(tmp[1]);
}

int selectslot(struct s_reader * reader, int slot) {
  // selects the Smartcard Socket "slot"
  //
	if (slot == current_slot)
		return(0);
	cs_debug("SC8in1: select slot %i", slot);
  int res;
  unsigned char tmp[128];
  struct termios termio;
	//cs_sleepms(10); //FIXME do I need this?
  // backup rs232 data
  tcgetattr(reader->handle,&termio);
  memcpy(&stored_termio[current_slot-1],&termio,sizeof(termio));
	//
  // switch SC8in1 to command mode
  IO_Serial_DTR_Set(reader);
  // set communication parameters
  termio.c_cc[VTIME] = 1; // working
  termio.c_cflag = B9600|CS8|CREAD|CLOCAL;
  if (tcsetattr(reader->handle,TCSANOW,&termio) < 0) {
    cs_log("ERROR: SC8in1 selectslot set RS232 attributes\n");
    return(-1);
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
	cs_sleepms(2);
  // switch SC8in1 to normal mode
  IO_Serial_DTR_Clr(reader);
  // restore rs232 data
  memcpy(&termio, &stored_termio[reader->slot-1], sizeof(termio));
  if (tcsetattr(reader->handle,TCSANOW,&termio) < 0) {
    cs_log("ERROR: SC8in1 selectslot restore RS232 attributes\n");
    return(-1);
  }
	//cs_sleepms(10); //FIXME do I need this?
  return(0);
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
		int i=readsc8in1(reader);
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
