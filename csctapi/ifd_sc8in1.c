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

#include "../globals.h"
#ifdef WITH_CARDREADER
#include "atr.h"
#include <termios.h>
#include "ifd_sc8in1.h"
#include "io_serial.h"
#include "icc_async.h"

#define LOCK_SC8IN1 \
{ \
	if (reader->typ == R_SC8in1) { \
		cs_writelock(&reader->sc8in1_config->sc8in1_lock); \
		cs_debug_mask(D_ATR, "SC8in1: locked for access of slot %i", reader->slot); \
		Sc8in1_Selectslot(reader, reader->slot); \
	} \
}

#define UNLOCK_SC8IN1 \
{	\
	if (reader->typ == R_SC8in1) { \
		cs_writeunlock(&reader->sc8in1_config->sc8in1_lock); \
		cs_debug_mask(D_ATR, "SC8in1: unlocked for access of slot %i", reader->slot); \
	} \
}

#ifdef WITH_DEBUG
int32_t Sc8in1_DebugSignals(struct s_reader *reader, uint16_t slot, const char *extra);
#else
#define Sc8in1_DebugSignals(a, b, c) {}
#endif


static int32_t mcrReadStatus(struct s_reader *reader, unsigned char *status);
static int32_t sc8in1ReadStatus(struct s_reader *reader, unsigned char *status);
int32_t Sc8in1_SetBaudrate (struct s_reader * reader, uint32_t baudrate, struct termios *termio, uint8_t cmdMode);
int32_t Sc8in1_NeedBaudrateChange(struct s_reader * reader, uint32_t desiredBaudrate, struct termios *current, struct termios *new, uint8_t cmdMode);
static int32_t sc8in1_tcdrain(struct s_reader *reader);


static int32_t sc8in1_command(struct s_reader * reader, unsigned char * buff,
		uint16_t lenwrite, uint16_t lenread, uint8_t enableEepromWrite, unsigned char getStatusMode,
		uint8_t selectSlotMode) {
	struct termios termio, termiobackup;
	uint32_t currentBaudrate = 0;

	if ( ! reader->handle ) {
		cs_log("ERROR: SC8in1 Command no valid handle\n");
		return ERROR;
	}

	Sc8in1_DebugSignals(reader, reader->slot, "CMD10");

	// switch SC8in1 to command mode
	IO_Serial_DTR_Set(reader);
	tcflush(reader->handle, TCIOFLUSH);

	// backup data
	tcgetattr(reader->handle, &termio);
	memcpy(&termiobackup, &termio, sizeof(termio));

	if (selectSlotMode) {
		if (reader->sc8in1_config->current_slot != 0) {
			memcpy(&reader->sc8in1_config->stored_termio[reader->sc8in1_config->current_slot - 1],
					&termiobackup, sizeof(termiobackup)); //not if current_slot is undefined
		}
	}

	// set communication parameters
	termio.c_oflag = 0;
	termio.c_lflag = 0;
	termio.c_cc[VTIME] = 1; // working
	termio.c_cflag = B9600 | CS8 | CREAD | CLOCAL;

	// Do we need to set the baudrate?
	if (Sc8in1_NeedBaudrateChange(reader, 9600, &termiobackup, &termio, 1)) {
		cs_debug_mask(D_TRACE, "Sc8in1_NeedBaudrateChange for SC8in1 command");
		// save current baudrate for later restore
		currentBaudrate = reader->sc8in1_config->current_baudrate;
		reader->sc8in1_config->current_baudrate = 9600;
		cfsetospeed(&termio, B9600);
		cfsetispeed(&termio, B9600);
		cs_debug_mask(D_DEVICE, "standard baudrate: cardmhz=%d mhz=%d -> effective baudrate %u", reader->cardmhz, reader->mhz, 9600);
	}
	if (tcsetattr(reader->handle, TCSANOW, &termio) < 0) {
		cs_log("ERROR: SC8in1 Command error in set RS232 attributes\n");
		return ERROR;
	}
	if (reader->sc8in1_dtrrts_patch == 1) {
		IO_Serial_DTR_Set(reader);
	}
	Sc8in1_DebugSignals(reader, reader->slot, "CMD11");

	// enable EEPROM write
	if (enableEepromWrite) {
		unsigned char eepromBuff[3];
		eepromBuff[0] = 0x70;
		eepromBuff[1] = 0xab;
		eepromBuff[2] = 0xba;
		cs_ddump_mask(D_DEVICE, eepromBuff, 3, "IO: Sending: ");
		if (!write(reader->handle, eepromBuff, 3)) {
			cs_log("SC8in1 Command write EEPROM error");
			return ERROR;
		}
		tcflush(reader->handle, TCIOFLUSH);
	}
	// write cmd
	cs_ddump_mask(D_DEVICE, buff, lenwrite, "IO: Sending: ");
	uint32_t dataWritten = 0, dataToWrite = lenwrite;
	while (dataWritten < lenwrite) {
		uint32_t written = write(reader->handle, buff, dataToWrite);
		if (written == -1) {
			cs_log("SC8in1 Command write error");
			return ERROR;
		}
		if (written == lenwrite) {
			break;
		}
		else {
			dataWritten += written;
			dataToWrite -= written;
		}
	}

	sc8in1_tcdrain(reader);

	if (IO_Serial_Read(reader, 1000, lenread, buff) == ERROR) {
		cs_log("SC8in1 Command read error");
		return ERROR;
	}

	// Workaround for systems where tcdrain doesnt work properly
	if (lenread <= 0 && reader->sc8in1_config->mcr_type) {
		unsigned char buff_echo_hack[2] = { 0x65, 'A' };
		cs_ddump_mask(D_DEVICE, &buff_echo_hack[0], 2, "IO: Sending: ");
		if (write(reader->handle, &buff_echo_hack[0], 2) != 2) {
			cs_log("SC8in1 Echo command write error");
			return ERROR;
		}
		sc8in1_tcdrain(reader);
		if (IO_Serial_Read(reader, 1000, 1, &buff_echo_hack[0]) == ERROR) {
			cs_log("SC8in1 Echo command read error");
			return ERROR;
		}
		if (buff_echo_hack[0] != 'A') {
			cs_log("SC8in1 Echo command read wrong character");
		}
	}

	if (selectSlotMode) {
		memcpy(&termiobackup, &reader->sc8in1_config->stored_termio[selectSlotMode - 1],
				sizeof(termiobackup));
		if (Sc8in1_NeedBaudrateChange(reader, reader->current_baudrate, &termio, &termiobackup, 1)) {
			cs_debug_mask(D_TRACE, "Sc8in1_SetTermioForSlot for select slot");
			if (Sc8in1_SetBaudrate(reader, reader->current_baudrate, &termiobackup, 0)) {
				cs_log("ERROR: SC8in1 Command Sc8in1_SetBaudrate\n");
				return ERROR;
			}
		}
		else {
			if (tcsetattr(reader->handle, TCSANOW, &termiobackup) < 0) {
				cs_log("ERROR: SC8in1 Command error in set RS232 attributes\n");
				return ERROR;
			}
		}
	}
	else {
		// restore baudrate only if changed
		if (currentBaudrate) {
			if (Sc8in1_SetBaudrate(reader, currentBaudrate, &termiobackup, 1)) {
				cs_log("ERROR: SC8in1 selectslot restore Bitrate attributes\n");
				return ERROR;
			}
		}
		else {
			// restore data
			if (tcsetattr(reader->handle, TCSANOW, &termiobackup) < 0) {
				cs_log("ERROR: SC8in1 Command error in restore RS232 attributes\n");
				return ERROR;
			}
		}
	}

	Sc8in1_DebugSignals(reader, reader->slot, "CMD12");
	if (reader->sc8in1_dtrrts_patch == 1) {
		IO_Serial_DTR_Set(reader);
	}

	tcflush(reader->handle, TCIOFLUSH);

	// switch SC8in1 to normal mode
	IO_Serial_DTR_Clr(reader);

	Sc8in1_DebugSignals(reader, reader->slot, "CMD13");

	return OK;
}

static int32_t sc8in1_tcdrain(struct s_reader *reader) {
	while (1) {
		int32_t tcdrain_ret = tcdrain(reader->handle);
		if (tcdrain_ret==-1) {
			if (errno==EINTR) {
				//try again in case of Interrupted system call
				continue;
			} else
				cs_log("ERROR in sc8in1_tcdrain - (errno=%d %s)", errno, strerror(errno));
				return ERROR;
		}
		break;
	}
	return OK;
}

static int32_t readSc8in1Status(struct s_reader * reader) {
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
	tcflush(reader->handle, TCIOFLUSH);
	if (reader->sc8in1_config->mcr_type) {
		unsigned char buff[2];
		if (mcrReadStatus(reader, &buff[0])) {
			return (-1);
		}
		tcflush(reader->handle, TCIOFLUSH);
		return buff[0];
	}
	else {
		unsigned char buff[8];
		if (sc8in1ReadStatus(reader, &buff[0])) {
			return (-1);
		}
		if (buff[1] != 0x90) {
			return (-1);
		}
		tcflush(reader->handle, TCIOFLUSH);
		return buff[2];
	}
}

static int32_t mcrReadStatus(struct s_reader *reader, unsigned char *status) {
	unsigned char buff[2];
	buff[0] = 0x3f;
	if (sc8in1_command(reader, buff, 1, 2, 0, 1, 0) < 0)
		return ERROR;
	status[0] = buff[0];
	status[1] = buff[1];
	return OK;
}

static int32_t sc8in1ReadStatus(struct s_reader *reader, unsigned char *status) {
	unsigned char buff[8];
	buff[0] = 0x47;
	if (sc8in1_command(reader, buff, 1, 8, 0, 1, 0) < 0)
		return ERROR;
	memcpy(&status[0], &buff[0], 8);
	return OK;
}

static int32_t mcrReadType(struct s_reader *reader, unsigned char *type) {
	unsigned char buff[1];
	buff[0] = 0x74;
	if (sc8in1_command(reader, buff, 1, 1, 0, 0, 0) < 0)
		return ERROR;
	type[0] = buff[0];
	return OK;
}

static int32_t mcrReadVersion(struct s_reader *reader, unsigned char *version) {
	unsigned char buff[1];
	buff[0] = 0x76;
	if (sc8in1_command(reader, buff, 1, 1, 0, 0, 0) < 0)
		return ERROR;
	version[0] = buff[0];
	return OK;
}

static int32_t mcrReadSerial(struct s_reader *reader, unsigned char *serial) {
	unsigned char buff[2];
	buff[0] = 0x6e;
	if (sc8in1_command(reader, buff, 1, 2, 0, 0, 0) < 0)
		return ERROR;
	serial[0] = buff[1];
	serial[1] = buff[0];
	return OK;
}

/*static int32_t mcrWriteDisplayRaw(struct s_reader *reader, unsigned char data[7]) {
	unsigned char buff[8];
	buff[0] = 0x64;
	memcpy(&buff[1], &data[0], 7);
	if (sc8in1_command(reader, buff, 8, 0, 0, 0, 0) < 0)
		return ERROR;
	return OK;
}*/

static int32_t mcrWriteDisplayAscii(struct s_reader *reader, unsigned char data, unsigned char timeout) {
	unsigned char buff[3];
	buff[0] = 0x61;
	buff[1] = data;
	buff[2] = timeout;
	if (sc8in1_command(reader, buff, 3, 0, 0, 0, 0) < 0)
		return ERROR;
	return OK;
}

static int32_t mcrWriteClock(struct s_reader *reader, unsigned char saveClock, unsigned char clock[2]) {
	unsigned char buff[3];
	buff[0] = 0x63;
	buff[1] = clock[0];
	buff[2] = clock[1];
	if (sc8in1_command(reader, buff, 3, 0, 0, 0, 0) < 0)
		return ERROR;
	if (saveClock) {
		buff[0] = 0x6d;
		if (sc8in1_command(reader, buff, 1, 0, 1, 0, 0) < 0)
			return ERROR;
	}
	return OK;
}

static int32_t mcrReadClock(struct s_reader *reader, unsigned char *clock) {
	unsigned char buff[2];
	buff[0] = 0x67;
	if (sc8in1_command(reader, buff, 1, 2, 0, 0, 0) < 0)
		return ERROR;
	clock[0] = buff[0];
	clock[1] = buff[1];
	return OK;
}

static int32_t mcrWriteTimeout(struct s_reader *reader, unsigned char timeout[2]) {
	unsigned char buff[3];
	buff[0] = 0x6f;
	buff[1] = timeout[0];
	buff[2] = timeout[1];
	if (sc8in1_command(reader, buff, 3, 0, 1, 0, 0) < 0)
		return ERROR;
	return OK;
}

static int32_t mcrReadTimeout(struct s_reader *reader, unsigned char *timeout) {
	unsigned char buff[2];
	buff[0] = 0x72;
	if (sc8in1_command(reader, buff, 1, 2, 0, 0, 0) < 0)
		return ERROR;
	timeout[0] = buff[1];
	timeout[1] = buff[0];
	return OK;
}

static int32_t mcrSelectSlot(struct s_reader *reader, unsigned char slot) {
	// Select slot for MCR device.
	// Parameter slot is from 1-8
	unsigned char buff[2];
	buff[0] = 0x73;
	buff[1] = slot - 1;
	if (sc8in1_command(reader, buff, 2, 0, 0, 0, slot) < 0)
		return ERROR;
	return OK;
}

static int32_t sc8in1SelectSlot(struct s_reader *reader, unsigned char slot) {
	// Select slot for SC8in1 device.
	// Parameter slot is from 1-8
	unsigned char buff[6];
	buff[0] = 0x53;
	buff[1] = slot & 0x0F;
	// Read 6 Bytes: 2 Bytes write cmd and 4 unknown Bytes.
	if (sc8in1_command(reader, buff, 2, 6, 0, 0, slot) < 0)
		return ERROR;
	return OK;
}

static int32_t mcrHelloOscam(struct s_reader *reader) {
	// Display "OSCam" on MCR display
	unsigned char helloOscam[5] = {'O', 'S', 'C', 'a', 'm'};
	return MCR_DisplayText(reader, &helloOscam[0], 5, 100, 1);
}

int32_t mcr_generateStatisticsForDisplay(struct s_reader *reader) {
	// show number of clients
	struct s_client *cl;
	uint16_t numClients = 0;
	for ( cl=first_client; cl ; cl=cl->next ) {
		if (cl->typ == 'c'){
			numClients++;
		}
	}
	char msg[8] = { 0 };
	int msgLen = snprintf(&msg[0], 8, "CN%i", numClients);
	if (msgLen > 0 && MCR_DisplayText(reader, msg, msgLen, 300, 0)) {
		return ERROR;
	}
	return OK;
}

static void* mcr_update_display_thread(void *param) {
	const uint16_t DEFAULT_SLEEP_TIME = 100;
	const int32_t STATISTICS_UPDATE_SECONDS = 60;
	struct s_reader *reader = (struct s_reader *)param;
	time_t lastStatisticUpdateTime = time((time_t*)0);

	if (reader->typ != R_SC8in1 ||  ! reader->sc8in1_config->mcr_type) {
		cs_log("Error: mcr_update_display_thread reader no MCR8in1 reader");
		pthread_exit(NULL);
	}

	while(reader->sc8in1_config->display_running) {
		uint16_t display_sleep = DEFAULT_SLEEP_TIME;

		// Update statistics
		time_t currentTime = time((time_t*)0);
		if (currentTime - lastStatisticUpdateTime >= STATISTICS_UPDATE_SECONDS) {
			if (mcr_generateStatisticsForDisplay(reader)) {
				cs_log("ERROR: mcr_generateStatisticsForDisplay");
			}
			lastStatisticUpdateTime = currentTime;
		}

		cs_writelock(&reader->sc8in1_config->sc8in1_display_lock);
		if (reader->sc8in1_config->display != NULL) { // is there something to display?
			cs_writeunlock(&reader->sc8in1_config->sc8in1_display_lock);

			display_sleep = reader->sc8in1_config->display->char_change_time;

			// display the next character
			cs_writelock(&reader->sc8in1_config->sc8in1_lock);
			if (reader->sc8in1_config->display->blocking) {
				uint16_t i = 0;
				for (i = 0; i < reader->sc8in1_config->display->text_length; i++) {
					if (mcrWriteDisplayAscii(reader->sc8in1_config->current_reader,
							reader->sc8in1_config->display->text[++reader->sc8in1_config->display->last_char - 1], 0xFF)) {
						cs_log("SC8in1: Error in mcr_update_display_thread write");
					}
					cs_sleepms(display_sleep);
				}
			}
			else {
				if (mcrWriteDisplayAscii(reader->sc8in1_config->current_reader,
						reader->sc8in1_config->display->text[++reader->sc8in1_config->display->last_char - 1], 0xFF)) {
					cs_log("SC8in1: Error in mcr_update_display_thread write");
				}
			}
			cs_writeunlock(&reader->sc8in1_config->sc8in1_lock);

			// remove the display struct if the text has been shown completely
			if (reader->sc8in1_config->display->last_char == reader->sc8in1_config->display->text_length) {
				cs_writelock(&reader->sc8in1_config->sc8in1_display_lock);
				struct s_sc8in1_display *next = reader->sc8in1_config->display->next;
				free(reader->sc8in1_config->display->text);
				free(reader->sc8in1_config->display);
				reader->sc8in1_config->display = next;
				cs_writeunlock(&reader->sc8in1_config->sc8in1_display_lock);
			}
		}
		else {
			cs_writeunlock(&reader->sc8in1_config->sc8in1_display_lock);
		}
		cs_sleepms(display_sleep);
	}
	pthread_exit(NULL);
	return NULL;
}

int32_t MCR_DisplayText(struct s_reader *reader, char* text, uint16_t text_len, uint16_t time, uint8_t blocking) {
	struct s_sc8in1_display *display;
	if (cs_malloc(&display, sizeof(struct s_sc8in1_display), -1)) {
		if ( ! cs_malloc(&display->text, text_len, -1) ) {
			cs_log("MCR_DisplayText: Out of memory.");
			free(display);
			return ERROR;
		}
		memcpy(display->text, text, text_len);
		display->text_length = text_len;
		display->char_change_time = time;
		display->last_char = 0;
		display->blocking = blocking;
		display->next = NULL;
		cs_writelock(&reader->sc8in1_config->sc8in1_display_lock);
		if (reader->sc8in1_config->display == NULL) {
			reader->sc8in1_config->display = display;
		}
		else {
			struct s_sc8in1_display *d = reader->sc8in1_config->display;
			while (d != NULL) {
				if (d->next == NULL) {
					d->next = display;
					break;
				}
				else {
					d = d->next;
				}
			}
		}
		cs_writeunlock(&reader->sc8in1_config->sc8in1_display_lock);
	} else {
		cs_log("MCR_DisplayText: Out of memory.");
		return ERROR;
	}
	return OK;
}

int32_t SC8in1_Reset (struct s_reader * reader, ATR * atr)
{
		LOCK_SC8IN1
		cs_debug_mask (D_IFD, "IFD: Resetting card:\n");
		int32_t ret;
		int32_t i;
		unsigned char buf[ATR_MAX_SIZE];
		int32_t parity[3] = {PARITY_EVEN, PARITY_ODD, PARITY_NONE};

		if ( ! reader->ins7e11_fast_reset ) {
			if (Sc8in1_SetBaudrate(reader, DEFAULT_BAUDRATE, NULL, 0)) {
				UNLOCK_SC8IN1
#ifdef WITH_DEBUG
				cs_debug_mask(D_TRACE, "ERROR, function call %s returns error.","Phoenix_SetBaudrate (reader, DEFAULT_BAUDRATE)");
#endif
				return ERROR;
			}
		}
		else {
			cs_log("Doing fast reset");
		}

		for(i=0; i<3; i++) {
			IO_Serial_Flush(reader);
			if (IO_Serial_SetParity (reader, parity[i])) {
				UNLOCK_SC8IN1
#ifdef WITH_DEBUG
				cs_debug_mask(D_TRACE, "ERROR, function call %s returns error.","IO_Serial_SetParity (reader, parity[i])");
#endif
				return ERROR;
			}

			ret = ERROR;
			IO_Serial_Ioctl_Lock(reader, 1);
#ifdef USE_GPIO
			if (reader->detect>4)
				set_gpio(reader, 0);
			else
#endif
			IO_Serial_RTS_Set(reader);
			cs_sleepms(200);
#ifdef USE_GPIO  //felix: set card reset hi (inactive)
			if (reader->detect>4) {
				set_gpio_input(reader);
			}
			else
#endif
			IO_Serial_RTS_Clr(reader);

			cs_sleepms(50);
			IO_Serial_Ioctl_Lock(reader, 0);

			int32_t n=0;
			while(n<ATR_MAX_SIZE && !IO_Serial_Read(reader, ATR_TIMEOUT, 1, buf+n))
				n++;
			if(n==0)
				continue;
			if (ATR_InitFromArray (atr, buf, n) == ATR_OK)
				ret = OK;
			// Succesfully retrieve ATR
			if (ret == OK)
				break;
		}
		IO_Serial_Flush(reader);
		UNLOCK_SC8IN1

		return ret;
}

int32_t Sc8in1_NeedBaudrateChange(struct s_reader * reader, uint32_t desiredBaudrate, struct termios *current, struct termios *new, uint8_t cmdMode) {
	// Returns 1 if we need to change the baudrate
	if ((desiredBaudrate != reader->sc8in1_config->current_baudrate)
			||(reader->mhz != reader->cardmhz)
			||(cmdMode == 0 && memcmp(current, new, sizeof(struct termios)))) {
		cs_debug_mask(D_TRACE, "Sc8in1_NeedBaudrateChange TRUE");
		return TRUE;
	}
	cs_debug_mask(D_TRACE, "Sc8in1_NeedBaudrateChange FALSE");
	return FALSE;
}

int32_t Sc8in1_SetBaudrate (struct s_reader * reader, uint32_t baudrate, struct termios *termio, uint8_t cmdMode) {
	/* Get current settings */
	struct termios tio;
	if (termio == NULL) {
		call (tcgetattr (reader->handle, &tio) != 0);
	}
	else {
		tio = *termio;
		if (baudrate == 0) {
			baudrate = reader->current_baudrate;
			if (baudrate == 0) {
				baudrate = 9600;
			}
		}
	}
	cs_debug_mask (D_IFD, "IFD: Sc8in1 Setting baudrate to %u\n", baudrate);
	cs_debug_mask(D_TRACE, "IFD: Sc8in1 Setting baudrate to %u, reader br=%u, currentBaudrate=%u, cmdMode=%u\n", baudrate, reader->current_baudrate, reader->sc8in1_config->current_baudrate, cmdMode);
	call (IO_Serial_SetBitrate (reader, baudrate, &tio));
	call (IO_Serial_SetProperties(reader, tio));
	if (cmdMode == 0) {
		reader->current_baudrate = baudrate;
	}
	return OK;
}

int32_t Sc8in1_SetTioAttr(int32_t fd, struct termios *current, struct termios *new) {
	// Only call tcsetattr if something changed, otherwise strange things may happen
	if ( ! memcmp(current, new, sizeof(struct termios))) {
		//memcpy(current, new, sizeof(struct termios));
		return tcsetattr(fd, TCSANOW, new);
	}
	return OK;
}

int32_t Sc8in1_Selectslot(struct s_reader * reader, uint16_t slot) {
	// selects the Smartcard Socket "slot"
	//
	if (slot == reader->sc8in1_config->current_slot)
		return OK;
	cs_debug_mask(D_TRACE, "SC8in1: select slot %i", slot);

#ifdef WITH_DEBUG
	struct timeval tv_start, tv_end;
	gettimeofday(&tv_start,0);
#endif

	int32_t status = ERROR;
	if (reader->sc8in1_config->mcr_type) {
		status = mcrSelectSlot(reader, slot);
	}
	else {
		status = sc8in1SelectSlot(reader, slot);
	}

	if (status == OK) {
		reader->sc8in1_config->current_reader = reader;
		reader->sc8in1_config->current_slot = slot;
	}
#ifdef WITH_DEBUG
	gettimeofday(&tv_end,0);
	uint32_t elapsed = (tv_end.tv_sec-tv_start.tv_sec)*1000000 + tv_end.tv_usec-tv_start.tv_usec;
	cs_debug_mask(D_DEVICE, "SC8in1 Selectslot in %ums", elapsed/1000);
#endif
	return status;
}

int32_t Sc8in1_Init(struct s_reader * reader) {
	//additional init, Phoenix_Init is also called for Sc8in1 !
	struct termios termio;
	int32_t i, speed, retval;
	uint16_t sc8in1_clock = 0;
	unsigned char buff[3];

	Sc8in1_DebugSignals(reader, reader->slot, "I-1");

	// Clr DTR, which is set by phoenix_init
	IO_Serial_DTR_Clr(reader);

	tcgetattr(reader->handle, &termio);
	for (i = 0; i < 8; i++) {
		//init all stored termios to default comm settings after device init, before ATR
		memcpy(&reader->sc8in1_config->stored_termio[i], &termio,
				sizeof(termio));
	}

	// Init sc8in1 config
	reader->sc8in1_config->mcr_type = 0;
	reader->sc8in1_config->current_reader = reader;

	// check for a MCR device and how many slots it has.
	unsigned char mcrType[1]; mcrType[0] = 0;
	if ( ! mcrReadType(reader, &mcrType[0]) ) {
		if (mcrType[0] == 4 || mcrType[0] == 8) {
			reader->sc8in1_config->mcr_type = mcrType[0];
			cs_log("SC8in1: MCR%u detected for device %s", reader->sc8in1_config->mcr_type, reader->device);

			unsigned char version[1]; version[0] = 0;
			if ( ! mcrReadVersion(reader, &version[0])) {
				cs_log("SC8in1: Version %u for device %s", (unsigned char)version[0], reader->device);
			}

			unsigned char serial[2]; serial[0] = 0; serial[1] = 0;
			if ( ! mcrReadSerial(reader, &serial[0])) {
				cs_log("SC8in1: Serial %u for device %s", (uint16_t)serial[0], reader->device);
			}

			//now work-around the problem that timeout of MCR has to be 0 in case of USB
			unsigned char timeout[2]; timeout[0] = 0; timeout[1] = 0;
			retval = mcrReadTimeout(reader, &timeout[0]);
			if (retval) {
				cs_log("SC8in1: Error reading timeout.");
			}
			else {
				cs_log("SC8in1: Timeout %u for device %s", (uint16_t)timeout[0], reader->device);
			}
			if ((strstr(reader->device, "USB"))
					&& (retval == ERROR || timeout[0] != 0 || timeout[1] != 0)) { //assuming we are connected thru USB and timeout is undetected or not zero
				cs_log("SC8in1: Detected Sc8in1 device connected with USB, setting timeout to 0 and writing to EEPROM");
				timeout[0] = 0; timeout[1] = 0;
				if (mcrWriteTimeout(reader, timeout)) {
					cs_log("SC8in1: Error writing timeout.");
				}
			}

			// Start display thread
			reader->sc8in1_config->display_running = TRUE;
			pthread_attr_t attr;
			pthread_attr_init(&attr);
#ifndef TUXBOX
			pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
#endif
			if (pthread_create(&reader->sc8in1_config->display_thread, &attr, mcr_update_display_thread, (void *)(reader)))
				cs_log("ERROR: can't create MCR_DISPLAY_THREAD thread");
			else {
				cs_log("MCR_DISPLAY_THREAD thread started");
			}
			pthread_attr_destroy(&attr);
		}
	}

	if ( ! reader->sc8in1_config->mcr_type ) {
		tcflush(reader->handle, TCIOFLUSH); // a non MCR reader might give longer answer
	}

	Sc8in1_DebugSignals(reader, reader->slot, "I0");

	struct s_reader *rdr;
	LL_ITER itr = ll_iter_create(configured_readers);
	while ((rdr = ll_iter_next(&itr))) //also do this for disabled readers, so we configure the clocks right for all readers
		if (rdr->sc8in1_config == reader->sc8in1_config) { //corresponding slot
			//check slot boundaries
			int32_t upper_slot = (reader->sc8in1_config->mcr_type) ? reader->sc8in1_config->mcr_type : 8; //set upper limit to 8 for non MCR readers
			if (rdr->slot <= 0 || rdr->slot > upper_slot) {
				cs_log("ERROR: device %s has invalid slot number %i", rdr->device, rdr->slot);
				return ERROR;
			}

			// set initial current_baudrate which is needed by sc8in1_command
			rdr->current_baudrate = reader->current_baudrate;

			if (reader->sc8in1_config->mcr_type) {
				//set RTS for every slot to 1 to prevent jitter/glitch detection problems
				Sc8in1_DebugSignals(reader, rdr->slot, "I1");
				mcrSelectSlot(reader, rdr->slot);
				Sc8in1_DebugSignals(reader, rdr->slot, "I2");
				IO_Serial_RTS_Set(reader);
				Sc8in1_DebugSignals(reader, rdr->slot, "I3");

				//calculate clock-bits
				switch (rdr->mhz) {
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
					cs_log("ERROR Sc8in1, cannot set clockspeed to %i", rdr->mhz);
					break;
				}
				sc8in1_clock |= (speed << ((rdr->slot - 1) * 2));
			}
		}

	if (reader->sc8in1_config->mcr_type) {
		sc8in1_clock = ((sc8in1_clock & 0xFF) << 8) | ((sc8in1_clock & 0xFF00) >> 8);

		//set clockspeeds for all slots
		unsigned char clockspeed[2];
		memcpy(&clockspeed, &sc8in1_clock, 2);
		if (mcrWriteClock(reader, 0, clockspeed)) {
			cs_log("ERROR Sc8in1, cannot set clockspeed %d", (uint16_t)clockspeed[0]);
		}

		// Clear RTS again
		LL_ITER itr = ll_iter_create(configured_readers);
		while ((rdr = ll_iter_next(&itr))) {
			if (rdr->sc8in1_config == reader->sc8in1_config) {
				Sc8in1_DebugSignals(reader, rdr->slot, "I4");
				mcrSelectSlot(reader, rdr->slot);
				Sc8in1_DebugSignals(reader, rdr->slot, "I5");
				IO_Serial_RTS_Clr(reader);
				Sc8in1_DebugSignals(reader, rdr->slot, "I6");
				// Discard ATR
				unsigned char buff[1];
				while ( ! IO_Serial_Read(reader, 500, 1, &buff[0]) ) {
					cs_sleepms(1);
				}
				tcflush(reader->handle, TCIOFLUSH);
			}
		}

		//DEBUG get clockspeeds
		if (mcrReadClock(reader, &clockspeed[0])) {
			cs_log("ERROR Sc8in1, cannot read clockspeed");
		}
		static char * clock[] = { "3,57", "3,68", "6,00", "8,00" };
		uint16_t result = clockspeed[0] << 8 | clockspeed[1];
		for (i = 0; i < 8; i++) {
			cs_log("Slot %i is clocked with %s mhz", i+1, clock[(result>>(i*2))&0X0003]);
		}
	}

	if (reader->sc8in1_config->mcr_type) {
		// select current readers slot again
		mcrSelectSlot(reader, reader->slot);
		reader->sc8in1_config->current_slot = reader->slot;
	}
	else {
		sc8in1SelectSlot(reader, reader->slot);
	}

	//IO_Serial_Flush(reader); //FIXME somehow ATR is generated and must be flushed
	i = -1; //Flag for GetStatus init
	Sc8in1_GetStatus(reader, &i); //Initialize cardstatus
	// Gimmick
	if (reader->sc8in1_config->mcr_type) {
		mcrHelloOscam(reader);
	}

	return OK;
}

#ifdef WITH_DEBUG
int32_t Sc8in1_DebugSignals(struct s_reader *reader, uint16_t slot, const char *extra) {
	uint32_t msr;
	if (ioctl(reader->handle, TIOCMGET, &msr) < 0)
		  return ERROR;
	cs_debug_mask(D_DEVICE, "SC8in1: Signals(%s): Slot: %i, DTR: %u, RTS: %u", extra, slot, msr & TIOCM_DTR ? 1 : 0, msr & TIOCM_RTS ? 1 : 0);
	return OK;
}
#endif

int32_t Sc8in1_Card_Changed(struct s_reader * reader) {
	// returns the SC8in1 Status
	// 0= no card was changed (inserted or removed)
	// -1= one ore more cards were changed (inserted or removed)
	int32_t result;
	int32_t lineData;
	if (reader->handle == 0) {
		return 0;
	}
	ioctl(reader->handle, TIOCMGET, &lineData);
	result = (lineData & TIOCM_CTS) / TIOCM_CTS;

	return (result - 1);
}

int32_t Sc8in1_GetStatus(struct s_reader * reader, int32_t * in) {
	// Only same thread my access serial port
	if ((reader->sc8in1_config->current_slot == reader->slot && Sc8in1_Card_Changed(reader)) || *in == -1) {
		int32_t i = readSc8in1Status(reader); //read cardstatus
		if (i < 0) {
			cs_log("Sc8in1_GetStatus Error");
			return ERROR;
		}
		reader->sc8in1_config->cardstatus = i;
		cs_debug_mask(D_TRACE, "SC8in1: Card status changed; cardstatus=0x%X", reader->sc8in1_config->cardstatus);
	}
	*in = (reader->sc8in1_config->cardstatus & 1 << (reader->slot - 1));
	return OK;
}

int32_t Sc8in1_GetActiveHandle(struct s_reader *reader, uint8_t onlyEnabledReaders) {
	// Returns a handle to the serial port, if it exists in some other
	// slot of the same physical reader.
	// Or returns 0 otherwise.
	struct s_reader *rdr;
	LL_ITER itr = ll_iter_create(configured_readers);
	while ((rdr = ll_iter_next(&itr))) {
		if (rdr->typ == R_SC8in1) {
			if ((reader != rdr) && (reader->sc8in1_config == rdr->sc8in1_config)
					&& rdr->handle != 0 && (onlyEnabledReaders ? rdr->enable != 0 : 1)) {
				return rdr->handle;
			}
		}
	}
	return OK;
}

int32_t Sc8in1_Close(struct s_reader *reader) {
	// Check if we are the last active slot for the reader,
	// then close the serial port. Otherwise select next acive slot.
	cs_debug_mask(D_IFD, "IFD: Closing SC8in1 device %s", reader->device);
	bool status = ERROR;

	if (Sc8in1_GetActiveHandle(reader, TRUE)) {
		cs_debug_mask(D_IFD, "IFD: Just deactivating SC8in1 device %s", reader->device);
		reader->written = 0;
		status = OK;
		// select next active reader slot, so getstatus still works
		if (reader->sc8in1_config->current_slot == reader->slot) {
			struct s_reader *rdr;
			for (rdr=first_active_reader; rdr; rdr=rdr->next) {
				if (rdr->typ == R_SC8in1) {
					if ((reader != rdr) && (reader->sc8in1_config == rdr->sc8in1_config)
							&& rdr->handle != 0) {
						status = Sc8in1_Selectslot(rdr, rdr->slot);
						break;
					}
				}
			}
		}
	} else {
		if (reader->sc8in1_config->mcr_type) {
			// disable reader threads
			reader->sc8in1_config->display_running = FALSE;
			pthread_join(reader->sc8in1_config->display_thread, NULL);
		}
		// disable other slots
		struct s_reader *rdr;
		LL_ITER itr = ll_iter_create(configured_readers);
		while ((rdr = ll_iter_next(&itr))) {
			if (rdr->typ == R_SC8in1) {
				if ((reader != rdr) && (reader->sc8in1_config == rdr->sc8in1_config)) {
					rdr->handle = 0;
				}
			}
		}
		// close serial port
		if (reader->handle != 0) {
			status = IO_Serial_Close(reader);
			reader->handle = 0;
		}
	}

	return status;
}

int32_t Sc8in1_InitLocks(struct s_reader * reader) {
	// Create SC8in1_Configs and init locks.
	// Method is called once for every reader.
	// If there is already a Sc8in1 reader configured with the
	// same device (means same reader, different slot) then use
	// its sc8in1_config, otherwise create a new sc8in1_config and return.

	// Only handle Sc8in1 reader
	if (reader->typ != R_SC8in1) {
		return OK;
	}

	Sc8in1_SetSlotForReader(reader);

	// Get device name
	int32_t pos = strlen(reader->device) - 2;
	if (pos <= 0) {
		return ERROR;
	}
	if (reader->device[pos] != 0x3a) //0x3a = ":"
		cs_log("ERROR: Sc8in1_InitLocks: '%c' detected instead of slot separator `:` at second to last position of device %s", reader->device[pos], reader->device);
	unsigned char savePos = reader->device[pos];
	reader->device[pos] = 0;


	uint8_t reader_config_exists = 0;
	struct s_reader *rdr;
	LL_ITER itr = ll_iter_create(configured_readers);
	while ((rdr = ll_iter_next(&itr))) {
		if (rdr->typ == R_SC8in1 && rdr != reader) {
			unsigned char save = rdr->device[pos];
			rdr->device[pos] = 0; //set to 0 so we can compare device names
			if (!strcmp(reader->device, rdr->device)) { //we have a match to another slot with same device name
				rdr->device[pos] = save; //restore character
				Sc8in1_SetSlotForReader(rdr);
				if (rdr->sc8in1_config) {
					reader->sc8in1_config = rdr->sc8in1_config;
					reader_config_exists = TRUE;
					cs_debug_mask(D_DEVICE, "Sc8in1_InitLocks: Found config for %s", reader->device);
				}
			}
			else {
				rdr->device[pos] = save; //restore character
			}
			if (reader_config_exists) {
				break;
			}
		}
	}

	if (!reader_config_exists) {
		cs_debug_mask(D_DEVICE, "Sc8in1_InitLocks: Creating new config for %s", reader->device);
		// Create SC8in1_Config for reader
		struct s_sc8in1_config *sc8in1_config;
		if (cs_malloc(&sc8in1_config, sizeof(struct s_sc8in1_config), -1)) {
			reader->sc8in1_config = sc8in1_config;
			char *buff = cs_malloc(&buff, 128, 1);
			snprintf(buff, 128, "sc8in1_lock_%s", reader->device);
			cs_lock_create(&reader->sc8in1_config->sc8in1_lock, 40, buff);
			char *buff2 = cs_malloc(&buff2, 128, 1);
			snprintf(buff2, 128, "display_sc8in1_lock_%s", reader->device);
			cs_lock_create(&reader->sc8in1_config->sc8in1_display_lock, 10, buff2);
		} else {
			reader->device[pos] = savePos;
			cs_log("sc8in1: Out of memory.");
			return ERROR;
		}
	}

	reader->device[pos] = savePos;

	return OK;
}

int32_t Sc8in1_SetSlotForReader(struct s_reader *reader) {
	// Sets the slot for the reader if it is not set already
	int32_t pos = strlen(reader->device)-2; //this is where : should be located; is also valid length of physical device name
	if (reader->device[pos] != 0x3a) //0x3a = ":"
		cs_log("ERROR: '%c' detected instead of slot separator `:` at second to last position of device %s", reader->device[pos], reader->device);
	reader->slot=(uint16_t)reader->device[pos+1] - 0x30;
	return OK;
}
#endif
