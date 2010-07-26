#include "../globals.h"
//#include "../reader-common.h"
#include "icc_async.h"
#include "io_serial.h"
#include <termios.h>

#define ACK 0x06

static const BYTE fw_version[] = {0x2a, 0x41};
static const BYTE set_vpp[] = {0x2a, 0x42};
static const BYTE set_data[] = {0x2a, 0x43};
static const BYTE set_oscillator[] = {0x2a, 0x5e};
static const BYTE terminate_com[] = {0x2a, 0x7b};
static const BYTE transthrough_mode[] = {0x2a, 0x7c};
static const BYTE phoenix_mode[] = {0x2a, 0x7d};
static const BYTE smartmouse_mode[] = {0x2a, 0x7e};
static const BYTE phoenix_6mhz_mode[] = {0x2a, 0x9a};
static const BYTE smartmouse_6mhz_mode[] = {0x2a, 0x9b};

static const char* product_code[] = {"MP3.4", "MP3.5", "MP3.6 USB"};

int MP35_Init(struct s_reader * reader)
{
  BYTE rec_buf[32];
  BYTE parameter;
  int original_mhz;

  memset(rec_buf, 0x00, sizeof(rec_buf));
  call(IO_Serial_InitPnP (reader));
  IO_Serial_Flush(reader);

  cs_debug_mask (D_IFD, "IFD: Initializing MP35 reader %s",  reader->label);

  IO_Serial_Sendbreak(reader, 1500);
  original_mhz = reader->mhz; // MP3.5 commands should be always be written using 9600 baud at 3.58MHz
  reader->mhz = 357;
  call(IO_Serial_SetParams (reader, 9600, 8, PARITY_NONE, 1, IO_SERIAL_LOW, IO_SERIAL_LOW));
  IO_Serial_Flush(reader);

  IO_Serial_DTR_Set(reader);
  
  call (IO_Serial_Write(reader, 0, 2, fw_version));
  call (IO_Serial_Read(reader, 200, 4, rec_buf));
  if(rec_buf[3] != ACK)
  {
    cs_debug_mask (D_IFD, "IFD: Failed MP35 command: fw_version");
    return ERROR;
  }

  if(rec_buf[2] < 0x40 || rec_buf[2] > 0x42)
  {
    cs_log("MP35_Init, unknown product code");
    return ERROR;
  }
  
  cs_log("MP35_Init: %s - FW:%02d.%02d", product_code[rec_buf[2]-0x40], rec_buf[1], rec_buf[0]);

/*
  call (IO_Serial_Write(reader, 0, 2, terminate_com));
  call (IO_Serial_Read(reader, 200, 1, rec_buf));
  if(rec_buf[0] != ACK)
  {
    cs_debug_mask (D_IFD, "IFD: Failed MP35 command: terminate_com");
    return ERROR;
  }

  parameter = 0x01;
  call (IO_Serial_Write(reader, 0, 2, set_vpp));
  call (IO_Serial_Write(reader, 0, 1, &parameter));
  call (IO_Serial_Read(reader, 200, 1, rec_buf));
  if(rec_buf[0] != ACK)
  {
    cs_debug_mask (D_IFD, "IFD: Failed MP35 command: set_vpp");
    return ERROR;
  }
  
  parameter = 0x02;
  call (IO_Serial_Write(reader, 0, 2, set_data));
  call (IO_Serial_Write(reader, 0, 1, &parameter));
  call (IO_Serial_Read(reader, 200, 1, rec_buf));
  if(rec_buf[0] != ACK)
  {
    cs_debug_mask (D_IFD, "IFD: Failed MP35 command: set_data");
    return ERROR;
  }
  
  parameter = 0x01;
  call (IO_Serial_Write(reader, 0, 2, set_oscillator));
  call (IO_Serial_Write(reader, 0, 1, &parameter));
  call (IO_Serial_Read(reader, 200, 1, rec_buf));
  if(rec_buf[0] != ACK)
  {
    cs_debug_mask (D_IFD, "IFD: Failed MP35 command: set_oscillator");
    return ERROR;
  }

  call (IO_Serial_SetParams (reader, 9600, 8, PARITY_NONE, 1, IO_SERIAL_HIGH, IO_SERIAL_LOW));
  
  call (IO_Serial_Write(reader, 0, 2, transthrough_mode));
*/

  if(original_mhz == 357)
  {
    cs_log("MP35_Init, Using oscillator 1 (3.57MHz)");
    call(IO_Serial_Write(reader, 0, 2, phoenix_mode));
  }
  else if(original_mhz == 600)
  {
    cs_log("MP35_Init, Using oscillator 2 (6.00MHz)");
    call(IO_Serial_Write(reader, 0, 2, phoenix_6mhz_mode));
  }
  else
  {
    cs_log("MP35_Init, MP35 support only mhz=357 or mhz=600");
    cs_log("MP35_Init, Forced oscillator 1 (3.57MHz)");
    original_mhz = 357;
  }

  reader->mhz = original_mhz; // We might have switched oscillator here
  
  IO_Serial_Flush(reader);

  return OK;
}

int MP35_Close(struct s_reader * reader)
{
	cs_debug_mask (D_IFD, "IFD: Closing MP35 device %s", reader->device);

  IO_Serial_Sendbreak(reader, 1500);
  IO_Serial_DTR_Clr(reader);

  IO_Serial_Close(reader);

	return OK;
}
