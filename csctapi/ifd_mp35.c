#include "../globals.h"
//#include "../reader-common.h"
#include "icc_async.h"
#include "io_serial.h"
#include <termios.h>

#define ACK 0x06

// Common command for AD-Teknik readers
static const BYTE fw_version[] = {0x2a, 0x41};

// Commands for AD-Teknik MP3.6 and MP3.6
static const BYTE set_vpp[] = {0x2a, 0x42};
static const BYTE set_data[] = {0x2a, 0x43};
static const BYTE set_oscillator[] = {0x2a, 0x5e};
static const BYTE terminate_com[] = {0x2a, 0x7b};
static const BYTE transthrough_mode[] = {0x2a, 0x7c};
static const BYTE phoenix_mode[] = {0x2a, 0x7d};
static const BYTE smartmouse_mode[] = {0x2a, 0x7e};
static const BYTE phoenix_6mhz_mode[] = {0x2a, 0x9a};
static const BYTE smartmouse_6mhz_mode[] = {0x2a, 0x9b};

// Commands for AD-Teknik USB Phoenix
static const BYTE set_mode_osc[] = {0x2a, 0x42};
static const BYTE exit_program_mode[] = {0x2a, 0x43}; // Same as above but different meaning for USB Phoenix

static const struct product { BYTE code; const char* product; } product_codes[] = {
  {0x10, "USB Phoenix"}, 
  {0x40, "MP3.4"}, 
  {0x41, "MP3.5"},
  {0x42, "MP3.6 USB"}};

BYTE current_product;

static int MP35_product_info(BYTE high, BYTE low, BYTE code)
{
  int i;

  for(i = 0; i < (int)(sizeof(product_codes) / sizeof(struct product)); i++)
  {
    if(product_codes[i].code == code)
    {
      cs_log("MP35_Init: %s - FW:%02d.%02d", product_codes[i].product, high, low);
      return OK;
    }
  }

  return ERROR;
}

int MP35_Init(struct s_reader * reader)
{
  BYTE rec_buf[32];
  BYTE parameter;
  int original_mhz;

  current_product = 0;
  memset(rec_buf, 0x00, sizeof(rec_buf));
  call(IO_Serial_InitPnP (reader));
  IO_Serial_Flush(reader);

  cs_debug_mask (D_IFD, "IFD: Initializing MP35 reader %s",  reader->label);

  original_mhz = reader->mhz; // MP3.5 commands should be always be written using 9600 baud at 3.58MHz
  reader->mhz = 357;

  call(IO_Serial_SetParams (reader, 9600, 8, PARITY_NONE, 1, IO_SERIAL_HIGH, IO_SERIAL_HIGH));
  IO_Serial_Sendbreak(reader, 1200);
  IO_Serial_DTR_Clr(reader);
  IO_Serial_Flush(reader);

  IO_Serial_DTR_Set(reader);
  
  call(IO_Serial_Write(reader, 0, 2, fw_version));
  call(IO_Serial_Read(reader, 200, 4, rec_buf));
  if(rec_buf[3] != ACK)
  {
    cs_debug_mask (D_IFD, "IFD: Failed MP35 command: fw_version");
    return ERROR;
  }

  if(MP35_product_info(rec_buf[1], rec_buf[0], rec_buf[2]) != OK)
  {
    cs_log("MP35_Init, unknown product code");
    return ERROR;
  }
  current_product = rec_buf[2];
/*
  call(IO_Serial_Write(reader, 0, 2, terminate_com));
  call(IO_Serial_Read(reader, 200, 1, rec_buf));
  if(rec_buf[0] != ACK)
  {
    cs_debug_mask (D_IFD, "IFD: Failed MP35 command: terminate_com");
    return ERROR;
  }

  parameter = 0x01;
  call(IO_Serial_Write(reader, 0, 2, set_vpp));
  call(IO_Serial_Write(reader, 0, 1, &parameter));
  call(IO_Serial_Read(reader, 200, 1, rec_buf));
  if(rec_buf[0] != ACK)
  {
    cs_debug_mask (D_IFD, "IFD: Failed MP35 command: set_vpp");
    return ERROR;
  }
  
  parameter = 0x02;
  call(IO_Serial_Write(reader, 0, 2, set_data));
  call(IO_Serial_Write(reader, 0, 1, &parameter));
  call(IO_Serial_Read(reader, 200, 1, rec_buf));
  if(rec_buf[0] != ACK)
  {
    cs_debug_mask (D_IFD, "IFD: Failed MP35 command: set_data");
    return ERROR;
  }
  
  parameter = 0x01;
  call(IO_Serial_Write(reader, 0, 2, set_oscillator));
  call(IO_Serial_Write(reader, 0, 1, &parameter));
  call(IO_Serial_Read(reader, 200, 1, rec_buf));
  if(rec_buf[0] != ACK)
  {
    cs_debug_mask (D_IFD, "IFD: Failed MP35 command: set_oscillator");
    return ERROR;
  }

  call(IO_Serial_SetParams (reader, 9600, 8, PARITY_NONE, 1, IO_SERIAL_HIGH, IO_SERIAL_LOW));
  
  call(IO_Serial_Write(reader, 0, 2, transthrough_mode));
*/

  if(current_product == 0x10) // USB Phoenix
  {
    if(original_mhz == 357)
    {
      cs_log("MP35_Init, Using oscillator 1 (3.57MHz)");
      parameter = 0x01;
    }
    else if(original_mhz == 368)
    {
      cs_log("MP35_Init, Using oscillator 2 (3.68MHz)");
      parameter = 0x02;
    }
    else if(original_mhz == 600)
    {
      cs_log("MP35_Init, Using oscillator 3 (6.00MHz)");
      parameter = 0x03;
    }
    else
    {
      cs_log("MP35_Init, MP35 support only mhz=357, mhz=368 or mhz=600");
      cs_log("MP35_Init, Forced oscillator 1 (3.57MHz)");
      parameter = 0x01;
      original_mhz = 357;
    }
    call(IO_Serial_Write(reader, 0, 2, set_mode_osc));
    call(IO_Serial_Write(reader, 0, 1, &parameter));
    call(IO_Serial_Read(reader, 200, 1, rec_buf)); // Read ACK from previous command
    if(rec_buf[0] != ACK)
    {
      cs_debug_mask (D_IFD, "IFD: Failed MP35 command: set_mode_osc");
      return ERROR;
    }
    cs_log("MP35_Init, Leaving programming mode");
    call(IO_Serial_Write(reader, 0, 2, exit_program_mode));
    call(IO_Serial_Read(reader, 200, 1, rec_buf));
    if(rec_buf[0] != ACK)
    {
      cs_debug_mask (D_IFD, "IFD: Failed MP35 command: exit_program_mode");
      return ERROR;
    }
  }
  else //MP3.5 or MP3.6
  {
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
      call(IO_Serial_Write(reader, 0, 2, phoenix_mode));
      original_mhz = 357;
    }
  }

  reader->mhz = original_mhz; // We might have switched oscillator here
  
  IO_Serial_Flush(reader);

  return OK;
}

int MP35_Close(struct s_reader * reader)
{
	cs_debug_mask (D_IFD, "IFD: Closing MP35 device %s", reader->device);

  if(current_product != 0x10) // USB Phoenix
  {
    IO_Serial_Sendbreak(reader, 1200);
    IO_Serial_DTR_Clr(reader);
  }

  IO_Serial_Close(reader);

	return OK;
}
