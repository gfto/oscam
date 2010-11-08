//FIXME Not checked on threadsafety yet; after checking please remove this line
#include "../globals.h"
#include "icc_async.h"
#include "io_serial.h"
#include <termios.h>

#define ACK 0x06
#define MP35_WRITE_DELAY 100
#define MP35_READ_DELAY 200
#define MP35_BREAK_LENGTH 1200

typedef struct
{
  BYTE current_product;
  ushort product_fw_version;
} MP35_info;

// Common command for AD-Teknik readers
static const BYTE fw_version[] = {0x2a, 0x41};

// Commands for AD-Teknik MP3.5 and MP3.6
static const BYTE power_always_on[] = {0x2a, 0x8a};
static const BYTE set_vpp[] = {0x2a, 0x42};
static const BYTE set_data[] = {0x2a, 0x43};
static const BYTE set_oscillator[] = {0x2a, 0x5e};
static const BYTE terminate_com[] = {0x2a, 0x7b};
static const BYTE transthrough_mode[] = {0x2a, 0x7c};
static const BYTE phoenix_mode[] = {0x2a, 0x7d};
static const BYTE smartmouse_mode[] = {0x2a, 0x7e};
static const BYTE phoenix_6mhz_mode[] = {0x2a, 0x9a};
static const BYTE smartmouse_6mhz_mode[] = {0x2a, 0x9b};
static const BYTE fw_info[] = {0x2a, 0xa2};

// Commands for AD-Teknik USB Phoenix
static const BYTE set_mode_osc[] = {0x2a, 0x42};
static const BYTE exit_program_mode[] = {0x2a, 0x43};

static const struct product { BYTE code; const char* product_name; } product_codes[] = {
  {0x10, "USB Phoenix"},
  {0x40, "MP3.4"},
  {0x41, "MP3.5"},
  {0x42, "MP3.6 USB"}};

static BYTE current_product;

static int MP35_product_info(BYTE high, BYTE low, BYTE code, MP35_info* info)
{
  int i;

  for(i = 0; i < (int)(sizeof(product_codes) / sizeof(struct product)); i++)
  {
    if(product_codes[i].code == code)
    {
      cs_log("MP35_Init: %s - FW:%02d.%02d", product_codes[i].product_name, high, low);
      info->current_product = code;
      info->product_fw_version = (high << 8) | low;
      return OK;
    }
  }

  return ERROR;
}

int MP35_Init(struct s_reader * reader)
{
  MP35_info reader_info;
  BYTE rec_buf[32];
  BYTE parameter;
  int original_mhz;

  cs_debug_mask (D_IFD, "IFD: Initializing MP35 reader %s",  reader->label);

  current_product = 0;
  original_mhz = reader->mhz; // MP3.5 commands should be always be written using 9600 baud at 3.58MHz
  reader->mhz = 357;
  
  call(IO_Serial_SetParams(reader, 9600, 8, PARITY_NONE, 1, IO_SERIAL_HIGH, IO_SERIAL_HIGH));

  IO_Serial_Sendbreak(reader, MP35_BREAK_LENGTH);
  IO_Serial_DTR_Clr(reader);
  IO_Serial_DTR_Set(reader);
  cs_sleepms(200);
  IO_Serial_Flush(reader);

  memset(rec_buf, 0x00, sizeof(rec_buf));
  call(IO_Serial_Write(reader, MP35_WRITE_DELAY, 2, fw_version));
  call(IO_Serial_Read(reader, MP35_READ_DELAY, 4, rec_buf));
  if(rec_buf[3] != ACK)
  {
    cs_debug_mask (D_IFD, "IFD: Failed MP35 command: fw_version");
    return ERROR;
  }

  if(MP35_product_info(rec_buf[1], rec_buf[0], rec_buf[2], &reader_info) != OK)
  {
    cs_log("MP35_Init: unknown product code");
    return ERROR;
  }

  if(reader_info.current_product == 0x10) // USB Phoenix
  {
    if(original_mhz == 357)
    {
      cs_log("MP35_Init: Using oscillator 1 (3.57MHz)");
      parameter = 0x01;
    }
    else if(original_mhz == 368)
    {
      cs_log("MP35_Init: Using oscillator 2 (3.68MHz)");
      parameter = 0x02;
    }
    else if(original_mhz == 600)
    {
      cs_log("MP35_Init: Using oscillator 3 (6.00MHz)");
      parameter = 0x03;
    }
    else
    {
      cs_log("MP35_Init: MP35 support only mhz=357, mhz=368 or mhz=600");
      cs_log("MP35_Init: Forced oscillator 1 (3.57MHz)");
      parameter = 0x01;
      original_mhz = 357;
    }
    memset(rec_buf, 0x00, sizeof(rec_buf));
    call(IO_Serial_Write(reader, MP35_WRITE_DELAY, 2, set_mode_osc));
    call(IO_Serial_Write(reader, MP35_WRITE_DELAY, 1, &parameter));
    call(IO_Serial_Read(reader, MP35_READ_DELAY, 1, rec_buf)); // Read ACK from previous command
    if(rec_buf[0] != ACK)
    {
      cs_debug_mask (D_IFD, "IFD: Failed MP35 command: set_mode_osc");
      return ERROR;
    }
    cs_log("MP35_Init: Leaving programming mode");
    memset(rec_buf, 0x00, sizeof(rec_buf));
    call(IO_Serial_Write(reader, MP35_WRITE_DELAY, 2, exit_program_mode));
    call(IO_Serial_Read(reader, MP35_READ_DELAY, 1, rec_buf));
    if(rec_buf[0] != ACK)
    {
      cs_debug_mask (D_IFD, "IFD: Failed MP35 command: exit_program_mode");
      return ERROR;
    }
  }
  else //MP3.5 or MP3.6
  {
    if(reader_info.product_fw_version >= 0x0500)
    {
      int info_len;
      char info[sizeof(rec_buf) - 2];

      memset(rec_buf, 0x00, sizeof(rec_buf));
      call(IO_Serial_Write(reader, MP35_WRITE_DELAY, 2,  fw_info));
      call(IO_Serial_Read(reader, MP35_READ_DELAY, 1, rec_buf));
      info_len = rec_buf[0];
      call(IO_Serial_Read(reader, MP35_READ_DELAY, info_len + 1, rec_buf));
      if(rec_buf[info_len] != ACK)
      {
        cs_debug_mask (D_IFD, "IFD: Failed MP35 command: fw_info");
        return ERROR;
      }
      memcpy(info, rec_buf, info_len);
      info[info_len] = '\0';
      cs_log("MP35_Init: FW Info - %s", info);
    }

    memset(rec_buf, 0x00, sizeof(rec_buf));
    if(original_mhz == 357)
    {
      cs_log("MP35_Init: Using oscillator 1 (3.57MHz)");
      call(IO_Serial_Write(reader, MP35_WRITE_DELAY, 2, phoenix_mode));
    }
    else if(original_mhz == 600)
    {
      cs_log("MP35_Init: Using oscillator 2 (6.00MHz)");
      call(IO_Serial_Write(reader, MP35_WRITE_DELAY, 2, phoenix_6mhz_mode));
    }
    else
    {
      cs_log("MP35_Init: MP35 support only mhz=357 or mhz=600");
      cs_log("MP35_Init: Forced oscillator 1 (3.57MHz)");
      call(IO_Serial_Write(reader, MP35_WRITE_DELAY, 2, phoenix_mode));
      original_mhz = 357;
    }
  }

  reader->mhz = original_mhz; // We might have switched oscillator here
  current_product = reader_info.current_product;
  IO_Serial_Flush(reader);

  return OK;
}

int MP35_Close(struct s_reader * reader)
{
	cs_debug_mask (D_IFD, "IFD: Closing MP35 device %s", reader->device);

  if(current_product != 0x10) // USB Phoenix
  {
    IO_Serial_Sendbreak(reader, MP35_BREAK_LENGTH);
    IO_Serial_DTR_Clr(reader);
  }

  IO_Serial_Close(reader);

	return OK;
}
