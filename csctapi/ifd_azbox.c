#include"../globals.h"

#if defined(WITH_CARDREADER) && defined(WITH_AZBOX)
#include "../oscam-time.h"
#include "icc_async.h"
#include "ifd_azbox.h"

#define OK 0
#define ERROR 1

static int32_t sc_mode;

int32_t _GetStatus(struct s_reader *reader, int32_t *UNUSED(in))
{
  unsigned char tmp[512];
  memset (tmp, 0, sizeof(tmp));

  return ioctl(reader->handle, SCARD_IOC_CHECKCARD, &tmp);
}

int32_t Azbox_Init(struct s_reader *reader)
{
  rdr_debug_mask(reader, D_DEVICE, "openxcas sc: init");

  if ((reader->handle = openxcas_get_smartcard_device(0)) < 0) {
    rdr_debug_mask(reader, D_DEVICE, "openxcas sc: init failed (%d)", reader->handle);
    return 0;
  }

  rdr_debug_mask(reader, D_DEVICE, "openxcas sc: init succeeded");

  return OK;
}

void Azbox_SetMode(struct s_reader *reader, int32_t mode)
{
  sc_mode = mode;
  rdr_log(reader, "openxcas sc: set mode %d", sc_mode);
}

int32_t Azbox_GetStatus(struct s_reader *reader, int32_t *in)
{
  unsigned char tmp[512];
  memset (tmp, 0, sizeof(tmp));

  int32_t status = _GetStatus(reader, in);

  if (in) {
    if (status != 1 && status != 3)
      *in = 0;
    else
      *in = 1;

    //rdr_debug_mask(reader, D_DEVICE, "openxcas sc: get status = %d", *in);
  }

  return OK;
}

int32_t Azbox_Reset(struct s_reader *reader, ATR *atr)
{
  int32_t status;
  unsigned char tmp[512];

  memset(tmp, 0, sizeof(tmp));
  tmp[0] = 3;
  tmp[1] = 1;

  ioctl(reader->handle, SCARD_IOC_WARMRESET, &tmp);

  cs_sleepms(500);

  while ((status = _GetStatus(reader, NULL)) != 3)
    cs_sleepms(50);

  tmp[0] = 0x02;
  tmp[1] = sc_mode;
  status = ioctl(reader->handle, SCARD_IOC_CHECKCARD, &tmp);

  memset(tmp, 0, sizeof(tmp));
  tmp[0] = 1;

  int32_t atr_len = ioctl(reader->handle, SCARD_IOC_CHECKCARD, &tmp);
  if (ATR_InitFromArray(atr, tmp, atr_len) == ERROR)
    return 0;

   cs_sleepms(500);

   return OK;
}

int32_t Azbox_Transmit(struct s_reader *reader, unsigned char *buffer, uint32_t size)
{
  if (write(reader->handle, buffer, size) != (ssize_t)size)
    return 0;

  return OK;
}

int32_t Azbox_Receive(struct s_reader *reader, unsigned char *buffer, uint32_t size)
{
  if (read(reader->handle, buffer, size) != (ssize_t)size)
    return 0;

  return OK;
 }

int32_t Azbox_Close(struct s_reader *UNUSED(reader))
{
  openxcas_release_smartcard_device(0);

  return OK;
}

void cardreader_internal_azbox(struct s_cardreader *crdr)
{
	crdr->desc         = "internal";
	crdr->typ          = R_INTERNAL;
	crdr->skip_extra_atr_parsing  = 1;
	crdr->max_clock_speed = 1;
	crdr->reader_init  = Azbox_Init;
}
#endif
