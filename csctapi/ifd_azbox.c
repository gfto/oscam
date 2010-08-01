
#include "ifd_azbox.h"

int Azbox_Init(struct s_reader *reader)
{
  if ((reader->handle = openxcas_get_smartcard_device(0)) < 0)
    return 0;

  return 1;
}

int Azbox_GetStatus(struct s_reader *reader, int *in)
{
  unsigned char tmp[512];
  memset (tmp, 0, sizeof(tmp));

  int status = ioctl(reader->handle, SCARD_IOC_CHECKCARD, &tmp);

  if (status != 1 && status != 3 && in != NULL)
    *in = 0;
  else
    *in = 1;

  return status;
}

int Azbox_Reset(struct s_reader *reader, ATR *atr)
{
  int status, reset = -1, mode = 0;
  unsigned char tmp[512];

  memset(tmp, 0, sizeof(tmp));
  tmp[0] = 3;
  tmp[1] = 1;

  ioctl(reader->handle, SCARD_IOC_WARMRESET, &tmp);

  cs_sleepms(500);

  while ((status = Azbox_GetStatus(reader, NULL)) != 3)
    cs_sleepms(50);

  memset(tmp, 0, sizeof(tmp));
  tmp[0] = 1;

  int atr_len = ioctl(reader->handle, SCARD_IOC_CHECKCARD, &tmp);
  if (ATR_InitFromArray(atr, tmp, atr_len) != ATR_OK)
    return 0;

   cs_sleepms(500);

   return 1;
}

int Azbox_Transmit(struct s_reader *reader, BYTE *buffer, unsigned size)
{
  if (write(reader->handle, buffer, size) != size)
    return 0;

  return 1;
}

int Azbox_Receive(struct s_reader *reader, BYTE *buffer, unsigned size)
{
  if (read(reader->handle, buffer, size) != size)
    return 0;

  return 1;
 }

int Azbox_Close(struct s_reader *reader)
{
  openxcas_release_smartcard_device(0);

  return 1;
}
