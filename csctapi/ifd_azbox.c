#include"../globals.h"

#ifdef CARDREADER_INTERNAL_AZBOX

#include "../oscam-time.h"

#include "atr.h"
#include "../extapi/openxcas/openxcas_api.h"
#include "../extapi/openxcas/openxcas_smartcard.h"
#include "io_serial.h"

#define OK 0
#define ERROR 1

static int32_t sc_mode;

static int32_t _GetStatus(struct s_reader *reader)
{
        unsigned char buf[64];
        memset(buf, 0, sizeof(buf));

        return ioctl(reader->handle, SCARD_IOC_CHECKCARD, &buf);
}

static int32_t Azbox_Reader_Init(struct s_reader *reader)
{
        rdr_log_dbg(reader, D_DEVICE, "Init");

	if((reader->handle = openxcas_get_smartcard_device(0)) < 0)
	{
		rdr_log_dbg(reader, D_DEVICE, "Init reader failed");
		return 0;
	}
	rdr_log_dbg(reader, D_DEVICE, "Init reader %d succeeded", reader->handle);
	return OK;
}

static int32_t Azbox_SetMode(struct s_reader *reader, int32_t mode)
{
        sc_mode = mode;

        rdr_log(reader, "sc_mode %d", sc_mode);
        return OK;
}

static int32_t Azbox_GetStatus(struct s_reader *reader, int32_t *status)
{
        int32_t card_status = _GetStatus(reader);

        if(card_status != 0x03 && card_status != 0x01)
                    { *status = 0; }
        else
                    { *status = 1; }

        //rdr_log_dbg(reader, D_IFD, "openxcas sc: status = %d", *status);
        return OK;
}

static int32_t Azbox_Reset(struct s_reader *reader, ATR *atr)
{
	rdr_log_dbg(reader, D_IFD, "Azbox resetting card");
        unsigned char buf[ATR_MAX_SIZE];
        int32_t card_status;

        buf[0] = 0x03;
        buf[1] = 0x01;
        card_status = ioctl(reader->handle, SCARD_IOC_WARMRESET, &buf);

        while((card_status = _GetStatus(reader)) != 0x03)
                { cs_sleepms(50); }

        buf[0] = 0x02;
        buf[1] = sc_mode;
        sc_mode = ioctl(reader->handle, SCARD_IOC_CHECKCARD, &buf);

        int32_t frequency;
        frequency = reader->cardmhz * 10000L;

        rdr_log(reader, "Set reader mhz = %.2f", (float) frequency / 1000000L);

        int32_t n = 0;
        buf[0] = 0x01;
        n = ioctl(reader->handle, SCARD_IOC_CHECKCARD, &buf);
        //cs_sleepms(50);

        rdr_log_dbg(reader, D_IFD, "Waiting for card ATR Response...");

        int32_t ret = 0;
        while(ret);

        int32_t FI = (buf[n] >> 4);

	int32_t Fi = atr_f_table[FI];
	float fmax = atr_fs_table[FI];

        int32_t D = ATR_DEFAULT_D;
	int32_t DI = (buf[n] & 0x0F);
	D = atr_d_table[DI];

        rdr_log_dbg(reader, D_ATR, "Advertised max cardfrequency is %.2f (Fmax), frequency divider is %d", fmax / 1000000L, Fi);

        if(D == 0) { D = 1;}
	rdr_log_dbg(reader, D_ATR, "Bitrate adjustment is %d (D)", D);

	rdr_log_dbg(reader, D_ATR, "Work ETU = %.2f us assuming card runs at %.2f Mhz", (double)((double)(1 / (double)D) * ((double)Fi / (double)((double)frequency / 1000000))), (float) frequency / 1000000);

        rdr_log_dbg(reader, D_ATR, "Initial ETU = %.2f us", (double)372 / (double)frequency * 1000000);

        rdr_log_dbg(reader, D_IFD, "ATR Fsmax is %.2f MHz, Work ETU is %.2f us, clocking card to %.2f MHz",
			                fmax / 1000000, (double)((double)(1 / (double)D) * ((double)Fi / (double)((double)frequency / 1000000))), (float) frequency / 1000000);

        ret = ATR_InitFromArray(atr, buf, n);

	if(ret == ERROR)
	{
		rdr_log(reader, "WARNING: ATR is invalid!");
		return ERROR;
	}

        rdr_log_dbg(reader, D_IFD, "Card activated");
	return OK;
}

static int32_t Azbox_Reader_Close(struct s_reader *reader)
{
        rdr_log_dbg(reader, D_IFD, "Deactivating card");

        if((reader->handle = openxcas_release_smartcard_device(0)) > 0)
        {
                    rdr_log_dbg(reader, D_DEVICE, "Closing reader %d", reader->handle);
                    return 0;
        }
        return OK;
}

static int32_t Azbox_do_reset(struct s_reader *reader, struct s_ATR *atr,
	                                 int32_t (*rdr_activate_card)(struct s_reader *, struct s_ATR *, uint16_t deprecated),
	                                 int32_t (*rdr_get_cardsystem)(struct s_reader *, struct s_ATR *))
{
       int32_t ret = 0;
       int32_t i;
       if(reader->azbox_mode != -1)
       {
               Azbox_SetMode(reader, reader->azbox_mode);
               if(!rdr_activate_card(reader, atr, 0))
                      { return -1; }
               ret = rdr_get_cardsystem(reader, atr);
       }
       else
       {
               for(i = 0; i < AZBOX_MODES; i++)
               {
                       Azbox_SetMode(reader, i);
                       if(!rdr_activate_card(reader, atr, 0))
                              { return -1; }
                       ret = rdr_get_cardsystem(reader, atr);
                       if(ret)
                               { break; }
               }
       }
       return ret;
}

const struct s_cardreader cardreader_internal_azbox =
{
	.desc         = "internal",
	.typ          = R_INTERNAL,
	.reader_init  = Azbox_Reader_Init,
	.get_status   = Azbox_GetStatus,
	.activate     = Azbox_Reset,
	.transmit     = IO_Serial_Transmit,
	.receive      = IO_Serial_Receive,
	.close        = Azbox_Reader_Close,
	.do_reset     = Azbox_do_reset,
};

#endif
