/*
        ifd_sci.c
        This module provides IFD handling functions for SCI internal reader.
*/

#include "../globals.h"

#ifdef CARDREADER_INTERNAL_SCI

#include "../oscam-time.h"

#include "atr.h"
#include "ifd_sci_global.h"
#include "ifd_sci_ioctl.h"
#include "io_serial.h"
#include "../oscam-string.h"

#undef ATR_TIMEOUT
#define ATR_TIMEOUT   800000

#define OK      0
#define ERROR 1

struct sr_data
{
	uint8_t old_reset;
	unsigned char T;
	uint32_t fs; 
	uint32_t ETU;
	uint32_t WWT; 
	uint32_t CWT; 
	uint32_t BWT; 
	uint32_t EGT; 	
	unsigned char P; 
	unsigned char I;
};

static int32_t Sci_GetStatus(struct s_reader *reader, int32_t *status)
{
	call (ioctl(reader->handle, IOCTL_GET_IS_CARD_PRESENT, status)<0);
	return OK;
}

static int32_t Sci_Deactivate(struct s_reader *reader)
{
	int32_t in = 0 ;
	rdr_log(reader, "Deactivating card");
	if (ioctl(reader->handle, IOCTL_GET_IS_CARD_PRESENT, &in)<0)
	{
		rdr_log(reader, "Error:%s ioctl(IOCTL_GET_IS_CARD_PRESENT) failed.(%d:%s)", __FUNCTION__, errno, strerror(errno) );
		return ERROR;
	}
	if (in != 1) {ioctl(reader->handle, IOCTL_GET_IS_CARD_ACTIVATED, &in);}

	if(in && boxtype_is("dm8000"))
	{
		if((ioctl(reader->handle, IOCTL_SET_DEACTIVATE)<0))
		{
			rdr_log(reader,"ioctl(IOCTL_SET_DEACTIVATE) not supported on %s", boxtype_get());
			return ERROR;
		}
	}
	else {return ERROR;}
		
	return OK;
	
}

static int32_t Sci_Activate(struct s_reader *reader)
{
	rdr_log_dbg(reader, D_IFD, "Is card present?");
	int32_t in = 0;
	if (ioctl(reader->handle, IOCTL_GET_IS_CARD_PRESENT, &in)<0)
	{
			rdr_log(reader, "Error:%s ioctl(IOCTL_GET_IS_CARD_PRESENT) failed.(%d:%s)", __FUNCTION__, errno, strerror(errno) );
			Sci_Deactivate(reader);
			return ERROR;
	}
	if (in != 1) {ioctl(reader->handle, IOCTL_GET_IS_CARD_ACTIVATED, &in);}

	if (in)
	{
		cs_sleepms(50);
		return OK;
	}
	else
	{
		rdr_log(reader, "Error: no card is present in readerslot!");
		Sci_Deactivate(reader);
		return ERROR;
	}
}

static int32_t Sci_Read_ATR(struct s_reader *reader, ATR *atr)   // reads ATR on the fly: reading and some low levelchecking at the same time
{
	uint32_t timeout = ATR_TIMEOUT;
	unsigned char buf[SCI_MAX_ATR_SIZE];
	int32_t n = 0, statusreturn = 0;
	
	if(IO_Serial_Read(reader, 0, timeout, 1, buf + n))  //read first char of atr
	{
		rdr_log(reader, "ERROR: no characters found in ATR!");
		return ERROR;
	}
	if(buf[0] == 0x3F)   // 3F: card is using inverse convention, 3B = card is using direct convention
	{
		rdr_log_dbg(reader, D_IFD, "This card uses inverse convention");
	}
	else { rdr_log_dbg(reader, D_IFD, "This card uses direct convention"); }
	n++;
	if(IO_Serial_Read(reader, 0, timeout, 1, buf + n))
	{
		rdr_log_dbg(reader, D_IFD, "ERROR: only 1 character found in ATR");
		return ERROR;
	}
	int32_t T0 = buf[n];
	int32_t historicalbytes = T0 & 0x0F; // num of historical bytes in lower nibble of T0 byte
	rdr_log_dbg(reader, D_ATR, "ATR historicalbytes should be: %d", historicalbytes);
	rdr_log_dbg(reader, D_ATR, "Fetching global interface characters for protocol T0"); // protocol T0 always aboard!
	n++;

	int32_t protocols = 1, tck = 0, protocol, protocolnumber; // protocols = total protocols on card, tck = checksum byte present, protocol = mandatory protocol
	int32_t D = 0;                                              // protocolnumber = TDi uses protocolnumber
	int32_t TDi = T0; // place T0 char into TDi for looped parsing.
	while(n < SCI_MAX_ATR_SIZE)
	{
		if(TDi & 0x10)  //TA Present:                              //The value of TA(i) is always interpreted as XI || UI if i > 2 and T = 15 ='F'in TD(i–1)
		{
			if(IO_Serial_Read(reader, 0, timeout, 1, buf + n)) { break; }  //In this case, TA(i) contains the clock stop indicator XI, which indicates the logical
			//state the clockline must assume when the clock is stopped, and the class indicator UI,
			rdr_log_dbg(reader, D_ATR, "TA%d: %02X", protocols, buf[n]);    //which specifies the supply voltage class.
			if((protocols > 2) && ((TDi & 0x0F) == 0x0F))  // Protocol T15 does not exists, it means mandatory on all ATRs
			{
				if((buf[n] & 0xC0) == 0xC0) { rdr_log_dbg(reader, D_ATR, "Clockline low or high on clockstop"); }
				if((buf[n] & 0xC0) == 0x00) { rdr_log_dbg(reader, D_ATR, "Clockline not supported on clockstop"); }
				if((buf[n] & 0xC0) == 0x40) { rdr_log_dbg(reader, D_ATR, "Clockline should be low on clockstop"); }
				if((buf[n] & 0xC0) == 0x80) { rdr_log_dbg(reader, D_ATR, "Clockline should be high on clockstop"); }
				if((buf[n] & 0x3F) == 0x01) { rdr_log_dbg(reader, D_ATR, "Voltage class A 4.5~5.5V"); }
				if((buf[n] & 0x3F) == 0x02) { rdr_log_dbg(reader, D_ATR, "Voltage class B 2.7~3.3V"); }
				if((buf[n] & 0x3F) == 0x03) { rdr_log_dbg(reader, D_ATR, "Voltage class A 4.5~5.5V and class B 2.7~3.3V"); }
				if((buf[n] & 0x3F) == 0x04) { rdr_log_dbg(reader, D_ATR, "Voltage RFU"); }
			}
			if((protocols > 2) && ((TDi & 0x0F) == 0x01))  // Protocol T1 specfic (There is always an obsolete T0 protocol!)
			{
				int32_t ifsc = buf[n];
				if(ifsc == 0x00) { ifsc = 32; }  //default is 32
				rdr_log_dbg(reader, D_ATR, "Maximum information field length this card can receive is %d bytes (IFSC)", ifsc);
			}

			if(protocols < 2)
			{
				int32_t FI = (buf[n] >> 4); // FI is high nibble                  ***** work ETU = (1/D)*(Frequencydivider/cardfrequency) (in seconds!)
				int32_t Fi = atr_f_table[FI]; // lookup the frequency divider
				float fmax = atr_fs_table[FI]; // lookup the max frequency      ***** initial ETU = 372 / initial frequency during atr  (in seconds!)

				int32_t DI = (buf[n] & 0x0F); // DI is low nibble
				D = atr_d_table[DI]; // lookup the bitrate adjustment (yeah there are floats in it, but in iso only integers!?)
				rdr_log_dbg(reader, D_ATR, "Advertised max cardfrequency is %.2f (Fmax), frequency divider is %d (Fi)", fmax / 1000000L, Fi); // High nibble TA1 contains cardspeed
				rdr_log_dbg(reader, D_ATR, "Bitrate adjustment is %d (D)", D); // Low nibble TA1 contains Bitrateadjustment
				rdr_log_dbg(reader, D_ATR, "Work ETU = %.2f us assuming card runs at %.2f Mhz",
							   (double)((1 / (double)D) * ((double)Fi / (double)fmax) * 1000000), fmax / 1000000L);  // And display it...
				rdr_log_dbg(reader, D_ATR, "Initial ETU = %.2f us", (double)372 / (double)fmax * 1000000); // And display it... since D=1 and frequency during ATR fetch might be different!
			}
			if(protocols > 1 && protocols < 3)
			{
				if((buf[n] & 0x80) == 0x80) { rdr_log_dbg(reader, D_ATR, "Switching between negotiable mode and specific mode is not possible"); }
				else
				{
					rdr_log_dbg(reader, D_ATR, "Switching between negotiable mode and specific mode is possible");
					// int32_t PPS = 1; Stupid compiler, will need it later on eventually
				}
				if((buf[n] & 0x01) == 0x01) { rdr_log_dbg(reader, D_ATR, "Transmission parameters implicitly defined in the interface characters."); }
				else { rdr_log_dbg(reader, D_ATR, "Transmission parameters explicitly defined in the interface characters."); }

				protocol = buf[n] & 0x0F;
				if(protocol) { rdr_log_dbg(reader, D_ATR, "Protocol T = %d is to be used!", protocol); }
			}
			n++; // next interface character
		}
		if(TDi & 0x20)   //TB Present
		{
			if(IO_Serial_Read(reader, 0, timeout, 1, buf + n)) { break; }
			rdr_log_dbg(reader, D_ATR, "TB%d: %02X", protocols, buf[n]);
			if((protocols > 2) && ((TDi & 0x0F) == 0x01))  // Protocol T1 specfic (There is always an obsolete T0 protocol!)
			{
				int32_t CWI = (buf[n] & 0x0F); // low nibble contains CWI code for the character waiting time CWT
				int32_t BWI = (buf[n] >> 4); // high nibble contains BWI code for the block waiting time BWT
				rdr_log_dbg(reader, D_ATR, "Protocol T1: Character waiting time is %d(CWI)", CWI);
				rdr_log_dbg(reader, D_ATR, "Protocol T1: Block waiting time is %d (BWI)", BWI);
			}

			n++; // next interface character
		}
		if(TDi & 0x40)   //TC Present
		{
			if(IO_Serial_Read(reader, 0, timeout, 1, buf + n)) { break; }
			rdr_log_dbg(reader, D_ATR, "TC%d: %02X", protocols, buf[n]);
			if((protocols > 1) && ((TDi & 0x0F) == 0x00))
			{
				int32_t WI = buf[n];
				rdr_log_dbg(reader, D_ATR, "Protocol T0: work wait time is %d work etu (WWT)", (int)(960 * D * WI));
			}
			if((protocols > 1) && ((TDi & 0x0F) == 0x01))
			{
				if(buf[n] & 0x01) { rdr_log_dbg(reader, D_ATR, "Protocol T1: CRC is used to compute the error detection code"); }
				else { rdr_log_dbg(reader, D_ATR, "Protocol T1: LRC is used to compute the error detection code"); }
			}
			if((protocols < 2) && (buf[n] < 0xFF)) { rdr_log_dbg(reader, D_ATR, "Extra guardtime of %d ETU (N)", (int) buf[n]); }
			if((protocols < 2) && (buf[n] == 0xFF)) { rdr_log_dbg(reader, D_ATR, "Protocol T1: Standard 2 ETU guardtime is lowered to 1 ETU"); }

			n++; // next interface character
		}
		if(TDi & 0x80)  //TD Present? Get next TDi there will be a next protocol
		{
			if(IO_Serial_Read(reader, 0, timeout, 1, buf + n)) { break; }
			rdr_log_dbg(reader, D_ATR, "TD%d %02X", protocols, buf[n]);
			TDi = buf[n];
			protocolnumber = TDi & 0x0F;
			if(protocolnumber == 0x00) { tck = 0; }  // T0 protocol do not use tck byte  (TCK = checksum byte!)
			if(protocolnumber == 0x0E) { tck = 1; }  // T14 protocol tck byte should be present
			if(protocolnumber == 0x01) { tck = 1; }  // T1 protocol tck byte is mandatory, BTW: this code doesnt calculate if the TCK is valid jet...
			rdr_log_dbg(reader, D_ATR, "Fetching global interface characters for protocol T%d:", (TDi & 0x0F)); // lower nibble contains protocol number
			protocols++; // there is always 1 protocol T0 in every ATR as per iso defined, max is 16 (numbered 0..15)

			n++; // next interface character
		}
		else { break; }
	}
	int32_t atrlength = 0;
	atrlength += n;
	atrlength += historicalbytes;
	rdr_log_dbg(reader, D_ATR, "Total ATR Length including %d historical bytes should be %d", historicalbytes, atrlength);
	if(T0 & 0x80) { protocols--; }  // if bit 8 set there was a TD1 and also more protocols, otherwise this is a T0 card: substract 1 from total protocols
	rdr_log_dbg(reader, D_ATR, "Total protocols in this ATR is %d", protocols);

	while(n < atrlength + tck)  // read all the rest and mandatory tck byte if other protocol than T0 is used.
	{
		if(IO_Serial_Read(reader, 0, timeout, 1, buf + n)) { break; }
		n++;
	}

	if(n != atrlength + tck) { rdr_log(reader, "WARNING: Total ATR characters received is: %d instead of expected %d", n, atrlength + tck); }

	if((buf[0] != 0x3B) && (buf[0] != 0x3F) && (n > 9 && !memcmp(buf + 4, "IRDETO", 6)))  //irdeto S02 reports FD as first byte on dreambox SCI, not sure about SH4 or phoenix
		{ buf[0] = 0x3B; }

	statusreturn = ATR_InitFromArray(atr, buf, n);  // n should be same as atrlength but in case of atr read error its less so do not use atrlenght here!

	if(buf[7] == 0x70 && buf[8] == 0x70 && (buf[9]&0x0F) >= 10)
	{
		struct s_cardreader *crdr_ops = reader->crdr;
		if (!crdr_ops) return ERROR;
		int8_t nxtr = 0;
		reader->crdr_flush = 0;
		while(nxtr < 2)
		{
			if(IO_Serial_Read(reader, 0, 75000, 1, buf + n + nxtr)) { break; }
			nxtr++;
		}
	}

	if(statusreturn == ATR_MALFORMED) { rdr_log(reader, "WARNING: ATR is malformed, you better inspect it with a -d2 log!"); }

	if(statusreturn == ERROR)
	{
		rdr_log(reader, "WARNING: ATR is invalid!");
		return ERROR;
	}

	return OK; // return OK but atr might be softfailing!
}

static int32_t Sci_Reset(struct s_reader *reader, ATR *atr)
{
	int32_t ret = ERROR;

	SCI_PARAMETERS params;

	memset(&params, 0, sizeof(SCI_PARAMETERS));

	params.ETU = 372; //initial ETU (in iso this parameter F)
	params.EGT = 0; //initial guardtime should be 0 (in iso this is parameter N)
	params.fs = 3; //initial cardmhz 3 Mhz for non pll readers (in iso this is parameter D)
	params.T = 0;
	if(reader->cardmhz > 2000)    // PLL based reader
	{
		params.ETU = 372;
		params.EGT = 0;
		params.fs = (int32_t)(reader->cardmhz / 100.0 + 0.5);  /* calculate divider for 1 MHz  */
		params.T = 0;
	}
	if(reader->cardmhz == 8300)    /* PLL based reader DM7025 */
	{
		params.ETU = 372;
		params.EGT = 0;
		params.fs = 16; /* read from table setting for 1 MHz:
        params.fs = 6 for cardmhz = 5.188 MHz
        params.fs = 7 for cardmhz = 4.611 MHz
        params.fs = 8 for cardmhz = 3.953 MHz
        params.fs = 9 for cardmhz = 3.609 MHz
        params.fs = 10 for cardmhz = 3.192 MHz
        params.fs = 11 for cardmhz = 2.965 MHz
        params.fs = 12 for cardmhz = 2.677 MHz
        params.fs = 13 for cardmhz = 2.441 MHz
        params.fs = 14 for cardmhz = 2.306 MHz
        params.fs = 15 for cardmhz = 2.128 MHz
        params.fs = 16 for cardmhz = 1.977 MHz */
		params.T = 0;
	}

	int32_t tries = 0;
	int32_t max_tries = 0;
	int32_t pll_start_fs = 0;
	if (reader->cardmhz > 2000 && reader->cardmhz != 8300) 
	{
		max_tries = (((double)(reader->cardmhz/900)) * 2 ) + 1 ; // the higher the maxpll the higher tries needed, to have 9 Mhz or first avb below.
		pll_start_fs = ((double)(reader->cardmhz/300)) + 1.5 ; // first avbl reader Mhz equal or above 3.0 Mhz
	}
	else
	{
		max_tries = 5;
	}
	while(ret == ERROR && tries < max_tries)
	{
		cs_sleepms(50);
//		rdr_log(reader, "Set reader parameters!");
		rdr_log_dbg(reader, D_IFD, "Sent reader setting at cardinit T=%d fs=%d ETU=%d WWT=%d CWT=%d BWT=%d EGT=%d clock=%d check=%d P=%d I=%d U=%d",
			   (int)params.T, params.fs, (int)params.ETU, (int)params.WWT,
			   (int)params.CWT, (int)params.BWT, (int)params.EGT,
			   (int)params.clock_stop_polarity, (int)params.check,
			   (int)params.P, (int)params.I, (int)params.U);
		ioctl(reader->handle, IOCTL_SET_PARAMETERS, &params);
		cs_sleepms(150); // give the reader some time to process the params

//		rdr_log(reader, "Reset internal cardreader!");
		if(ioctl(reader->handle, IOCTL_SET_RESET, 1) < 0)
		{
			ret = ERROR;
			rdr_log(reader, "Error:%s ioctl(IOCTL_SET_RESET) failed.(%d:%s)", __FUNCTION__, errno, strerror(errno) );
			Sci_Deactivate(reader);
			Sci_Activate(reader);
			cs_sleepms(50);
        }
		else
		{
			ret = Sci_Read_ATR(reader, atr);
			if(ret == ERROR) 
			{ 
				Sci_Deactivate(reader);
				Sci_Activate(reader);
				if (reader->cardmhz > 2000 && reader->cardmhz != 8300)
				{
					tries++; // increase fs
					params.fs = (pll_start_fs - tries); // if 1 Mhz init failed retry with min 300 Mhz up to max 9.0 Mhz
					rdr_log(reader, "Read ATR fail, attempt %d/%d  fs = %d", tries, max_tries, params.fs);
				}
				else if (reader->cardmhz > 2000 && reader->cardmhz == 8300)
				{
					tries++; // increase fs
					params.fs = (11 - tries); // if 1 Mhz init failed retry with 3.19 Mhz up to 5.188 Mhz
					rdr_log(reader, "Read ATR fail, attempt %d/5  fs = %d", tries, params.fs);
				}
				else 
				{
					tries++; // increase fs
					params.fs = (2 + tries); // if 1 Mhz init failed retry with 3.0 Mhz up to 7.0 Mhz
					rdr_log(reader, "Read ATR fail, attempt %d/5  fs = %d", tries, params.fs);
				} 
			}
			else // ATR fetched successfully!
			{
				if(ioctl(reader->handle, IOCTL_SET_ATR_READY, 1) < 0)
				{
					ret = ERROR;
					rdr_log(reader, "Error:%s ioctl(IOCTL_SET_ATR_READY) failed.(%d:%s)", __FUNCTION__, errno, strerror(errno) );
				}
			}
		}
	}
	return ret;
}

static int32_t Sci_WriteSettings(struct s_reader *reader, unsigned char T, uint32_t fs, uint32_t ETU, uint32_t WWT, uint32_t CWT, uint32_t BWT, uint32_t EGT, unsigned char P, unsigned char I)
{
    cs_sleepms(150);
	struct sr_data *crdr_data = reader->crdr_data;
	//int32_t n;
	SCI_PARAMETERS params;
	//memset(&params,0,sizeof(SCI_PARAMETERS));
	ioctl(reader->handle, IOCTL_GET_PARAMETERS, &params);
	params.T = T;
	params.fs = fs;

	//for Irdeto T14 cards, do not set ETU
	if(ETU)
		{ params.ETU = ETU; }
	params.EGT = EGT;
	params.WWT = WWT;
	params.BWT = BWT;
	params.CWT = CWT;
	if(P)
		{ params.P = P; }
	if(I)
		{ params.I = I; }

	crdr_data->T = params.T;
	crdr_data->fs = params.fs;
	crdr_data->ETU = params.ETU;
	crdr_data->WWT = params.WWT;
	crdr_data->CWT = params.CWT;
	crdr_data->BWT = params.BWT;
	crdr_data->EGT = params.EGT;
	crdr_data->P = params.P;
	crdr_data->I = params.I;

	rdr_log_dbg(reader, D_IFD, "Sent reader settings T=%d fs=%d ETU=%d WWT=%d CWT=%d BWT=%d EGT=%d clock=%d check=%d P=%d I=%d U=%d",
				   (int)params.T, params.fs, (int)params.ETU, (int)params.WWT,
				   (int)params.CWT, (int)params.BWT, (int)params.EGT,
				   (int)params.clock_stop_polarity, (int)params.check,
				   (int)params.P, (int)params.I, (int)params.U);

	ioctl(reader->handle, IOCTL_SET_PARAMETERS, &params);
	cs_sleepms(150); // give the reader some time to process the params
	return OK;
}

static int32_t Sci_FastReset(struct s_reader *reader, ATR *atr)
{
	struct sr_data *crdr_data = reader->crdr_data;
	int8_t atr_ok = 1; // initiate atr in ERROR
	uint32_t timeout = ATR_TIMEOUT;
	unsigned char buf[SCI_MAX_ATR_SIZE];
	int8_t atr_len = 0;

	if(reader->seca_nagra_card == 1)
	{
		atr_len = reader->card_atr_length; // this is a special case the data buffer has only the atr lenght.
	}
	else
	{
		atr_len = reader->card_atr_length + 2; // data buffer has atr lenght + 2 bytes 
	}

	Sci_Activate(reader);
	cs_sleepms(50);
	if(ioctl(reader->handle, IOCTL_SET_RESET, 1) < 0)
	{
		rdr_log(reader, "Error:%s ioctl(IOCTL_SET_RESET) failed.(%d:%s)", __FUNCTION__, errno, strerror(errno) );
		Sci_Deactivate(reader);
		atr_ok = ERROR;
	}
	else
	{
		IO_Serial_Read(reader, 0, timeout,atr_len, buf);  //read atr
//		rdr_log_dump(reader,buf, SCI_MAX_ATR_SIZE * 2, "SCI ATR :"); // just to crosscheck the buffer I left it commented.
		if(ioctl(reader->handle, IOCTL_SET_ATR_READY, 1) < 0)
		{
			rdr_log(reader, "Error:%s ioctl(IOCTL_SET_ATR_READY) failed.(%d:%s)", __FUNCTION__, errno, strerror(errno) );
			Sci_Deactivate(reader);
			atr_ok = ERROR;
		}
		else
		{
			if(ATR_InitFromArray(atr, buf, atr_len) != ERROR)
			{
				atr_ok = OK;
			}
			else
			{
				rdr_log(reader,"Error reading ATR");
				atr_ok= ERROR;
			}
				
			cs_sleepms(150);
			Sci_WriteSettings(reader, crdr_data->T,crdr_data->fs,crdr_data->ETU, crdr_data->WWT,crdr_data->CWT,crdr_data->BWT,crdr_data->EGT,crdr_data->P,crdr_data->I);
			cs_sleepms(150);
		}
	}
	return atr_ok;
}

static int32_t Sci_Init(struct s_reader *reader)
{
	uint8_t i = 0;
	while(reader->handle_nr > 0 && i < 5)
	{
		i++;
		rdr_log(reader," Wait On closing before restart %u", i);
		cs_sleepms(1000);
	}
	
	int flags = O_RDWR | O_NOCTTY;
#if defined(__SH4__) || defined(STB04SCI)
	flags |= O_NONBLOCK;
	reader->sh4_stb = 1;
#endif
	reader->handle = open(reader->device, flags);
	if(reader->handle < 0)
	{
		rdr_log(reader, "ERROR: Opening device %s (errno=%d %s)", reader->device, errno, strerror(errno));
		return ERROR;
	}

	if(!reader->crdr_data && !cs_malloc(&reader->crdr_data, sizeof(struct sr_data)))
		{ return ERROR; }
	struct sr_data *crdr_data = reader->crdr_data;
	crdr_data->old_reset = 1;	
	reader->handle_nr = reader->handle + 1;
	return OK;
}

static int32_t sci_activate(struct s_reader *reader, ATR *atr)
{
	if(!reader->ins7e11_fast_reset)
	{
		call(Sci_Activate(reader));
		call(Sci_Reset(reader, atr));
	}
	else
	{
		rdr_log_dbg(reader, D_IFD, "Fast card reset with atr");
		call(Sci_FastReset(reader, atr));
	}
	return OK;
}

static int32_t Sci_Close(struct s_reader *reader)
{
	Sci_Deactivate(reader);
	IO_Serial_Close(reader);
	NULLFREE(reader->crdr_data); //clearing allocated module mem
	NULLFREE(reader->csystem_data); //clearing allocated card system mem
	cs_sleepms(150); // some stb's needs small extra time even after close procedure seems to be ok.
	reader->handle_nr = 0;
	return OK;
}

static int32_t sci_write_settings(struct s_reader *reader, struct s_cardreader_settings *s)
{
	if(reader->cardmhz > 2000)   // only for dreambox internal pll readers clockspeed can be set precise others like vu ignore it and work always at 4.5 Mhz 
	{
		// P fixed at 5V since this is default class A card, and TB is deprecated
		if(reader->protocol_type != ATR_PROTOCOL_TYPE_T14)   // fix VU+ internal reader slow responses on T0/T1
		{
			cs_sleepms(150);
			call(Sci_WriteSettings(reader, 0, reader->divider, s->ETU, s->WWT, reader->CWT, reader->BWT, s->EGT, 5, (unsigned char)s->I));
			cs_sleepms(150);
		}
		else     // no fixup for T14 protocol otherwise error
		{
			cs_sleepms(150);
			call(Sci_WriteSettings(reader, reader->protocol_type, reader->divider, s->ETU, s->WWT, reader->CWT, reader->BWT, s->EGT, 5, (unsigned char)s->I));
			cs_sleepms(150);
		}
	}
	else     // all other brand boxes than dreamboxes or VU+!
	{
		// P fixed at 5V since this is default class A card, and TB is deprecated
		cs_sleepms(150);
		// non pll internal reader needs base frequency like 1,2,3,4,5,6 MHz not clock rate conversion factor (Fi)
		call(Sci_WriteSettings(reader, reader->protocol_type, s->F/100, s->ETU, s->WWT, reader->CWT, reader->BWT, s->EGT, 5, (unsigned char)s->I));
		cs_sleepms(150);
	}
	return OK;
}

void cardreader_internal_sci(struct s_cardreader *crdr)
{
	crdr->desc         = "internal";
	crdr->typ          = R_INTERNAL;
	crdr->flush        = 1;
	crdr->max_clock_speed = 1;
	crdr->reader_init  = Sci_Init;
	crdr->get_status   = Sci_GetStatus;
	crdr->activate     = sci_activate;
	crdr->transmit     = IO_Serial_Transmit;
	crdr->receive      = IO_Serial_Receive;
	crdr->close        = Sci_Close;
	crdr->write_settings = sci_write_settings;
}

#endif
