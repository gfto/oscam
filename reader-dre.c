#include "globals.h"
#include "reader-common.h"

#define OK_RESPONSE 0x61
#define CMD_BYTE 0x59

static uchar xor (uchar * cmd, int cmdlen)
{
  int i;
  uchar checksum = 0x00;
  for (i = 0; i < cmdlen; i++)
    checksum ^= cmd[i];
  return checksum;
}

static int dre_command (struct s_reader * reader, uchar * cmd, int cmdlen, unsigned char * cta_res, unsigned short * p_cta_lr)	//attention: inputcommand will be changed!!!! answer will be in cta_res, length cta_lr ; returning 1 = no error, return ERROR = err
{
  static uchar startcmd[] = { 0x80, 0xFF, 0x10, 0x01, 0x05 };	//any command starts with this, 
  //last byte is nr of bytes of the command that will be sent
  //after the startcmd
//response on startcmd+cmd:     = { 0x61, 0x05 }  //0x61 = "OK", last byte is nr. of bytes card will send
  static uchar reqans[] = { 0x00, 0xC0, 0x00, 0x00, 0x08 };	//after command answer has to be requested, 
  //last byte must be nr. of bytes that card has reported to send
  uchar command[256];
  int headerlen = sizeof (startcmd);
  startcmd[4] = cmdlen + 3;	//commandlength + type + len + checksum bytes
  memcpy (command, startcmd, headerlen);
  command[headerlen++] = CMD_BYTE;	//type
  command[headerlen++] = cmdlen + 1;	//len = command + 1 checksum byte
  memcpy (command + headerlen, cmd, cmdlen);

  uchar checksum = ~xor (cmd, cmdlen);
  //cs_debug ("[dre-reader] Checksum: %02x", checksum);
  cmdlen += headerlen;
  command[cmdlen++] = checksum;

  reader_cmd2icc (reader, command, cmdlen, cta_res, p_cta_lr);

  if ((*p_cta_lr != 2) || (cta_res[0] != OK_RESPONSE)) {
    cs_log ("[dre-reader] unexpected answer from card: %s", cs_hexdump (0, cta_res, *p_cta_lr));
    return ERROR;			//error
  }

  reqans[4] = cta_res[1];	//adapt length byte
  reader_cmd2icc (reader, reqans, 5, cta_res, p_cta_lr);

  if (cta_res[0] != CMD_BYTE) {
    cs_log ("[dre-reader] unknown response: cta_res[0] expected to be %02x, is %02x", CMD_BYTE, cta_res[0]);
    return ERROR;
  }
  if ((cta_res[1] == 0x03) && (cta_res[2] == 0xe2)) {
    switch (cta_res[3]) {
    case 0xe1:
      cs_log ("[dre-reader] checksum error: %s.", cs_hexdump (0, cta_res, *p_cta_lr));
      break;
    case 0xe2:
      cs_log ("[dre-reader] wrong provider: %s.", cs_hexdump (0, cta_res, *p_cta_lr));
      break;
    case 0xe3:
      cs_log ("[dre-reader] illegal command: %s.", cs_hexdump (0, cta_res, *p_cta_lr));  
      break;
    case 0xec:
      cs_log ("[dre-reader] wrong signature: %s.", cs_hexdump (0, cta_res, *p_cta_lr));
      break;
    default:
      cs_debug ("[dre-reader] unknown error: %s.", cs_hexdump (0, cta_res, *p_cta_lr));
      break;
    }
    return ERROR;			//error
  }
  int length_excl_leader = *p_cta_lr;
  if ((cta_res[*p_cta_lr - 2] == 0x90) && (cta_res[*p_cta_lr - 1] == 0x00))
    length_excl_leader -= 2;

  checksum = ~xor (cta_res + 2, length_excl_leader - 3);

  if (cta_res[length_excl_leader - 1] != checksum) {
    cs_log ("[dre-reader] checksum does not match, expected %02x received %02x:%s", checksum,
	    cta_res[length_excl_leader - 1], cs_hexdump (0, cta_res, *p_cta_lr));
    return ERROR;			//error
  }
  return OK;
}

#define dre_cmd(cmd) \
{ \
  	dre_command(reader, cmd, sizeof(cmd),cta_res,&cta_lr); \
}

static int dre_set_provider_info (struct s_reader * reader)
{
  def_resp;
  int i;
  static uchar cmd59[] = { 0x59, 0x14 };	// subscriptions
  static uchar cmd5b[] = { 0x5b, 0x00, 0x14 };	//validity dates

  cmd59[1] = reader->provider;
  if ((dre_cmd (cmd59))) {	//ask subscription packages, returns error on 0x11 card
    uchar pbm[32];
    memcpy (pbm, cta_res + 3, cta_lr - 6);
    cs_debug ("[dre-reader] pbm: %s", cs_hexdump (0, pbm, 32));

    if (pbm[0] == 0xff)
      cs_ri_log (reader, "[dre-reader] no active packages");
    else
      for (i = 0; i < 32; i++)
	if (pbm[i] != 0xff) {
	  cmd5b[1] = i;
	  cmd5b[2] = reader->provider;
	  dre_cmd (cmd5b);	//ask for validity dates 

	  time_t start;
	  time_t end;
	  start = (cta_res[3] << 24) | (cta_res[4] << 16) | (cta_res[5] << 8) | cta_res[6];
	  end = (cta_res[7] << 24) | (cta_res[8] << 16) | (cta_res[9] << 8) | cta_res[10];

	  struct tm *temp;

	  temp = localtime (&start);
	  int startyear = temp->tm_year + 1900;
	  int startmonth = temp->tm_mon + 1;
	  int startday = temp->tm_mday;
	  temp = localtime (&end);
	  int endyear = temp->tm_year + 1900;
	  int endmonth = temp->tm_mon + 1;
	  int endday = temp->tm_mday;
	  cs_ri_log (reader, "[dre-reader] active package %i valid from %04i/%02i/%02i to %04i/%02i/%02i", i, startyear, startmonth, startday,
		  endyear, endmonth, endday);
	}
  }
  return OK;
}

int dre_card_init (struct s_reader * reader, ATR newatr)
{
	get_atr;
  def_resp;
  static uchar ua[] = { 0x43, 0x15 };	// get serial number (UA)
  static uchar providers[] = { 0x49, 0x15 };	// get providers
  int i;
	char *card;

  if ((atr[0] != 0x3b) || (atr[1] != 0x15) || (atr[2] != 0x11) || (atr[3] != 0x12 || atr[4] != 0xca || atr[5] != 0x07))
    return ERROR;

  reader->provider = atr[6];
  uchar checksum = xor (atr + 1, 6);

  if (checksum != atr[7])
    cs_log ("[dre-reader] warning: expected ATR checksum %02x, smartcard reports %02x", checksum, atr[7]);

  switch (atr[6]) {
  case 0x11:
    card = "Tricolor Centr";
    reader->caid[0] = 0x4ae0;
    break;			//59 type card = MSP (74 type = ATMEL)
  case 0x12:
    card = "Cable TV";
    reader->caid[0] = 0x4ae0;	//TODO not sure about this one
    break;
  case 0x14:
    card = "Tricolor Syberia / Platforma HD new";
    reader->caid[0] = 0x4ae1;
    break;			//59 type card
  case 0x15:
    card = "Platforma HD / DW old";
    reader->caid[0] = 0x4ae1;
    break;			//59 type card
  default:
    card = "Unknown";
    reader->caid[0] = 0x4ae1;
    break;
  }

  memset (reader->prid, 0x00, 8);

  static uchar cmd30[] =
    { 0x30, 0x81, 0x00, 0x81, 0x82, 0x03, 0x84, 0x05, 0x06, 0x87, 0x08, 0x09, 0x00, 0x81, 0x82, 0x03, 0x84, 0x05,
    0x00
  };
  dre_cmd (cmd30);		//unknown command, generates error on card 0x11 and 0x14
/*
response:
59 03 E2 E3 
FE 48 */

  static uchar cmd54[] = { 0x54, 0x14 };	// geocode
  cmd54[1] = reader->provider;
  uchar geocode = 0;
  if ((dre_cmd (cmd54)))	//error would not be fatal, like on 0x11 cards
    geocode = cta_res[3];

  providers[1] = reader->provider;
  if (!(dre_cmd (providers)))
    return ERROR;			//fatal error
  if ((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
    return ERROR;
  uchar provname[128];
  for (i = 0; ((i < cta_res[2] - 6) && (i < 128)); i++) {
    provname[i] = cta_res[6 + i];
    if (provname[i] == 0x00)
      break;
  }
  int major_version = cta_res[3];
  int minor_version = cta_res[4];

  ua[1] = reader->provider;
  dre_cmd (ua);			//error would not be fatal

  int hexlength = cta_res[1] - 2;	//discard first and last byte, last byte is always checksum, first is answer code

  reader->hexserial[0] = 0;
  reader->hexserial[1] = 0;
  memcpy (reader->hexserial + 2, cta_res + 3, hexlength);

  int low_dre_id = ((cta_res[4] << 16) | (cta_res[5] << 8) | cta_res[6]) - 48608;
  int dre_chksum = 0;
  uchar buf[32];
  sprintf ((char *)buf, "%i%i%08i", reader->provider - 16, major_version + 1, low_dre_id);
  for (i = 0; i < 32; i++) {
    if (buf[i] == 0x00)
      break;
    dre_chksum += buf[i] - 48;
  }

  //cs_ri_log("[dre-reader] type: DRE Crypt, caid: %04X, serial: %llu, card: v%x",
  cs_ri_log (reader, "[dre-reader] type: DRE Crypt, caid: %04X, serial: %s, dre id: %i%i%i%08i, geocode %i, card: %s v%i.%i",
	  reader->caid[0], cs_hexdump (0, reader->hexserial + 2, 4), dre_chksum, reader->provider - 16,
	  major_version + 1, low_dre_id, geocode, card, major_version, minor_version);
  cs_ri_log (reader, "[dre-reader] Provider name:%s.", provname);


  memset (reader->sa, 0, sizeof (reader->sa));
  memcpy (reader->sa[0], reader->hexserial + 2, 1);	//copy first byte of unique address also in shared address, because we dont know what it is...

  cs_ri_log (reader, "[dre-reader] SA = %02X%02X%02X%02X, UA = %s", reader->sa[0][0], reader->sa[0][1], reader->sa[0][2],
	  reader->sa[0][3], cs_hexdump (0, reader->hexserial + 2, 4));

  reader->nprov = 1;

  if (!dre_set_provider_info (reader))
    return ERROR;			//fatal error

  cs_log ("[dre-reader] ready for requests");
  return OK;
}

int dre_do_ecm (struct s_reader * reader, ECM_REQUEST * er)
{
  def_resp;
  if (reader->caid[0] == 0x4ae0) {
    static uchar ecmcmd41[] = { 0x41,
      0x58, 0x1f, 0x00,		//fixed part, dont change 
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,	//0x01 - 0x08: next key
      0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,	//0x11 - 0x18: current key
      0x3b, 0x59, 0x11		//0x3b = keynumber, can be a value 56 ;; 0x59 number of package = 58+1 - Pay Package ;; 0x11 = provider
    };
    ecmcmd41[22] = reader->provider;
    memcpy (ecmcmd41 + 4, er->ecm + 8, 16);
    ecmcmd41[20] = er->ecm[6];	//keynumber
    ecmcmd41[21] = 0x58 + er->ecm[25];	//package number
    cs_debug ("[dre-reader] unused ECM info front:%s", cs_hexdump (0, er->ecm, 8));
    cs_debug ("[dre-reader] unused ECM info back:%s", cs_hexdump (0, er->ecm + 24, er->ecm[2] + 2 - 24));
    if ((dre_cmd (ecmcmd41))) {	//ecm request
      if ((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
				return ERROR;		//exit if response is not 90 00
      memcpy (er->cw, cta_res + 11, 8);
      memcpy (er->cw + 8, cta_res + 3, 8);

      return OK;
    }
  }
  else {

    static uchar ecmcmd51[] = { 0x51, 0x02, 0x56, 0x05, 0x00, 0x4A, 0xE3,	//fixed header?
      0x9C, 0xDA,		//first three nibbles count up, fourth nibble counts down; all ECMs sent twice
      0xC1, 0x71, 0x21, 0x06, 0xF0, 0x14, 0xA7, 0x0E,	//next key?
      0x89, 0xDA, 0xC9, 0xD7, 0xFD, 0xB9, 0x06, 0xFD,	//current key?
      0xD5, 0x1E, 0x2A, 0xA3, 0xB5, 0xA0, 0x82, 0x11,	//key or signature?
      0x14			//provider
    };
    memcpy (ecmcmd51 + 1, er->ecm + 5, 0x21);
    cs_debug ("[dre-reader] unused ECM info front:%s", cs_hexdump (0, er->ecm, 5));
    cs_debug ("[dre-reader] unused ECM info back:%s", cs_hexdump (0, er->ecm + 37, 4));
    ecmcmd51[33] = reader->provider;	//no part of sig
    if ((dre_cmd (ecmcmd51))) {	//ecm request
      if ((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
				return ERROR;		//exit if response is not 90 00
      memcpy (er->cw, cta_res + 11, 8);
      memcpy (er->cw + 8, cta_res + 3, 8);
      return OK;
    }
  }
  return ERROR;
}

int dre_get_emm_type(EMM_PACKET *ep, struct s_reader * rdr)
{
  rdr=rdr;
  switch (ep->emm[0]) {
		case 0x87:
			ep->type = UNIQUE; //FIXME no filling of ep->hexserial
			break;
		case 0x89:
			ep->type = SHARED; //FIXME no filling of ep->hexserial
			break;
		default:
			ep->type = UNKNOWN;
	}
	return TRUE; //FIXME no checking of serial or SA
}
	

int dre_do_emm (struct s_reader * reader, EMM_PACKET * ep)
{
  def_resp;
  int emm_length = ((ep->emm[1] & 0x0f) << 8) + ep->emm[2];

  cs_ddump (ep->emm, emm_length + 3, "EMM:");
  ep->type = ep->emm[0];

  if (reader->caid[0] == 0x4ae1) {
    static uchar emmcmd52[0x3a];
    emmcmd52[0] = 0x52;
    int i;
    for (i = 0; i < 2; i++) {
      memcpy (emmcmd52 + 1, ep->emm + 5 + 32 + i * 56, 56);
      // check for shared address
      if(ep->emm[3]!=reader->sa[0][0]) 
        return OK; // ignore, wrong address
      emmcmd52[0x39] = reader->provider;
      if ((dre_cmd (emmcmd52)))
				if ((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
	  			return ERROR;		//exit if response is not 90 00
    	}
  }
  else {
    static uchar emmcmd42[] =
      { 0x42, 0x85, 0x58, 0x01, 0xC8, 0x00, 0x00, 0x00, 0x05, 0xB8, 0x0C, 0xBD, 0x7B, 0x07, 0x04, 0xC8,
      0x77, 0x31, 0x95, 0xF2, 0x30, 0xB7, 0xE9, 0xEE, 0x0F, 0x81, 0x39, 0x1C, 0x1F, 0xA9, 0x11, 0x3E,
      0xE5, 0x0E, 0x8E, 0x50, 0xA4, 0x31, 0xBB, 0x01, 0x00, 0xD6, 0xAF, 0x69, 0x60, 0x04, 0x70, 0x3A,
      0x91,
      0x56, 0x58, 0x11
    };
		int i;
		switch (ep->type) {
			case UNIQUE: 
	    	for (i = 0; i < 2; i++) {
					memcpy (emmcmd42 + 1, ep->emm + 42 + i*49, 48);
					emmcmd42[49] = ep->emm[i*49 + 41]; //keynr
					emmcmd42[50] = 0x58 + ep->emm[40]; //package nr
			    emmcmd42[51] = reader->provider;
			    if ((dre_cmd (emmcmd42))) {
			      if ((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
							return ERROR;		//exit if response is not 90 00
					}
				}
				break;
			case SHARED:
			default:
		    memcpy (emmcmd42 + 1, ep->emm + 6, 48);
		    emmcmd42[51] = reader->provider;
		    //emmcmd42[50] = ecmcmd42[2]; //TODO package nr could also be fixed 0x58
		    emmcmd42[50] = 0x58;
		    emmcmd42[49] = ep->emm[5];	//keynr
		    /* response: 
		       59 05 A2 02 05 01 5B 
		       90 00 */
		    if ((dre_cmd (emmcmd42))) {	//first emm request
		      if ((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
						return ERROR;		//exit if response is not 90 00
		
		      memcpy (emmcmd42 + 1, ep->emm + 55, 7);	//TODO OR next two lines?
		      /*memcpy (emmcmd42 + 1, ep->emm + 55, 7);  //FIXME either I cant count or my EMM log contains errors
		         memcpy (emmcmd42 + 8, ep->emm + 67, 41); */
		      emmcmd42[51] = reader->provider;
		      //emmcmd42[50] = ecmcmd42[2]; //TODO package nr could also be fixed 0x58
		      emmcmd42[50] = 0x58;
		      emmcmd42[49] = ep->emm[54];	//keynr
		      if ((dre_cmd (emmcmd42))) {	//second emm request
						if ((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
							return ERROR;		//exit if response is not 90 00
		      }
		    }
		}
  }
  return OK;			//success
}

int dre_card_info (void)
{
  return OK;
}
