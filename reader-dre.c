#include "globals.h"
#include "reader-common.h"
//#include <stdlib.h>

extern uchar cta_cmd[], cta_res[];
extern ushort cta_lr;
unsigned long long serial;
char *card;
static uchar provider;
static short int mode;

#define OK_RESPONSE 0x61
#define CMD_BYTE 0x59

#define dre_cmd(cmd) \
{ \
  	dre_command(cmd, sizeof(cmd)); \
}

int dre_set_provider_info (void)
{
  int i;
  static uchar cmd59[] = { 0x59, 0x14 };	// subscriptions
  static uchar cmd5b[] = { 0x5b, 0x00, 0x14 };	//validity dates

  cmd59[1] = provider;
  if ((dre_cmd (cmd59))) {	//ask subscription packages, returns error on 0x11 card
    uchar pbm[32];
    memcpy (pbm, cta_res + 3, cta_lr - 6);
    cs_debug ("DRECRYPT pbm: %s", cs_hexdump (0, pbm, 32));

    if (pbm[0] == 0xff)
      cs_log ("No active packages!");
    else
      for (i = 0; i < 32; i++)
	if (pbm[i] != 0xff) {
	  cmd5b[1] = i;
	  cmd5b[2] = provider;
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
	  cs_log ("Active package %i valid from %04i/%02i/%02i to %04i/%02i/%02i", i, startyear, startmonth, startday,
		  endyear, endmonth, endday);
	}
  }
  return 1;
}

uchar xor (uchar * cmd, int cmdlen)
{
  int i;
  uchar checksum = 0x00;
  for (i = 0; i < cmdlen; i++)
    checksum ^= cmd[i];
  return checksum;
}


int dre_command (uchar * cmd, int cmdlen)	//attention: inputcommand will be changed!!!! answer will be in cta_res, length cta_lr ; returning 1 = no error, return 0 = err
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
  //cs_debug ("Checksum: %02x", checksum);
  cmdlen += headerlen;
  command[cmdlen++] = checksum;

  reader_cmd2icc (command, cmdlen);

  if ((cta_lr != 2) || (cta_res[0] != OK_RESPONSE)) {
    cs_log ("DRECRYPT ERROR: unexpected answer from card: %s", cs_hexdump (0, cta_res, cta_lr));
    return 0;			//error
  }

  reqans[4] = cta_res[1];	//adapt length byte
  reader_cmd2icc (reqans, 5);

  if (cta_res[0] != CMD_BYTE) {
    cs_log ("DRECRYPT Unknown response: cta_res[0] expected to be %02x, is %02x", CMD_BYTE, cta_res[0]);
    return 0;
  }
  if ((cta_res[1] == 0x03) && (cta_res[2] == 0xe2)) {
    switch (cta_res[3]) {
    case 0xe1:
      cs_log ("DRECRYPT checksum error: %s.", cs_hexdump (0, cta_res, cta_lr));
      break;
    case 0xe2:
      cs_log ("DRECRYPT wrong provider: %s.", cs_hexdump (0, cta_res, cta_lr));
      break;
    case 0xec:
      cs_log ("DRECRYPT wrong signature: %s.", cs_hexdump (0, cta_res, cta_lr));
      break;
    default:
      cs_debug ("DRECRYPT unknown error: %s.", cs_hexdump (0, cta_res, cta_lr));
      break;
    }
    return 0;			//error
  }
  int length_excl_leader = cta_lr;
  if ((cta_res[cta_lr - 2] == 0x90) && (cta_res[cta_lr - 1] == 0x00))
    length_excl_leader -= 2;

  checksum = ~xor (cta_res + 2, length_excl_leader - 3);

  if (cta_res[length_excl_leader - 1] != checksum) {
    cs_log ("DRECRYPT checksum does not match, expected %02x received %02x:%s", checksum,
	    cta_res[length_excl_leader - 1], cs_hexdump (0, cta_res, cta_lr));
    return 0;			//error
  }
  return 1;
}

int dre_card_init (uchar * atr, int atrsize)
{
  static uchar ua[] = { 0x43, 0x15 };	// get serial number (UA)
  static uchar providers[] = { 0x49, 0x15 };	// get providers
  int i;

  if ((atr[0] != 0x3b) || (atr[1] != 0x15) || (atr[2] != 0x11) || (atr[3] != 0x12 || atr[4] != 0xca || atr[5] != 0x07))
    return (0);

  provider = atr[6];
  uchar checksum = xor (atr + 1, 6);

  if (checksum != atr[7])
    cs_log ("DRECRYPT Warning: expected ATR checksum %02x, smartcard reports %02x", checksum, atr[7]);

  switch (atr[6]) {
  case 0x11:
    card = "Tricolor Centr";
    reader[ridx].caid[0] = 0x4ae0;
    mode = 41;
    break;			//59 type card = MSP (74 type = ATMEL)
  case 0x12:
    card = "Cable TV";
    reader[ridx].caid[0] = 0x4ae0;	//TODO not sure about this one
    mode = 41;			//TODO not sure
    break;
  case 0x14:
    card = "Tricolor Syberia / Platforma HD new";
    reader[ridx].caid[0] = 0x4ae1;
    mode = 51;
    break;			//59 type card
  case 0x15:
    card = "Platforma HD / DW old";
    reader[ridx].caid[0] = 0x4ae1;
    mode = 51;
    break;			//59 type card
  default:
    card = "Unknown";
    reader[ridx].caid[0] = 0x4ae1;
    mode = 51;
    break;
  }

  memset (reader[ridx].prid, 0x00, 8);

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
  cmd54[1] = provider;
  uchar geocode = 0;
  if ((dre_cmd (cmd54)))	//error would not be fatal, like on 0x11 cards
    geocode = cta_res[3];

  providers[1] = provider;
  if (!(dre_cmd (providers)))
    return 0;			//fatal error
  if ((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
    return 0;
  uchar provname[128];
  for (i = 0; ((i < cta_res[2] - 6) && (i < 128)); i++) {
    provname[i] = cta_res[6 + i];
    if (provname[i] == 0x00)
      break;
  }
  int major_version = cta_res[3];
  int minor_version = cta_res[4];

  ua[1] = provider;
  dre_cmd (ua);			//error would not be fatal

  int hexlength = cta_res[1] - 2;	//discard first and last byte, last byte is always checksum, first is answer code

  reader[ridx].hexserial[0] = 0;
  reader[ridx].hexserial[1] = 0;
  memcpy (reader[ridx].hexserial + 2, cta_res + 3, hexlength);

  int low_dre_id = ((cta_res[4] << 16) | (cta_res[5] << 8) | cta_res[6]) - 48608;
  int dre_chksum = 0;
  uchar buf[32];
  sprintf (buf, "%i%i%08i", provider - 16, major_version + 1, low_dre_id);
  for (i = 0; i < 32; i++) {
    if (buf[i] == 0x00)
      break;
    dre_chksum += buf[i] - 48;
  }

  //cs_ri_log("type: DRECrypt, caid: %04X, serial: %llu, card: v%x",
  cs_log ("type: DRECrypt, caid: %04X, serial: %s, dre id: %i%i%i%08i, geocode %i, card: %s v%i.%i",
	  reader[ridx].caid[0], cs_hexdump (0, reader[ridx].hexserial + 2, 4), dre_chksum, provider - 16,
	  major_version + 1, low_dre_id, geocode, card, major_version, minor_version);
  cs_log ("Provider name:%s.", provname);


  memset (reader[ridx].sa, 0, sizeof (reader[ridx].sa));
  memcpy (reader[ridx].sa[0], reader[ridx].hexserial + 2, 1);	//copy first byte of unique address also in shared address, because we dont know what it is...

  cs_log ("DEBUG: SA = %02X%02X%02X%02X, UA = %s", reader[ridx].sa[0][0], reader[ridx].sa[0][1], reader[ridx].sa[0][2],
	  reader[ridx].sa[0][3], cs_hexdump (0, reader[ridx].hexserial + 2, 4));

  //reader[ridx].nprov = 1; TODO doesnt seem necessary

  if (!dre_set_provider_info ())
    return 0;			//fatal error

  cs_log ("ready for requests");
  return (1);
}

int dre_do_ecm (ECM_REQUEST * er)
{
  if (mode == 41) {
    static uchar ecmcmd41[] = { 0x41,
      0x58, 0x1f, 0x00,		//fixed part, dont change 
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,	//0x01 - 0x08: next key
      0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,	//0x11 - 0x18: current key
      0x3b, 0x59, 0x11		//0x3b = keynumber, can be a value 56 ;; 0x59 number of package = 58+1 - Pay Package ;; 0x11 = provider
    };
    ecmcmd41[22] = provider;
    memcpy (ecmcmd41 + 4, er->ecm + 8, 16);
    ecmcmd41[20] = er->ecm[6];	//keynumber
    ecmcmd41[21] = 0x58 + er->ecm[25];	//package number
    cs_debug ("DEBUG: unused ECM info front:%s", cs_hexdump (0, er->ecm, 8));
    cs_debug ("DEBUG: unused ECM info back:%s", cs_hexdump (0, er->ecm + 24, er->ecm[2] + 2 - 24));
    if ((dre_cmd (ecmcmd41))) {	//ecm request
      if ((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
	return 0;		//exit if response is not 90 00
      memcpy (er->cw, cta_res + 11, 8);
      memcpy (er->cw + 8, cta_res + 3, 8);

      return 1;
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
    cs_debug ("DEBUG: unused ECM info front:%s", cs_hexdump (0, er->ecm, 5));
    cs_debug ("DEBUG: unused ECM info back:%s", cs_hexdump (0, er->ecm + 37, 4));
    ecmcmd51[33] = provider;	//no part of sig
    if ((dre_cmd (ecmcmd51))) {	//ecm request
      if ((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
	return 0;		//exit if response is not 90 00
      memcpy (er->cw, cta_res + 11, 8);
      memcpy (er->cw + 8, cta_res + 3, 8);
      return 1;
    }
  }
  return 0;
}

int dre_do_emm (EMM_PACKET * ep)
{

  int emm_length = ((ep->emm[1] & 0x0f) << 8) + ep->emm[2];

  cs_ddump (ep->emm, emm_length + 3, "EMM:");
  ep->type = ep->emm[0];

  if (mode == 51) {
    static uchar emmcmd52[0x3a];
    emmcmd52[0] = 0x52;
    int i;
    for (i = 0; i < 2; i++) {
      memcpy (emmcmd52 + 1, ep->emm + 5 + 32 + i * 56, 56);
      emmcmd52[0x39] = provider;
      if ((dre_cmd (emmcmd52)))
	if ((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
	  return 0;		//exit if response is not 90 00
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
    memcpy (emmcmd42 + 1, ep->emm + 6, 48);
    emmcmd42[51] = provider;
    //emmcmd42[50] = ecmcmd42[2]; //TODO package nr could also be fixed 0x58
    emmcmd42[50] = 0x58;
    emmcmd42[49] = ep->emm[5];	//keynr
    /* response: 
       59 05 A2 02 05 01 5B 
       90 00 */
    if ((dre_cmd (emmcmd42))) {	//first emm request
      if ((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
	return 0;		//exit if response is not 90 00

      memcpy (emmcmd42 + 1, ep->emm + 55, 7);	//TODO OR next two lines?
      /*memcpy (emmcmd42 + 1, ep->emm + 55, 7);  //FIXME either I cant count or my EMM log contains errors
         memcpy (emmcmd42 + 8, ep->emm + 67, 41); */
      emmcmd42[51] = provider;
      //emmcmd42[50] = ecmcmd42[2]; //TODO package nr could also be fixed 0x58
      emmcmd42[50] = 0x58;
      emmcmd42[49] = ep->emm[54];	//keynr
      if ((dre_cmd (emmcmd42))) {	//second emm request
	if ((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
	  return 0;		//exit if response is not 90 00
      }
    }
  }
  return 1;			//success
}

int dre_card_info (void)
{
  return (1);
}
