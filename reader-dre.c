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
    reader[ridx].caid[0] = 0x4ae1;	//TODO not sure
    mode = 41;			//TODO not sure
    break;			//59 type card
  default:
    card = "Unknown";
    reader[ridx].caid[0] = 0x4ae1;	//TODO: what is sensible value here?
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


  /* Unknown function 51
     59 
     23 51 82 3B 05 00 4A D4 CA 
     A3 1D A2 
     DF 95 29 90 65 E1 95 B8 1C 91 87 C8 B5 CB 62 2F 
     09 
     F7 BC 18 BA 14  some byte seems to be missing !?!

     ANOTHER INS is the same except last line:
     EF C7 1D 4C E3 14 last byte stays the same = provider byte???

     response: DW info retour
     59 12 D2 8E 7A FE BA 6C DF 31 49 
     1A 8F 34 
     98 48 42 CE 0D DE 
     90 00 */


  //memcpy(&reader[ridx].prid[i][2], cta_res, 2); 

//############### PLAYGROUND ////

//from bbs, provider = 15???
//static uchar ecmtest[] = { 0x51, 0x01, 0x56, 0x00, 0x00, 0x48, 0xC6, 0xF0, 0x19, 0x01, 0xD4, 0xDF, 0x4F, 0xD7, 0x91, 0x55, 0x68, 0x02, 0x72, 0xF7, 0x98, 0x28, 0xBD, 0x78, 0x8E, 0x4E, 0xE8, 0xED, 0x0B, 0x51, 0xBF, 0xA4, 0x4E, 0x15 };
//from log, works:
//static uchar ecmtest[] = { 0x51, 0x02, 0x56, 0x05, 0x00, 0x4A, 0xE3, 0x9C, 0xDA, 0xC1, 0x71, 0x21, 0x06, 0xF0, 0x14, 0xA7, 0x0E, 0x89, 0xDA, 0xC9, 0xD7, 0xFD, 0xB9, 0x06, 0xFD, 0xD5, 0x1E, 0x2A, 0xA3, 0xB5, 0xA0, 0x82, 0x11, 0x14 };
/*  static uchar ecmtest[] =
    { 0x51, 0x03, 0x56, 0x05, 0x00, 0x4A, 0xE4, 0x58, 0x02, 0x8B, 0xAE, 0x42, 0xEE, 0xE2, 0x6A, 0x7F, 0x51, 0xE0, 0x7D,
0xCE, 0x20, 0x8A, 0x24, 0xE8, 0xBA, 0xA6, 0xC3, 0xCB, 0x35, 0x45, 0x35, 0x52, 0x94, 0x14 };
*/
//from platforma itself through dvbviewer
/*
  static uchar ecmtest[] =
    { 0x51, 0x02, 0x56, 0x00, 0x00, 0x4A, 0xEC, 0x00, 0xAA, 0x31, 0x39, 0x06, 0x57, 0x94, 0x55, 0x1D, 0x23, 0x52, 0x88, 
0x3D, 0xA8, 0x62, 0xDC, 0xA2, 0x98, 0xD7, 0xAB, 0x0D, 0x80, 0x60, 0x15, 0xF5, 0x07, 0x14 };
*/
  //from redirected dvbviewer
  static uchar ecmtest[] =
    { 0x51, 0x02, 0x56, 0x00, 0x00, 0x4A, 0xEC, 0x3B, 0xF6, 0x56, 0x5A, 0x43, 0x95, 0x43, 0x05, 0x02, 0xBB, 0x46, 0x22,
    0x27, 0xEF, 0x33, 0xF4, 0xA9, 0xD0, 0x65, 0xDB, 0x57, 0x8F, 0x8F, 0x7C, 0x19, 0x36, 0x14
  };

//rest: 0x93, 0x36, 0x58, 0xC9


  //ecmcmd51[33]=provider; //FIXME part of signatur 

//int hans, index, save;
//for (index=1; index<3; index++) {
//  save = ecmtest[index];
//  for (hans=0; hans<256; hans++) {
//   ecmtest[index] = hans;
//    if ((dre_cmd(ecmtest)))
//      cs_log("HANS SUCCESS");
//  }
//  ecmtest[index] = save;
//}

  EMM_PACKET *eptmp;
  eptmp = malloc (sizeof (EMM_PACKET));
//  static unsigned char tempser[] = { 0, 0, 0xC8, 0x4D, 0x25, 0x5A };
//  memcpy (reader[ridx].hexserial, tempser, 8);
  dre_do_emm (eptmp);
  free (eptmp);
//############### PLAYGROUND ////
  cs_log ("ready for requests");
  return (1);
}

/*
static int get_prov_index (char *provid)	//returns provider id or -1 if not found
{
  int prov;
  for (prov = 0; prov < reader[ridx].nprov; prov++)	//search for provider index
    if (!memcmp (provid, &reader[ridx].prid[prov][2], 2))
      return (prov);
  return (-1);
}
*/

int dre_do_ecm (ECM_REQUEST * er)
{
  //
  //cmd41 is not known for card provider 0x14 ???
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
	return (0);		//exit if response is not 90 00 //TODO: if response is 9027 ppv mode is possible!
      //memcpy(er->cw,cta_res+3,16); 
      //or swap bytes: 
      memcpy (er->cw, cta_res + 11, 8);
      memcpy (er->cw + 8, cta_res + 3, 8);

      //  return 0; //FIXME only used for testing CWs
      return 1;
    }
  }
  else {

    //cmd51 is used for provider 0x14
    static uchar ecmcmd51[] = { 0x51, 0x02, 0x56, 0x05, 0x00, 0x4A, 0xE3,	//fixed header?
      0x9C, 0xDA,		//first three nibbles count up, fourth nibble counts down; all ECMs sent twice
      0xC1, 0x71, 0x21, 0x06, 0xF0, 0x14, 0xA7, 0x0E,	//next key?
      0x89, 0xDA, 0xC9, 0xD7, 0xFD, 0xB9, 0x06, 0xFD,	//current key?
      0xD5, 0x1E, 0x2A, 0xA3, 0xB5, 0xA0, 0x82, 0x11,	//key or signature?
      0x14			//provider
    };
    memcpy (ecmcmd51 + 1, er->ecm + 5, 0x21);
    //cs_log ("DEBUG: ECM: %s", cs_hexdump (0, er->ecm, er->ecm[2] + 3));
    cs_debug ("DEBUG: unused ECM info front:%s", cs_hexdump (0, er->ecm, 5));
    cs_debug ("DEBUG: unused ECM info back:%s", cs_hexdump (0, er->ecm + 37, 4));
    ecmcmd51[33] = provider;	//no part of sig
    if ((dre_cmd (ecmcmd51))) {	//ecm request
      if ((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
	return (0);		//exit if response is not 90 00 //TODO: if response is 9027 ppv mode is possible!
      //memcpy(er->cw,cta_res+3,16); 
      //or swap bytes: 
      memcpy (er->cw, cta_res + 11, 8);
      memcpy (er->cw + 8, cta_res + 3, 8);

      //  return 0; //FIXME only used for testing CWs
      return 1;
    }
  }
  return 0;
}

int dre_do_emm (EMM_PACKET * ep)
{
  //return 0;                   //FIXME STUB
  /*
  uchar emmtest[] = { 0x87, 0x00, 0x8C, 0xC8, 0x4D, 0x25, 0x5A, 0x02, 0xA9, 0xA5, 0x34, 0x31, 0xAB, 0x9C, 0x9B, 0x59,
    0x5D, 0x47, 0x95, 0xB3, 0xB1, 0x61, 0x47, 0xE6, 0x85, 0xE0, 0x17, 0xC8, 0x25, 0x70, 0x59, 0x73,
    0x12, 0x1F, 0x2B, 0x9B, 0x02, 0x5A, 0x9D, 0x3A, 0x05, 0x56, 0x85, 0x58, 0x00, 0xC8, 0x4D, 0x25,
    0x5A, 0x06, 0x02, 0x23, 0xB4, 0x37, 0x1E, 0xE0, 0x7E, 0x59, 0xFC, 0x38, 0xCA, 0x13, 0x21, 0x0D,
    0x3E, 0x09, 0xDF, 0xB4, 0x45, 0x6C, 0x99, 0x7E, 0x3E, 0xDA, 0xA4, 0xC7, 0xB9, 0x7B, 0xAB, 0x4A,
    0xB5, 0xE2, 0x1D, 0xA3, 0xCD, 0x03, 0xAF, 0xDA, 0xBA, 0xEA, 0x3B, 0x85, 0x58, 0x00, 0xC8, 0x4D,
    0x25, 0x5A, 0x05, 0xF4, 0xAF, 0x8B, 0x8F, 0x2F, 0x6C, 0xF2, 0x43, 0x8C, 0x86, 0x03, 0xFD, 0x1C,
    0xDF, 0x7A, 0xE4, 0xB6, 0x0B, 0xF9, 0x70, 0x72, 0xFC, 0x2A, 0xEC, 0x0F, 0x6D, 0x8D, 0x82, 0xC6,
    0x4C, 0x16, 0x81, 0xDC, 0xC9, 0x3C, 0x34, 0x84, 0x35, 0x9A, 0xA7, 0xED, 0xB1, 0x39, 0xBC
  }; //UNIQE EMM
*/

  uchar emmtest[] = { 0x89, 0x00, 0x68, 0x00, 0x4D, 0x56, 0x85, 0x58, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x29, 0x58,
    0x89, 0x04, 0x3A, 0xEE, 0x15, 0xB1, 0x38, 0x4A, 0x75, 0x5A, 0x21, 0xEE, 0x4D, 0x37, 0xF3, 0x53,
    0xF8, 0xAC, 0x1F, 0x8D, 0xEA, 0xDF, 0x12, 0x73, 0x00, 0x69, 0xBB, 0x67, 0x5D, 0x8A, 0x96, 0x2D,
    0x1C, 0x08, 0xEB, 0xF1, 0xCA, 0x40, 0x3B, 0x85, 0x58, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0x85,
    0xF2, 0xE1, 0xD9, 0x86, 0xEA, 0x19, 0x6A, 0xEF, 0x3B, 0x9D, 0x0C, 0xEA, 0xF3, 0x7B, 0x74, 0xE5,
    0xF7, 0x4F, 0xD6, 0x9C, 0x85, 0x6C, 0x7E, 0x79, 0xDF, 0x18, 0xD1, 0xC3, 0x54, 0xA9, 0x47, 0xCB,
    0xAC, 0xB6, 0x18, 0x71, 0xC8, 0x69, 0x6B, 0x10, 0xFF, 0x9D, 0x11 }; //GLOBAL EMM

  memcpy (ep->emm, emmtest, 0x8f);

  int emm_length = ((ep->emm[1] & 0x0f) << 8) + ep->emm[2];

  cs_ddump (ep->emm, emm_length + 3, "EMM:");
  ep->type = ep->emm[0];
  cs_debug ("ep->type%x", ep->type);

  if (mode != 41) {
    cs_log ("EMM Mode not implemented yet");
    return 0;
  }

  static uchar emmcmd42[] =
    { 0x42, 0x85, 0x58, 0x01, 0xC8, 0x00, 0x00, 0x00, 0x05, 0xB8, 0x0C, 0xBD, 0x7B, 0x07, 0x04, 0xC8,
    0x77, 0x31, 0x95, 0xF2, 0x30, 0xB7, 0xE9, 0xEE, 0x0F, 0x81, 0x39, 0x1C, 0x1F, 0xA9, 0x11, 0x3E,
    0xE5, 0x0E, 0x8E, 0x50, 0xA4, 0x31, 0xBB, 0x01, 0x00, 0xD6, 0xAF, 0x69, 0x60, 0x04, 0x70, 0x3A,
    0x91,
    0x56, 0x58, 0x11
  };

  switch (ep->type) {
  case 0x88:			//shared EMM
    {
      cs_debug ("HANS: checkpoint 1");
      if (memcmp (ep->emm + 9, reader[ridx].sa[0], 1)) {	//in case of SHARED EMM, only first byte has to match?
	cs_log ("EMM: Shared update did not match; EMM SA:%02X%02X%02X%02X, Reader SA:%s.", ep->emm[9], ep->emm[10],
		ep->emm[11], ep->emm[12], cs_hexdump (0, reader[ridx].sa[0], 4));
	return (0);
      }
      else {
	cs_log ("EMM: Shared update matched for EMM SA %02X%02X%02X%02X.", ep->emm[9], ep->emm[19], ep->emm[11],
		ep->emm[12]);
      }
      /*
         01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16
         88 00 68 C8 4D 56 85 58 01 C8 00 00 00 05 B8 0C 

         17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 -- 
         BD 7B 07 04 C8 77 31 95 F2 30 B7 E9 EE 0F 81 39 

         33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 -- 
         1C 1F A9 11 3E E5 0E 8E 50 A4 31 BB 01 00 D6 AF 

         49 50 51 52 53 54X55 56 57 58 59 60 61 62 63 64 -- 
         69 60 04 70 3A 91 3B 85 58 01 C8 00 00 00 05 B1 

         65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 -- 
         3F BF A0 05 6E BD AB 0A 70 77 30 C2 AC EC 06 C2 

         81 82 83 84 85 86 87 88 89 90 91 92 93 94 95 96 -- 
         3D 47 50 8D B1 77 68 62 6B 26 6B CE A9 EF 1B 6A 

         97 98 99 00 01 02 03 04 05 06 07 08 09 10 11 12 -- 
         DF 7B 39 52 A4 5A 0E B0 A6 ED 7B DC 82 3C AE A3 

         Here we have: 

         Bytes ... 
         01 (88) - EMM filter can be a value 87 
         03 (68) - length of data EMM 
         04 (C8) - the number of SA for the filter (C8 - is a map) 
         06 (56) - index kriptodannyh (56/3B alternate) are likely key number 

         07 (85) - choice of algorithm (8x - MSP / 4x - Atmel), in the cards until only 85 
         08 (01) - the type of EMM (00 - EMM_U, solo / 01 - EMM_S, group) 
         10 - 13 (C8 00 00 00) - here only for SA EMM_S 
         14 (05) - additional flags 
         15 - 54 (V8. .. 91) own body EMM, information about the key.
         55 (3B) may be a checksum. 

         Bytes 56 - 104 - for the second key. 
         Appointment of the remaining bytes is unknown. 
       */
    }				// end shared EMM NO BREAK so rest happens in global EMM
  case 0x89:			//global EMM ??
    {
      if (ep->type == 0x89)
	cs_log ("EMM: Global update");
      /* 89 00 68 00 4D 56 85 58 01 00 00 00 00 06 29 58
       * 89 04 3A EE 15 B1 38 4A 75 5A 21 EE 4D 37 F3 53
       * F8 AC 1F 8D EA DF 12 73 00 69 BB 67 5D 8A 96 2D
       * 1C 08 EB F1 CA 40X3BX85 58 01 00 00 00 00 05 85
       * F2 E1 D9 86 EA 19 6A EF 3B 9D 0C EA F3 7B 74 E5
       * F7 4F D6 9C 85 6C 7E 79 DF 18 D1 C3 54 A9 47 CB
       * AC B6 18 71 C8 69 6B 10 FF 9D 11 
       */
      memcpy (emmcmd42 + 1, ep->emm + 6, 48);
      emmcmd42[51] = provider;
      //emmcmd42[50] = ecmcmd42[2]; //TODO package nr could also be fixed 0x58
      emmcmd42[49] = ep->emm[5];	//keynr
      /* response: 
         59 05 A2 02 05 01 5B 
         90 00 */
      cs_debug ("HANS: checkpoint 5");
      if ((dre_cmd (emmcmd42))) {	//first emm request
	if ((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
	  return (0);		//exit if response is not 90 00

	cs_debug ("HANS: checkpoint 6");
	memcpy (emmcmd42 + 1, ep->emm + 55, 7);
	memcpy (emmcmd42 + 8, ep->emm + 67, 41);
	emmcmd42[51] = provider;
	//emmcmd42[50] = ecmcmd42[2]; //TODO package nr could also be fixed 0x58
	emmcmd42[49] = ep->emm[54];	//keynr
	if ((dre_cmd (emmcmd42))) {	//second emm request
	  if ((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
	    return (0);		//exit if response is not 90 00
	  return 1;		//success
	}
      }

      break;
    }				//end global EMM
  case 0x87:			//unique EMM
    {
      /*
         0x87, 0x00, 0x8C, ser1, ser2, ser3, ser4, 0x02, 0xA9, 0xA5, 0x34, 0x31, 0xAB, 0x9C, 0x9B, 0x59,
         0x5D, 0x47, 0x95, 0xB3, 0xB1, 0x61, 0x47, 0xE6, 0x85, 0xE0, 0x17, 0xC8, 0x25, 0x70, 0x59, 0x73,
         0x12, 0x1F, 0x2B, 0x9B, 0x02, 0x5A, 0x9D, 0x3A, 0x05, 0x56, 0x85, 0x58, 0x00, 0xC8, 0x4D, 0x25,
         0x5A, 0x06, 0x02, 0x23, 0xB4, 0x37, 0x1E, 0xE0, 0x7E, 0x59, 0xFC, 0x38, 0xCA, 0x13, 0x21, 0x0D,
         0x3E, 0x09, 0xDF, 0xB4, 0x45, 0x6C, 0x99, 0x7E, 0x3E, 0xDA, 0xA4, 0xC7, 0xB9, 0x7B, 0xAB, 0x4A,
         0xB5, 0xE2, 0x1D, 0xA3, 0xCD, 0x03, 0xAF, 0xDA, 0xBA, 0xEA, 0x3B, 0x85, 0x58, 0x00, 0xC8, 0x4D,
         0x25, 0x5A, 0x05, 0xF4, 0xAF, 0x8B, 0x8F, 0x2F, 0x6C, 0xF2, 0x43, 0x8C, 0x86, 0x03, 0xFD, 0x1C,
         0xDF, 0x7A, 0xE4, 0xB6, 0x0B, 0xF9, 0x70, 0x72, 0xFC, 0x2A, 0xEC, 0x0F, 0x6D, 0x8D, 0x82, 0xC6,
         0x4C, 0x16, 0x81, 0xDC, 0xC9, 0x3C, 0x34, 0x84, 0x35, 0x9A, 0xA7, 0xED, 0xB1, 0x39, 0xBC
       */
      cs_debug ("HANS: checkpoint 2");
      //first test if UA matches
      if (memcmp (reader[ridx].hexserial + 2, ep->emm + 3, 4)) {
	cs_log ("EMM: Unique update did not match; EMM Serial:%02X%02X%02X%02X, Reader Serial:%s.", ep->emm[3],
		ep->emm[4], ep->emm[5], ep->emm[6], cs_hexdump (0, reader[ridx].hexserial + 2, 4));
	return (0);
      }
      else {
	cs_log ("EMM: Unique update matched EMM Serial:%02X%02X%02X%02X.", ep->emm[3], ep->emm[4], ep->emm[5],
		ep->emm[6]);
	cs_log ("EMM: layout of EMM 0x87 unknown, cannot be processed yet.");
      }
      break;
    }				//end unique EMM
  default:
    cs_log
      ("EMM: Congratulations, you have discovered a new EMM type on DRECRYPT. This has not been decoded yet, so send this output to authors:");
    cs_dump (ep->emm, emm_length + 3, "EMM:");
    return 0;			//unknown
  }				//end of switch


  cs_debug ("HANS: checkpoint 3");
  return 0;
}

int dre_card_info (void)
{
  return (1);
}
