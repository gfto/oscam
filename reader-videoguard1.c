#include "globals.h"
#include "reader-common.h"
#include "reader-videoguard-common.h"


static int vg1_do_cmd(struct s_reader *reader, const unsigned char *ins, const unsigned char *txbuff, unsigned char *rxbuff, unsigned char *cta_res)
{
  ushort cta_lr;
  unsigned char ins2[5];
  memcpy(ins2, ins, 5);
  unsigned char len = 0;
  len = ins2[4];

  unsigned char tmp[264];
  if (!rxbuff) {
    rxbuff = tmp;
  }

  if (txbuff == NULL) {
    if (!write_cmd_vg(ins2, NULL) || !status_ok(cta_res + len)) {
      return -1;
    }
    memcpy(rxbuff, ins2, 5);
    memcpy(rxbuff + 5, cta_res, len);
    memcpy(rxbuff + 5 + len, cta_res + len, 2);
  } else {
    if (!write_cmd_vg(ins2, (uchar *) txbuff) || !status_ok(cta_res)) {
      return -2;
    }
    memcpy(rxbuff, ins2, 5);
    memcpy(rxbuff + 5, txbuff, len);
    memcpy(rxbuff + 5 + len, cta_res, 2);
  }

  return len;
}

static void read_tiers(struct s_reader *reader)
{
  def_resp;
//  const unsigned char ins2a[5] = {  0x48, 0x2a, 0x00, 0x00, 0x00  };
  int l;

//  return; // Not working at present so just do nothing

//  l = vg1_do_cmd(reader, ins2a, NULL, NULL, cta_res);
//  if (l < 0 || !status_ok(cta_res + l))
//  {
//    return;
//  }
  unsigned char ins76[5] = { 0x48, 0x76, 0x00, 0x00, 0x00 };
  ins76[3] = 0x7f;
  ins76[4] = 2;
  if (!write_cmd_vg(ins76, NULL) || !status_ok(cta_res + 2)) {
    return;
  }
  ins76[3] = 0;
  ins76[4] = 0x0a;
  int num = cta_res[1];
  int i;

  for (i = 0; i < num; i++) {
    ins76[2] = i;
    l = vg1_do_cmd(reader, ins76, NULL, NULL, cta_res);
    if (l < 0 || !status_ok(cta_res + l)) {
      return;
    }
    if (cta_res[2] == 0 && cta_res[3] == 0) {
      break;
    }
    int y, m, d, H, M, S;
    rev_date_calc(&cta_res[4], &y, &m, &d, &H, &M, &S, reader->card_baseyear);
    unsigned short tier_id = (cta_res[2] << 8) | cta_res[3];
    char *tier_name = get_tiername(tier_id, reader->caid);
    cs_ri_log(reader, "[videoguard1-reader] tier: %04x, expiry date: %04d/%02d/%02d-%02d:%02d:%02d %s", tier_id, y, m, d, H, M, S, tier_name);
  }
}

static int videoguard1_card_init(struct s_reader *reader, ATR newatr)
{

  get_hist;
  /* 40 B0 09 4A 50 01 4E 5A */
  if ((hist_size < 7) || (hist[1] != 0xB0) || (hist[3] != 0x4A) || (hist[4] != 0x50)) {
    return ERROR;
  }

  get_atr;
  def_resp;

  /* set information on the card stored in reader-videoguard-common.c */
  set_known_card_info(reader,atr,&atr_size);

  if((reader->ndsversion != NDS1) && ((reader->card_system_version != NDS1) || (reader->ndsversion != NDSAUTO))) {
    /* known ATR and not NDS1
       or unknown ATR and not forced to NDS1
       or known NDS1 ATR and forced to another NDS version
       ... probably not NDS1 */
    return ERROR;
  }

  cs_ri_log(reader, "[videoguard1-reader] type: %s, baseyear: %i", reader->card_desc, reader->card_baseyear);
  if(reader->ndsversion == NDS1){
    cs_log("[videoguard1-reader] forced to NDS1+");
  }

  /* NDS1 Class 48 only cards only need a very basic initialisation
     NDS1 Class 48 only cards do not respond to vg1_do_cmd(ins7416)
     nor do they return list of valid command therefore do not even try
     NDS1 Class 48 only cards need to be told the length as (48, ins, 00, 80, 01) 
     does not return the length */

  int l = 0;
  unsigned char buff[256];

  /* Try to get the boxid from the card, even if BoxID specified in the config file
     also used to check if it is an NDS1 card as the returned information will
     not be encrypted if it is an NDS1 card */

  static const unsigned char ins36[5] = { 0x48, 0x36, 0x00, 0x00, 0x90 };
  unsigned char boxID[4];
  int boxidOK = 0;
  l = vg1_do_cmd(reader, ins36, NULL, buff, cta_res);
  if (buff[7] > 0x0F) {
    cs_log("[videoguard1-reader] class48 ins36: encrypted - therefore not an NDS1 card");
    return ERROR;
  } else {
    /* skipping the initial fixed fields: cmdecho (4) + length (1) + encr/rev++ (4) */
    int i = 9;
    int gotUA = 0;
    while (i < l) {
      if (!gotUA && buff[i] < 0xF0) {	/* then we guess that the next 4 bytes is the UA */
	gotUA = 1;
	i += 4;
      } else {
	switch (buff[i]) {	/* object length vary depending on type */
	case 0x00:		/* padding */
	  {
	    i += 1;
	    break;
	  }
	case 0xEF:		/* card status */
	  {
	    i += 3;
	    break;
	  }
	case 0xD1:
	  {
	    i += 4;
	    break;
	  }
	case 0xDF:		/* next server contact */
	  {
	    i += 5;
	    break;
	  }
	case 0xF3:		/* boxID */
	  {
	    memcpy(&boxID, &buff[i + 1], sizeof(boxID));
	    boxidOK = 1;
	    i += 5;
	    break;
	  }
	case 0xF6:
	  {
	    i += 6;
	    break;
	  }
	case 0xFC:		/* No idea seems to with with NDS1 */
	  {
	    i += 14;
	    break;
	  }
	case 0x01:		/* date & time */
	  {
	    i += 7;
	    break;
	  }
	case 0xFA:
	  {
	    i += 9;
	    break;
	  }
	case 0x5E:
	case 0x67:		/* signature */
	case 0xDE:
	case 0xE2:
	case 0xE9:		/* tier dates */
	case 0xF8:		/* Old PPV Event Record */
	case 0xFD:
	  {
	    i += buff[i + 1] + 2;	/* skip length + 2 bytes (type and length) */
	    break;
	  }
	default:		/* default to assume a length byte */
	  {
	    cs_log("[videoguard1-reader] class48 ins36: returned unknown type=0x%02X - parsing may fail", buff[i]);
	    i += buff[i + 1] + 2;
	  }
	}
      }
    }
  }

  // cs_log("[videguard1nz-reader] calculated BoxID: %02X%02X%02X%02X", boxID[0], boxID[1], boxID[2], boxID[3]);

  /* the boxid is specified in the config */
  if (reader->boxid > 0) {
    int i;
    for (i = 0; i < 4; i++) {
      boxID[i] = (reader->boxid >> (8 * (3 - i))) % 0x100;
    }
    // cs_log("[videguard1nz-reader] config BoxID: %02X%02X%02X%02X", boxID[0], boxID[1], boxID[2], boxID[3]);
  }

  if (!boxidOK) {
    cs_log("[videoguard1-reader] no boxID available");
    return ERROR;
  } 

  // Send BoxID
  static const unsigned char ins4C[5] = { 0x48, 0x4C, 0x00, 0x00, 0x09 };
  unsigned char payload4C[9] = { 0, 0, 0, 0, 3, 0, 0, 0, 4 };
  memcpy(payload4C, boxID, 4);
  if (!write_cmd_vg(ins4C, payload4C) || !status_ok(cta_res + l)) {
    cs_log("[videoguard1-reader] class48 ins4C: sending boxid failed");
    return ERROR;
  }

  static const unsigned char ins58[5] = { 0x48, 0x58, 0x00, 0x00, 0x17 };
  l = vg1_do_cmd(reader, ins58, NULL, buff, cta_res);
  if (l < 0) {
    cs_log("[videoguard1-reader] class48 ins58: failed");
    return ERROR;
  }

  memset(reader->hexserial, 0, 8);
  memcpy(reader->hexserial + 2, cta_res + 1, 4);
  memcpy(reader->sa, cta_res + 1, 3);
  //  reader->caid = cta_res[24] * 0x100 + cta_res[25];
  /* Force caid until can figure out how to get it */
  reader->caid = 0x9 * 0x100 + 0x69;

  /* we have one provider, 0x0000 */
  reader->nprov = 1;
  memset(reader->prid, 0x00, sizeof(reader->prid));

  cs_ri_log(reader,
	    "[videoguard1-reader] type: VideoGuard, caid: %04X, serial: %02X%02X%02X%02X, BoxID: %02X%02X%02X%02X",
	    reader->caid, reader->hexserial[2], reader->hexserial[3], reader->hexserial[4], reader->hexserial[5], boxID[0], boxID[1], boxID[2], boxID[3]);
  cs_log("[videoguard1-reader] ready for requests - this is in testing please send -d 255 logs");

  return OK;
}

static int videoguard1_do_ecm(struct s_reader *reader, ECM_REQUEST * er)
{
  unsigned char cta_res[CTA_RES_LEN];
  unsigned char ins40[5] = { 0x48, 0x40, 0x00, 0x80, 0xFF };
  static const unsigned char ins54[5] = { 0x48, 0x54, 0x00, 0x00, 0x0D };
  int posECMpart2 = er->ecm[6] + 7;
  int lenECMpart2 = er->ecm[posECMpart2];
  unsigned char tbuff[264];
  unsigned char rbuff[264];
  memcpy(&tbuff[0], &(er->ecm[posECMpart2 + 1]), lenECMpart2 - 1);
  ins40[4] = lenECMpart2;
  int l;
  l = vg1_do_cmd(reader, ins40, tbuff, NULL, cta_res);
  if (l > 0 && status_ok(cta_res)) {
    l = vg1_do_cmd(reader, ins54, NULL, rbuff, cta_res);
    if (l > 0 && status_ok(cta_res + l)) {
      if (!cw_is_valid(rbuff+5,0))    //sky cards report 90 00 = ok but send cw = 00 when channel not subscribed
      {
        cs_log("[videoguard1-reader] class48 ins54 status 90 00 but cw=00 -> channel not subscribed");
        return ERROR;
      }

      if(er->ecm[0]&1) {
        memset(er->cw+0, 0, 8);
        memcpy(er->cw+8, rbuff + 5, 8);
      } else {
        memcpy(er->cw+0, rbuff + 5, 8);
        memset(er->cw+8, 0, 8);
      }
      return OK;
    }
  }
  cs_log("[videoguard1-reader] class48 ins54 (%d) status not ok %02x %02x", l, cta_res[0], cta_res[1]);
  return ERROR;
}

static int videoguard1_do_emm(struct s_reader *reader, EMM_PACKET * ep)
{
   return videoguard_do_emm(reader, ep, 0x48, read_tiers);
}

static int videoguard1_card_info(struct s_reader *reader)
{
  /* info is displayed in init, or when processing info */
  cs_log("[videoguard1-reader] card detected");
  cs_log("[videoguard1-reader] type: %s", reader->card_desc);
  read_tiers(reader);
  return OK;
}

void reader_videoguard1(struct s_cardsystem *ph) 
{
	ph->do_emm=videoguard1_do_emm;
	ph->do_ecm=videoguard1_do_ecm;
	ph->card_info=videoguard1_card_info;
	ph->card_init=videoguard1_card_init;
	ph->get_emm_type=videoguard_get_emm_type;
	ph->get_emm_filter=videoguard_get_emm_filter;
	ph->caids[0]=0x09;
	ph->desc="videoguard1";
}
