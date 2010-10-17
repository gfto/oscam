#include "globals.h"
#include "reader-common.h"
#include "reader-videoguard-common.h"

// Redefine logging funtion to include reader name
#define cs_log(x...)  cs_log("[videoguard12-reader] "x)
#define cs_ri_log(x,y...)  cs_ri_log(x,"[videoguard12-reader] "y)
#ifdef WITH_DEBUG
  #define cs_debug(x...)  cs_debug("[videoguard12-reader] "x)
  #define cs_debug_mask(x,y...) cs_debug_mask(x,"[videoguard12-reader] "y)
#endif

static int vg12_do_cmd(struct s_reader * reader, const unsigned char *ins, const unsigned char *txbuff, unsigned char *rxbuff,
           unsigned char * cta_res)
{
  ushort cta_lr;
  unsigned char ins2[5];
  memcpy(ins2,ins,5);
  unsigned char len=0, mode=0;

  if(cmd_table_get_info(reader,ins2,&len,&mode)) {
    if(len==0xFF && mode==2) {
      if(ins2[4]==0) ins2[4]=len=read_cmd_len(reader,ins2);
      }
    else if(mode!=0) ins2[4]=len;
    }

  len=ins2[4];

  unsigned char tmp[264];
  if(!rxbuff) rxbuff=tmp;
  if(mode>1) {
    if(!write_cmd_vg(ins2,NULL) || !status_ok(cta_res+len)) return -1;
    memcpy(rxbuff,ins2,5);
    memcpy(rxbuff+5,cta_res,len);
    memcpy(rxbuff+5+len,cta_res+len,2);
    }
  else {
    if(!write_cmd_vg(ins2,(uchar *)txbuff) || !status_ok(cta_res)) return -2;
    memcpy(rxbuff,ins2,5);
    memcpy(rxbuff+5,txbuff,len);
    memcpy(rxbuff+5+len,cta_res,2);
    }

  return len;
}

static void read_tiers(struct s_reader * reader)
{
  def_resp;
  static const unsigned char ins2a[5] = { 0x48,0x2a,0x00,0x00,0x00 };
  int l;
  l=vg12_do_cmd(reader,ins2a,NULL,NULL,cta_res);
  if(l<0 || !status_ok(cta_res+l)) return;
  unsigned char ins76[5] = { 0x48,0x76,0x00,0x00,0x00 };
  ins76[3]=0x7f; ins76[4]=2;
  if(!write_cmd_vg(ins76,NULL) || !status_ok(cta_res+2)) return;
  ins76[3]=0; ins76[4]=0;
  int num=cta_res[1];
  int i;

  for(i=0; i<num; i++) {
    ins76[2]=i;
    l=vg12_do_cmd(reader,ins76,NULL,NULL,cta_res);
    if(l<0 || !status_ok(cta_res+l)) return;
    if(cta_res[2]==0 && cta_res[3]==0) break;
    int y,m,d,H,M,S;
    rev_date_calc(&cta_res[4],&y,&m,&d,&H,&M,&S,reader->card_baseyear);
    unsigned short tier_id = (cta_res[2] << 8) | cta_res[3];
    char *tier_name = get_tiername(tier_id, reader->caid[0]);
    cs_ri_log(reader, "tier: %04x, expiry date: %04d/%02d/%02d-%02d:%02d:%02d %s",tier_id,y,m,d,H,M,S,tier_name);
    }
}

static int videoguard12_card_init(struct s_reader * reader, ATR newatr)
{

  get_hist;
  if ((hist_size < 7) || (hist[1] != 0xB0) || (hist[4] != 0xFF) || (hist[5] != 0x4A) || (hist[6] != 0x50)){
    cs_debug("failed history check");
    return ERROR;
  }
  cs_debug("passed history check");

  get_atr;
  def_resp;

  /* set information on the card stored in reader-videoguard-common.c */
  set_known_card_info(reader,atr,&atr_size);

  if((reader->ndsversion != NDS12) && ((reader->card_system_version != NDS12) || (reader->ndsversion != NDSAUTO))) {
    /* known ATR and not NDS1+
       or unknown ATR and not forced to NDS1+
       or known NDS1+ ATR and forced to another NDS version
       ... probably not NDS1+ */
    return ERROR;
  }

  cs_debug("type: %s, baseyear: %i", reader->card_desc, reader->card_baseyear);
  if(reader->ndsversion == NDS12){
    cs_debug("forced to NDS1+");
  }

  int l = 1;

  /* NDS1 and NDS1+ cards  return XX 90 00 to this command NDS2 cards fail to respond to this*/
  static const unsigned char ins3601[5] = { 0x48,0x36,0x01,0x00,0x01 };
  if(!write_cmd_vg(ins3601,NULL) || !status_ok(cta_res+l)) {
    return ERROR;  //  not a possible NDS1+ card
  }

  static const unsigned char dummy_cmd_table[132] = {
    0x01, 0x82, 0x20, 0x01,
    0x48, 0x0E, 0xFF, 0x02,
    0x48, 0x18, 0x0C, 0x01,
    0x48, 0x1A, 0x08, 0x03,
    0x48, 0x1E, 0x09, 0x03,
    0x48, 0x2E, 0xFF, 0x00,
    0x48, 0x32, 0x01, 0x01,
    0x48, 0x36, 0xFF, 0x02,
    0x48, 0x38, 0x02, 0x03,
    0x48, 0x40, 0xFF, 0x00,
    0x48, 0x42, 0xFF, 0x00,
    0x48, 0x44, 0x35, 0x01,
    0x48, 0x46, 0xFF, 0x00,
    0x48, 0x4A, 0xFF, 0x00,
    0x48, 0x4C, 0x09, 0x01,
    0x48, 0x4E, 0x05, 0x03,
    0x48, 0x50, 0xFF, 0x02,
    0x48, 0x54, 0x2C, 0x03,
    0x48, 0x56, 0xFF, 0x02,
    0x48, 0x58, 0x4A, 0x03,
    0x48, 0x5A, 0xFF, 0x02,
    0x48, 0x5C, 0x04, 0x03,
    0x48, 0x5E, 0xFF, 0x02,
    0x48, 0x70, 0x25, 0x03,
    0x48, 0x72, 0x23, 0x03,
    0x48, 0x74, 0xFF, 0x02,
    0x48, 0x76, 0x0A, 0x03,
    0x48, 0x78, 0x18, 0x03,
    0x48, 0x7A, 0xFF, 0x00,
    0x48, 0x7C, 0xFF, 0x02,
    0x48, 0xB4, 0x40, 0x01,
    0x48, 0xBC, 0x50, 0x03,
    0x48, 0xBE, 0x10, 0x03 };

  memorize_cmd_table (reader,dummy_cmd_table,132);

  unsigned char buff[256];

  // Read card serial number to check the card
  unsigned char ins52[5] = { 0x48,0x52,0x00,0x00,0x14 };

  if(!write_cmd_vg(ins52,NULL) || !status_ok(cta_res+0x14)) {
    cs_log ("class48 ins52: failed to read serial");
    return ERROR;
    }

  static const unsigned char ins36[5] = { 0x48,0x36,0x00,0x00,0x00 };
  unsigned char boxID [4];

  if (reader->boxid > 0) {
    /* the boxid is specified in the config */
    int i;
    for (i=0; i < 4; i++) {
        boxID[i] = (reader->boxid >> (8 * (3 - i))) % 0x100;
    }
  } else {
    /* we can try to get the boxid from the card */
    int boxidOK=0;
    l=vg12_do_cmd(reader,ins36,NULL,buff,cta_res);
    if(l<13)
      cs_log("class48 ins36: too short answer");
    else if (buff[7] > 0x0F)
      cs_log("class48 ins36: encrypted - can't parse");
    else {
      /* skipping the initial fixed fields: cmdecho (4) + length (1) + encr/rev++ (4) */
      int i=9;
      int gotUA=0;
      while (i<l) {
        if (!gotUA && buff[i]<0xF0) { /* then we guess that the next 4 bytes is the UA */
          gotUA=1;
          i+=4;
        } else switch (buff[i]) { /* object length vary depending on type */
            case 0x00: /* padding */
              i+=1;
              break;
            case 0xEF: /* card status */
              i+=3;
              break;
            case 0xD1:
              i+=4;
              break;
            case 0xDF: /* next server contact */
              i+=5;
              break;
            case 0xF3: /* boxID */
                  memcpy(boxID,buff+i+1,sizeof(boxID));
                  boxidOK=1;
              i+=5;
              break;
            case 0xF6:
              i+=6;
              break;
            case 0x01: /* date & time */
              i+=7;
              break;
            case 0xFA:
              i+=9;
              break;
            case 0x5E:
            case 0x67: /* signature */
            case 0xDE:
            case 0xE2:
            case 0xE9: /* tier dates */
            case 0xF8: /* Old PPV Event Record */
            case 0xFD:
              i+=buff[i+1]+2; /* skip length + 2 bytes (type and length) */
              break;
            default: /* default to assume a length byte */
              cs_log("class48 ins36: returned unknown type=0x%02X - parsing may fail", buff[i]);
              i+=buff[i+1]+2;
        }
      }
    }

    if(!boxidOK) {
      cs_log ("no boxID available");
      return ERROR;
      }
  }

  static const unsigned char ins4C[5] = { 0x48,0x4C,0x00,0x00,0x09 };
  unsigned char payload4C[9] = { 0,0,0,0, 3,0,0,0,4 };
  memcpy(payload4C,boxID,4);
  if(!write_cmd_vg(ins4C,payload4C) || !status_ok(cta_res+l)) {
    cs_log("class48 ins4C: failed - sending boxid failed");
    return ERROR;
    }

  static const unsigned char ins58[5] = { 0x48,0x58,0x00,0x00,0x00 };
  l=vg12_do_cmd(reader,ins58,NULL,buff,cta_res);
  if(l<0) {
    cs_log("class48 ins58: failed");
    return ERROR;
    }
  memset(reader->hexserial, 0, 8);
  memcpy(reader->hexserial+2, cta_res+3, 4);
  memcpy(reader->sa, cta_res+3, 3);
  reader->caid[0] = cta_res[24]*0x100+cta_res[25];

  /* we have one provider, 0x0000 */
  reader->nprov = 1;
  memset(reader->prid, 0x00, sizeof(reader->prid));

  static const unsigned char insBE[5] = { 0x4B,0xBE,0x00,0x00,0x00 };
  l=vg12_do_cmd(reader,insBE,NULL,NULL,cta_res);
  if(l<0) {
    cs_log("class4B insBE: failed");
    return ERROR;
    }

  cs_ri_log(reader, "type: %s, caid: %04X",
         reader->card_desc,
         reader->caid[0]);
  cs_ri_log(reader, "serial: %02X%02X%02X%02X, BoxID: %02X%02X%02X%02X, baseyear: %i",
         reader->hexserial[2],reader->hexserial[3],reader->hexserial[4],reader->hexserial[5],
         boxID[0],boxID[1],boxID[2],boxID[3],
         reader->card_baseyear);
  cs_log("ready for requests");

  return OK;
}

static int videoguard12_do_ecm(struct s_reader * reader, ECM_REQUEST *er)
{
  unsigned char cta_res[CTA_RES_LEN];
  unsigned char ins40[5] = { 0x49,0x40,0x00,0x80,0xFF };
  static const unsigned char ins54[5] = { 0x4B,0x54,0x00,0x00,0x00};
  int posECMpart2=er->ecm[6]+7;
  int lenECMpart2=er->ecm[posECMpart2]+1;
  unsigned char tbuff[264], rbuff[264];
  tbuff[0]=0;

  memset(er->cw+0,0,16); //set cw to 0 so client will know it is invalid unless it is overwritten with a valid cw
  memcpy(tbuff+1,er->ecm+posECMpart2+1,lenECMpart2-1);

  ins40[4]=lenECMpart2;
  int l;

  l = vg12_do_cmd(reader,ins40,tbuff,NULL,cta_res);
  if(l<0 || !status_ok(cta_res)) {
    cs_log ("class49 ins40: (%d) status not ok %02x %02x",l,cta_res[0],cta_res[1]);
    return ERROR;
  } else {
    l = vg12_do_cmd(reader,ins54,NULL,rbuff,cta_res);
    if(l<0 || !status_ok(cta_res+l)) {
      cs_log("class4B ins54: (%d) status not ok %02x %02x",l,cta_res[0],cta_res[1]);
      return ERROR;
    } else {

      if (!cw_is_valid(rbuff+5,0)){ //sky cards report 90 00 = ok but send cw = 00 when channel not subscribed
        cs_log("class4B ins54: status 90 00 = ok but cw=00 -> channel not subscribed " );
        return ERROR;
      }

      // copy cw1 in place
      memcpy(er->cw+0,rbuff+5,8);

      if(er->ecm[0]&1) {
        unsigned char tmpcw[8];
        memcpy(tmpcw,er->cw+8,8);
        memcpy(er->cw+8,er->cw+0,8);
        memcpy(er->cw+0,tmpcw,8);
      }

      return OK;
    }
  }
}

static int videoguard12_get_emm_type(EMM_PACKET *ep, struct s_reader * rdr)
{

/*
82 30 ad 70 00 XX XX XX 00 XX XX XX 00 XX XX XX 00 XX XX XX 00 00
d3 02 00 22 90 20 44 02 4a 50 1d 88 ab 02 ac 79 16 6c df a1 b1 b7 77 00 ba eb 63 b5 c9 a9 30 2b 43 e9 16 a9 d5 14 00
d3 02 00 22 90 20 44 02 13 e3 40 bd 29 e4 90 97 c3 aa 93 db 8d f5 6b e4 92 dd 00 9b 51 03 c9 3d d0 e2 37 44 d3 bf 00
d3 02 00 22 90 20 44 02 97 79 5d 18 96 5f 3a 67 70 55 bb b9 d2 49 31 bd 18 17 2a e9 6f eb d8 76 ec c3 c9 cc 53 39 00
d2 02 00 21 90 1f 44 02 99 6d df 36 54 9c 7c 78 1b 21 54 d9 d4 9f c1 80 3c 46 10 76 aa 75 ef d6 82 27 2e 44 7b 00
*/

	int i, pos;
	int serial_count = ((ep->emm[3] >> 4) & 3) + 1;
	int serial_len = (ep->emm[3] & 0x80) ? 3 : 4;
	uchar emmtype = (ep->emm[3] & VG_EMMTYPE_MASK) >> 6;

	pos = 4 + (serial_len * serial_count) + 2;

	switch(emmtype) {
		case VG_EMMTYPE_G:
			ep->type=GLOBAL;
			cs_debug_mask(D_EMM, "EMM: GLOBAL");
			return TRUE;

		case VG_EMMTYPE_U:
			cs_debug_mask(D_EMM, "EMM: UNIQUE");
			ep->type=UNIQUE;
			if (ep->emm[1] == 0) // detected UNIQUE EMM from cccam (there is no serial)
				return TRUE;

			for (i = 1;i <= serial_count;i++) {
				if (!memcmp (rdr->hexserial + 2, ep->emm + (serial_len * i), serial_len)) {
					memcpy(ep->hexserial, ep->emm + (serial_len * i), serial_len);
				return TRUE;
				}

				pos = pos + ep->emm[pos+5] + 5;
			}
			return FALSE; // if UNIQUE but no serial match return FALSE

		case VG_EMMTYPE_S:
			ep->type=SHARED;
			cs_debug_mask(D_EMM, "EMM: SHARED");
			return TRUE; // FIXME: no check for SA

		default:
			if (ep->emm[pos-2] != 0x00 && ep->emm[pos-1] != 0x00 && ep->emm[pos-1] != 0x01) {
				//remote emm without serial
				ep->type=UNKNOWN;
				return TRUE;
			}
			return FALSE;
	}
}

static void videoguard12_get_emm_filter(struct s_reader * rdr, uchar *filter)
{
	filter[0]=0xFF;
	filter[1]=3;

	//ToDo videoguard12_get_emm_filter basic construction

	filter[2]=UNIQUE;
	filter[3]=0;

	filter[4+0]    = 0x82;
	filter[4+0+16] = 0xFF;

	memcpy(filter+4+2, rdr->hexserial+2, 4);
	memset(filter+4+2+16, 0xFF, 4);


	filter[36]=UNIQUE;
	filter[37]=0;

	filter[38+0]    = 0x82;
	filter[38+0+16] = 0xFF;

	memcpy(filter+38+6, rdr->hexserial+2, 4);
	memset(filter+38+6+16, 0xFF, 4);


	filter[70]=UNIQUE;
	filter[71]=0;

	filter[72+0]    = 0x82;
	filter[72+0+16] = 0xFF;

	memcpy(filter+72+10, rdr->hexserial+2, 4);
	memset(filter+72+10+16, 0xFF, 4);


	/* filter[104]=UNIQUE;
	filter[105]=0;

	filter[106+0]    = 0x82;
	filter[106+0+16] = 0xFF;

	memcpy(filter+106+14, rdr->hexserial+2, 2);
	memset(filter+106+14+16, 0xFF, 2); */

	return;
}

static int videoguard12_do_emm(struct s_reader * reader, EMM_PACKET *ep)
{
  unsigned char cta_res[CTA_RES_LEN];
  unsigned char ins42[5] = { 0x49,0x42,0x00,0x00,0xFF };
  int rc=ERROR;

  const unsigned char *payload = payload_addr(ep->type, ep->emm, reader->hexserial);
  while (payload) {
    ins42[4]=*payload;
    int l = vg12_do_cmd(reader,ins42,payload+1,NULL,cta_res);
    if(l>0 && status_ok(cta_res)) {
      rc=OK;
      }

    cs_debug_mask(D_EMM, "EMM request return code : %02X%02X", cta_res[0], cta_res[1]);
    //cs_dump(ep->emm, 64, "EMM:");
    if (status_ok (cta_res) && (cta_res[1] & 0x01)) {
      read_tiers(reader);
      }

    if (num_addr(ep->emm) == 1 && (int)(&payload[1] - &ep->emm[0]) + *payload + 1 < ep->l) {
      payload += *payload + 1;
      if (*payload == 0x00) ++payload;
      ++payload;
      if (*payload != 0x02) break;
      payload += 2 + payload[1];
      }
    else
      payload = 0;

    }

  return(rc);
}

static int videoguard12_card_info(struct s_reader * reader)
{
  /* info is displayed in init, or when processing info */
  cs_log("card detected");
  cs_log("type: %s", reader->card_desc);
  read_tiers (reader);
  return OK;
}

void reader_videoguard12(struct s_cardsystem *ph)
{
	ph->do_emm=videoguard12_do_emm;
	ph->do_ecm=videoguard12_do_ecm;
	ph->card_info=videoguard12_card_info;
	ph->card_init=videoguard12_card_init;
	ph->get_emm_type=videoguard12_get_emm_type;
	ph->get_emm_filter=videoguard12_get_emm_filter;
	ph->caids[0]=0x09;
}
