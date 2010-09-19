#include "globals.h"
#include "reader-common.h"
#include "reader-videoguard-common.h"


static void vg2_read_tiers(struct s_reader * reader)
{
  def_resp;
  int l;

  /* ins2a is not needed and causes an error on some cards eg Sky Italy 09CD
     check if ins2a is in command table before running it
  */
  static const unsigned char ins2a[5] = { 0xd0,0x2a,0x00,0x00,0x00 };
  if(cmd_exists(ins2a)) {
    l=do_cmd(reader, ins2a,NULL,NULL,cta_res);
    if(l<0 || !status_ok(cta_res+l)){
      cs_log ("[videoguard2-reader] cmd ins2a failed");
      return;
    }
  }

  static unsigned char ins76007f[5] = { 0xd0,0x76,0x00,0x7f,0x02 };
  if(!write_cmd_vg(ins76007f,NULL) || !status_ok(cta_res+2)){
    cs_log ("[videoguard2-reader] cmd ins76007f failed");
    return;
  }
  int num=cta_res[1];

  int i;
  static unsigned char ins76[5] = { 0xd0,0x76,0x00,0x00,0x00 };
#ifdef CS_RDR_INIT_HIST
  reader->init_history_pos = 0; //reset for re-read
  memset(reader->init_history, 0, sizeof(reader->init_history));
#endif
  for(i=0; i<num; i++) {
    ins76[2]=i;
    l=do_cmd(reader, ins76,NULL,NULL,cta_res);
    if(l<0 || !status_ok(cta_res+l)) return;
    if(cta_res[2]==0 && cta_res[3]==0) break;
    int y,m,d,H,M,S;
    rev_date_calc(&cta_res[4],&y,&m,&d,&H,&M,&S,VG_BASEYEAR);
    unsigned short tier_id = (cta_res[2] << 8) | cta_res[3];
    char *tier_name = get_tiername(tier_id, reader->caid[0]);
    cs_ri_log(reader, "[videoguard2-reader] tier: %04x, expiry date: %04d/%02d/%02d-%02d:%02d:%02d %s",tier_id,y,m,d,H,M,S,tier_name);
    }
}

int videoguard2_card_init(struct s_reader * reader, ATR newatr)
{

  get_hist;
  if ((hist_size < 7) || (hist[1] != 0xB0) || (hist[4] != 0xFF) || (hist[5] != 0x4A) || (hist[6] != 0x50))
    return ERROR;

  get_atr;
  def_resp;

  /* get information on the card from reader-videoguard-common.c */
  NDS_ATR_ENTRY nds_atr_entry = {{0},0,0,0,0};
  memcpy(nds_atr_entry.atr,atr,atr_size);
  nds_atr_entry.atr_len = atr_size;

  getNdsAtrEntry(&nds_atr_entry);

  if((reader->ndsversion != NDS2) &&
     (((nds_atr_entry.nds_version != NDS2) && (nds_atr_entry.nds_version != NDSUNKNOWN)) ||
      (reader->ndsversion != NDSAUTO))) {
    /* known ATR and not NDS2
       or known NDS2 ATR and forced to another NDS version */
    return ERROR;
  }

  cs_ri_log(reader, "[videoguard2-reader] type: %s, baseyear: %i", nds_atr_entry.desc, nds_atr_entry.base_year);
  if(reader->ndsversion == NDS2){
    cs_log("[videoguard2-reader] forced to NDS2");
  }

  VG_BASEYEAR=nds_atr_entry.base_year;

  //a non videoguard2/NDS2 card will fail on read_cmd_len(ins7401)
  //this way unknown videoguard2/NDS2 cards will also pass this check

  unsigned char ins7401[5] = { 0xD0,0x74,0x01,0x00,0x00 };
  int l;
  ins7401[3]=0x80;  // from newcs log
  ins7401[4]=0x01;
  if((l=read_cmd_len(reader, ins7401))<0) return ERROR; //not a videoguard2/NDS card or communication error
  ins7401[3]=0x00;
  ins7401[4]=l;
  if(!write_cmd_vg(ins7401,NULL) || !status_ok(cta_res+l)) {
    cs_log ("[videoguard2-reader] failed to read cmd list");
    return ERROR;
    }

  memorize_cmd_table (cta_res,l);

  unsigned char buff[256];

  unsigned char ins7416[5] = { 0xD0,0x74,0x16,0x00,0x00 };
  if(do_cmd(reader, ins7416, NULL, NULL,cta_res)<0) {
    cs_log ("[videoguard2-reader] cmd 7416 failed");
    return ERROR;
    }

  unsigned char ins36[5] = { 0xD0,0x36,0x00,0x00,0x00 };
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
    l=do_cmd(reader, ins36, NULL, buff,cta_res);
    if(l<13)
      cs_log("[videoguard2-reader] ins36: too short answer");
    else if (buff[7] > 0x0F)
      cs_log("[videoguard2-reader] ins36: encrypted - can't parse");
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
                  memcpy(&boxID,&buff[i+1],sizeof(boxID));
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
              cs_log("[videoguard2-reader] ins36 returned unknown type=0x%02X - parsing may fail", buff[i]);
              i+=buff[i+1]+2;
        }
      }
    }

    if(!boxidOK) {
      cs_log ("[videoguard2-reader] no boxID available");
      return ERROR;
      }
  }

  unsigned char ins4C[5] = { 0xD0,0x4C,0x00,0x00,0x09 };
  unsigned char payload4C[9] = { 0,0,0,0, 3,0,0,0,4 };
  memcpy(payload4C,boxID,4);
  if(!write_cmd_vg(ins4C,payload4C) || !status_ok(cta_res+l)) {
    cs_log("[videoguard2-reader] sending boxid failed");
    return ERROR;
    }
// Start of suggested fix for 09ac cards
    unsigned char Dimeno_Magic[0x10]={0xF9,0xFB,0xCD,0x5A,0x76,0xB5,0xC4,0x5C,0xC8,0x2E,0x1D,0xE1,0xCC,0x5B,0x6B,0x02}; 
    int a;
    for(a=0; a<4; a++)
        Dimeno_Magic[a]=Dimeno_Magic[a]^boxID[a];
    //I supposed to declare a AES_KEY Astro_Key somewhere before...
    AES_set_decrypt_key(Dimeno_Magic,128,&Astro_Key);
    Astro_Key.rounds=10;
    //Important for ecm decryption...
//	End of suggested fix

  //short int SWIRDstatus = cta_res[1];
  unsigned char ins58[5] = { 0xD0,0x58,0x00,0x00,0x00 };
  l=do_cmd(reader, ins58, NULL, buff,cta_res);
  if(l<0) {
    cs_log("[videoguard2-reader] cmd ins58 failed");
    return ERROR;
    }
  memset(reader->hexserial, 0, 8);
  memcpy(reader->hexserial+2, cta_res+3, 4);
  memcpy(reader->sa, cta_res+3, 3);
  reader->caid[0] = cta_res[24]*0x100+cta_res[25];

  /* we have one provider, 0x0000 */
  reader->nprov = 1;
  memset(reader->prid, 0x00, sizeof(reader->prid));

  /*
  cs_log ("[videoguard2-reader] INS58 : Fuse byte=0x%02X, IRDStatus=0x%02X", cta_res[2],SWIRDstatus);
  if (SWIRDstatus==4)  {
  // If swMarriage=4, not married then exchange for BC Key
  cs_log ("[videoguard2-reader] Card not married, exchange for BC Keys");
   */

  static unsigned char seed1[] = {
    0xb9, 0xd5, 0xef, 0xd5, 0xf5, 0xd5, 0xfb, 0xd5, 0x31, 0xd6, 0x43, 0xd6, 0x55, 0xd6, 0x61, 0xd6,
    0x85, 0xd6, 0x9d, 0xd6, 0xaf, 0xd6, 0xc7, 0xd6, 0xd9, 0xd6, 0x09, 0xd7, 0x15, 0xd7, 0x21, 0xd7,
    0x27, 0xd7, 0x3f, 0xd7, 0x45, 0xd7, 0xb1, 0xd7, 0xbd, 0xd7, 0xdb, 0xd7, 0x11, 0xd8, 0x23, 0xd8,
    0x29, 0xd8, 0x2f, 0xd8, 0x4d, 0xd8, 0x8f, 0xd8, 0xa1, 0xd8, 0xad, 0xd8, 0xbf, 0xd8, 0xd7, 0xd8
    };
  static unsigned char seed2[] = {
    0x01, 0x00, 0xcf, 0x13, 0xe0, 0x60, 0x54, 0xac, 0xab, 0x99, 0xe6, 0x0c, 0x9f, 0x5b, 0x91, 0xb9,
    0x72, 0x72, 0x4d, 0x5b, 0x5f, 0xd3, 0xb7, 0x5b, 0x01, 0x4d, 0xef, 0x9e, 0x6b, 0x8a, 0xb9, 0xd1,
    0xc9, 0x9f, 0xa1, 0x2a, 0x8d, 0x86, 0xb6, 0xd6, 0x39, 0xb4, 0x64, 0x65, 0x13, 0x77, 0xa1, 0x0a,
    0x0c, 0xcf, 0xb4, 0x2b, 0x3a, 0x2f, 0xd2, 0x09, 0x92, 0x15, 0x40, 0x47, 0x66, 0x5c, 0xda, 0xc9
    };
  cCamCryptVG_SetSeed(seed1,seed2);

  unsigned char insB4[5] = { 0xD0,0xB4,0x00,0x00,0x40 };
  unsigned char tbuff[64];
  cCamCryptVG_GetCamKey(tbuff);
  l=do_cmd(reader, insB4, tbuff, NULL,cta_res);
  if(l<0 || !status_ok(cta_res)) {
    cs_log ("[videoguard2-reader] cmd D0B4 failed (%02X%02X)", cta_res[0], cta_res[1]);
    return ERROR;
    }

  unsigned char insBC[5] = { 0xD0,0xBC,0x00,0x00,0x00 };
  l=do_cmd(reader, insBC, NULL, NULL,cta_res);
  if(l<0) {
    cs_log("[videoguard2-reader] cmd D0BC failed");
    return ERROR;
    }

  unsigned char insBE[5] = { 0xD3,0xBE,0x00,0x00,0x00 };
  l=do_cmd(reader, insBE, NULL, NULL,cta_res);
  if(l<0) {
    cs_log("[videoguard2-reader] cmd D3BE failed");
    return ERROR;
    }

  unsigned char ins58a[5] = { 0xD1,0x58,0x00,0x00,0x00 };
  l=do_cmd(reader, ins58a, NULL, NULL,cta_res);
  if(l<0) {
    cs_log("[videoguard2-reader] cmd D158 failed");
    return ERROR;
    }

  unsigned char ins4Ca[5] = { 0xD1,0x4C,0x00,0x00,0x00 };
  l=do_cmd(reader, ins4Ca,payload4C, NULL,cta_res);
  if(l<0 || !status_ok(cta_res)) {
    cs_log("[videoguard2-reader] cmd D14Ca failed");
    return ERROR;
    }

  cs_ri_log(reader, "[videoguard2-reader] type: VideoGuard, caid: %04X, serial: %02X%02X%02X%02X, BoxID: %02X%02X%02X%02X",
         reader->caid[0],
         reader->hexserial[2],reader->hexserial[3],reader->hexserial[4],reader->hexserial[5],
         boxID[0],boxID[1],boxID[2],boxID[3]);

  cs_log("[videoguard2-reader] ready for requests");

  return OK;
}

int videoguard2_do_ecm(struct s_reader * reader, ECM_REQUEST *er)
{
  unsigned char cta_res[CTA_RES_LEN];
  static unsigned char ins40[5] = { 0xD1,0x40,0x00,0x80,0xFF };
  static const unsigned char ins54[5] = { 0xD3,0x54,0x00,0x00,0x00};
  int posECMpart2=er->ecm[6]+7;
  int lenECMpart2=er->ecm[posECMpart2]+1;
  unsigned char tbuff[264];
  tbuff[0]=0;
  memcpy(&tbuff[1],&(er->ecm[posECMpart2+1]),lenECMpart2-1);
  ins40[4]=lenECMpart2;
  int l;
  l = do_cmd(reader, ins40,tbuff,NULL,cta_res);
  if(l>0 && status_ok(cta_res)) {
    l = do_cmd(reader, ins54,NULL,NULL,cta_res);
    if(l>0 && status_ok(cta_res+l)) {
      if (!cw_is_valid(CW1)) //sky cards report 90 00 = ok but send cw = 00 when channel not subscribed
      {
          snprintf( er->msglog, MSGLOGSIZE, "9000 but cw=00 -> channel not subscribed " );
	return ERROR;
      }

      if(er->ecm[0]&1) {
        memcpy(er->cw+8,CW1,8);
        memcpy(er->cw+0,CW2,8);
      }
      else {
        memcpy(er->cw+0,CW1,8);
        memcpy(er->cw+8,CW2,8);
      }


      //test for postprocessing marker
      int posB0 = -1;
      int i;
      for (i = 6; i < posECMpart2; i++)
      {
        if (er->ecm[i-3] == 0x80 && er->ecm[i] == 0xB0 && ((er->ecm[i+1] == 0x01) ||(er->ecm[i+1] == 0x02)||(er->ecm[i+1] == 0x03) ) ) {
			posB0 = i;
      	  break;
		}
      }

	  if (posB0 != -1) {
		  do_post_dw_hash( er->cw+0, &er->ecm[posB0-2]);
		  do_post_dw_hash( er->cw+8, &er->ecm[posB0-2]);
	  }

      return OK;
    }
  }
  snprintf( er->msglog, MSGLOGSIZE, "(%d) status not ok %02x %02x",l, cta_res[0],cta_res[1] );
  return ERROR;
}

static int num_addr(const unsigned char *data)
{
  return ((data[3]&0x30)>>4)+1;
}
/*
Example of GLOBAL EMM's
This one has IRD-EMM + Card-EMM
82 70 20 00 02 06 02 7D 0E 89 53 71 16 90 14 40
01 ED 17 7D 9E 1F 28 CF 09 97 54 F1 8E 72 06 E7
51 AF F5
This one has only IRD-EMM
82 70 6D 00 07 69 01 30 07 14 5E 0F FF FF 00 06
00 0D 01 00 03 01 00 00 00 0F 00 00 00 5E 01 00
01 0C 2E 70 E4 55 B6 D2 34 F7 44 86 9E 5C 91 14
81 FC DF CB D0 86 65 77 DF A9 E1 6B A8 9F 9B DE
90 92 B9 AA 6C B3 4E 87 D2 EC 92 DA FC 71 EF 27
B3 C3 D0 17 CF 0B D6 5E 8C DB EB B3 37 55 6E 09
7F 27 3C F1 85 29 C9 4E 0B EE DF 68 BE 00 C9 00
*/
static const unsigned char *payload_addr(uchar emmtype, const unsigned char *data, const unsigned char *a)
{
  int s;
  int l;
  const unsigned char *ptr = NULL;
  int position=-1;
  int numAddrs=0;

  switch(emmtype) {
    case SHARED: s=3; break;
    case UNIQUE: s=4; break;
    default: s=0;
  }

  numAddrs=num_addr(data);

  if(s>0) {
    for(l=0;l<numAddrs;l++) {
      if(!memcmp(&data[l*4+4],a+2,s)) {
        position=l;
        break;
      }
    }
  }

  int num_filter = (position == -1) ? 0 : numAddrs;

  /* skip header and the filter list */
  ptr = data+4+4*num_filter;

  if (*ptr != 0x02 &&  *ptr != 0x07) // some clients omit 00 00 separator */
  {
    ptr += 2;                // skip 00 00 separator
    if (*ptr == 0x00) ptr++; // skip optional 00
    ptr++;                   // skip the 1st bitmap len
  }

  /* check for IRD-EMM */
  if (*ptr != 0x02 &&  *ptr != 0x07) return NULL;

  /* skip IRD-EMM part, 02 00 or 02 06 xx aabbccdd yy */
  ptr += 2 + ptr[1];

    /* check for EMM boundaries - ptr should not exceed EMM length */
    if ((int)(ptr - (data + 3)) >= data[2]) return NULL;

  for(l=0;l<position;l++) {
    /* skip the payload of the previous sub-EMM */
    ptr += 1 + ptr [0];

    /* check for EMM boundaries - ptr should not exceed EMM length */
    if ((int)(ptr - (data + 3)) >= data[2]) return NULL;

    /* skip optional 00 */
    if (*ptr == 0x00) ptr++;

    /* skip the bitmap len */
    ptr++;

    /* check for IRD-EMM */
    if (*ptr != 0x02 &&  *ptr != 0x07) return NULL;

    /* skip IRD-EMM part, 02 00 or 02 06 xx aabbccdd yy */
    ptr += 2 + ptr[1];
  }

  return ptr;
}

int videoguard2_get_emm_type(EMM_PACKET *ep, struct s_reader * rdr)
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
			cs_debug_mask(D_EMM, "VIDEOGUARD2 EMM: GLOBAL");
			return TRUE;

		case VG_EMMTYPE_U:
			cs_debug_mask(D_EMM, "VIDEOGUARD2 EMM: UNIQUE");
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
			cs_debug_mask(D_EMM, "VIDEOGUARD2 EMM: SHARED");
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

void videoguard2_get_emm_filter(struct s_reader * rdr, uchar *filter)
{
	filter[0]=0xFF;
	filter[1]=3;

	//ToDo videoguard2_get_emm_filter basic construction

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

int videoguard2_do_emm(struct s_reader * reader, EMM_PACKET *ep)
{
  unsigned char cta_res[CTA_RES_LEN];
  unsigned char ins42[5] = { 0xD1,0x42,0x00,0x00,0xFF };
  int rc=ERROR;

  const unsigned char *payload = payload_addr(ep->type, ep->emm, reader->hexserial);
  while (payload) {
    ins42[4]=*payload;
    int l = do_cmd(reader, ins42,payload+1,NULL,cta_res);
    if(l>0 && status_ok(cta_res)) {
      rc=OK;
      }

    cs_debug_mask(D_EMM, "[videoguard2-reader] EMM request return code : %02X%02X", cta_res[0], cta_res[1]);
    //cs_dump(ep->emm, 64, "EMM:");
    if (status_ok (cta_res) && (cta_res[1] & 0x01)) {
      vg2_read_tiers(reader);
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

int videoguard2_card_info(struct s_reader * reader)
{
  /* info is displayed in init, or when processing info */
  cs_log("[videoguard2-reader] card detected");
  cs_log("[videoguard2-reader] type: VideoGuard" );
  vg2_read_tiers (reader);
  return OK;
}
