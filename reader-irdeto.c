#include "globals.h"
#include "reader-common.h"

extern uchar cta_res[];
extern ushort cta_lr;

static const uchar CryptTable[256] =
{
  0xDA, 0x26, 0xE8, 0x72, 0x11, 0x52, 0x3E, 0x46,
  0x32, 0xFF, 0x8C, 0x1E, 0xA7, 0xBE, 0x2C, 0x29,
  0x5F, 0x86, 0x7E, 0x75, 0x0A, 0x08, 0xA5, 0x21,
  0x61, 0xFB, 0x7A, 0x58, 0x60, 0xF7, 0x81, 0x4F,
  0xE4, 0xFC, 0xDF, 0xB1, 0xBB, 0x6A, 0x02, 0xB3,
  0x0B, 0x6E, 0x5D, 0x5C, 0xD5, 0xCF, 0xCA, 0x2A,
  0x14, 0xB7, 0x90, 0xF3, 0xD9, 0x37, 0x3A, 0x59,
  0x44, 0x69, 0xC9, 0x78, 0x30, 0x16, 0x39, 0x9A,
  0x0D, 0x05, 0x1F, 0x8B, 0x5E, 0xEE, 0x1B, 0xC4,
  0x76, 0x43, 0xBD, 0xEB, 0x42, 0xEF, 0xF9, 0xD0,
  0x4D, 0xE3, 0xF4, 0x57, 0x56, 0xA3, 0x0F, 0xA6,
  0x50, 0xFD, 0xDE, 0xD2, 0x80, 0x4C, 0xD3, 0xCB,
  0xF8, 0x49, 0x8F, 0x22, 0x71, 0x84, 0x33, 0xE0,
  0x47, 0xC2, 0x93, 0xBC, 0x7C, 0x3B, 0x9C, 0x7D,
  0xEC, 0xC3, 0xF1, 0x89, 0xCE, 0x98, 0xA2, 0xE1,
  0xC1, 0xF2, 0x27, 0x12, 0x01, 0xEA, 0xE5, 0x9B,
  0x25, 0x87, 0x96, 0x7B, 0x34, 0x45, 0xAD, 0xD1,
  0xB5, 0xDB, 0x83, 0x55, 0xB0, 0x9E, 0x19, 0xD7,
  0x17, 0xC6, 0x35, 0xD8, 0xF0, 0xAE, 0xD4, 0x2B,
  0x1D, 0xA0, 0x99, 0x8A, 0x15, 0x00, 0xAF, 0x2D,
  0x09, 0xA8, 0xF5, 0x6C, 0xA1, 0x63, 0x67, 0x51,
  0x3C, 0xB2, 0xC0, 0xED, 0x94, 0x03, 0x6F, 0xBA,
  0x3F, 0x4E, 0x62, 0x92, 0x85, 0xDD, 0xAB, 0xFE,
  0x10, 0x2E, 0x68, 0x65, 0xE7, 0x04, 0xF6, 0x0C,
  0x20, 0x1C, 0xA9, 0x53, 0x40, 0x77, 0x2F, 0xA4,
  0xFA, 0x6D, 0x73, 0x28, 0xE2, 0xCD, 0x79, 0xC8,
  0x97, 0x66, 0x8E, 0x82, 0x74, 0x06, 0xC7, 0x88,
  0x1A, 0x4A, 0x6B, 0xCC, 0x41, 0xE9, 0x9D, 0xB8,
  0x23, 0x9F, 0x3D, 0xBF, 0x8D, 0x95, 0xC5, 0x13,
  0xB9, 0x24, 0x5A, 0xDC, 0x64, 0x18, 0x38, 0x91,
  0x7F, 0x5B, 0x70, 0x54, 0x07, 0xB6, 0x4B, 0x0E,
  0x36, 0xAC, 0x31, 0xE6, 0xD6, 0x48, 0xAA, 0xB4
};

static uchar
  sc_CamKey[]         = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 },
  sc_GetCountryCode[] = { 0x02, 0x02, 0x03, 0x00, 0x00 },
  sc_GetASCIISerial[] = { 0x02, 0x00, 0x03, 0x00, 0x00 },
  sc_GetHEXSerial[]   = { 0x02, 0x01, 0x00, 0x00, 0x00 },
  sc_GetProvider[]    = { 0x02, 0x03, 0x03, 0x00, 0x00 },
  sc_GetCardFile[]    = { 0x02, 0x0E, 0x02, 0x00, 0x00 },
  sc_GetCountryCode2[]= { 0x02, 0x0B, 0x00, 0x00, 0x00 },
  sc_GetChanelIds[]   = { 0x02, 0x04, 0x00, 0x00, 0x01, 0x00 },
  sc_GetCamKey384CZ[] = { 0x02, 0x09, 0x03, 0x00, 0x40, 
                          0x18, 0xD7, 0x55, 0x14, 0xC0, 0x83, 0xF1, 0x38, 
                          0x39, 0x6F, 0xF2, 0xEC, 0x4F, 0xE3, 0xF1, 0x85, 
                          0x01, 0x46, 0x06, 0xCE, 0x7D, 0x08, 0x2C, 0x74, 
                          0x46, 0x8F, 0x72, 0xC4, 0xEA, 0xD7, 0x9C, 0xE0, 
                          0xE1, 0xFF, 0x58, 0xE7, 0x70, 0x0C, 0x92, 0x45, 
                          0x26, 0x18, 0x4F, 0xA0, 0xE2, 0xF5, 0x9E, 0x46, 
                          0x6F, 0xAE, 0x95, 0x35, 0xB0, 0x49, 0xB2, 0x0E, 
                          0xA4, 0x1F, 0x8E, 0x47, 0xD0, 0x24, 0x11, 0xD0 },
  sc_GetCamKey384DZ[] = { 0x02, 0x09, 0x03, 0x00, 0x40, 
                          0x27, 0xF2, 0xD6, 0xCD, 0xE6, 0x88, 0x62, 0x46, 
                          0x81, 0xB0, 0xF5, 0x3E, 0x6F, 0x13, 0x4D, 0xCC, 
                          0xFE, 0xD0, 0x67, 0xB1, 0x93, 0xDD, 0xF4, 0xDE, 
                          0xEF, 0xF5, 0x3B, 0x04, 0x1D, 0xE5, 0xC3, 0xB2, 
                          0x54, 0x38, 0x57, 0x7E, 0xC8, 0x39, 0x07, 0x2E, 
                          0xD2, 0xF4, 0x05, 0xAA, 0x15, 0xB5, 0x55, 0x24, 
                          0x90, 0xBB, 0x9B, 0x00, 0x96, 0xF0, 0xCB, 0xF1, 
                          0x8A, 0x08, 0x7F, 0x0B, 0xB8, 0x79, 0xC3, 0x5D },
  sc_GetCamKey384FZ[] = { 0x02, 0x09, 0x03, 0x00, 0x40,
                          0x62, 0xFE, 0xD8, 0x4F, 0x44, 0x86, 0x2C, 0x21,
                          0x50, 0x9A, 0xBE, 0x27, 0x15, 0x9E, 0xC4, 0x48,
                          0xF3, 0x73, 0x5C, 0xBD, 0x08, 0x64, 0x6D, 0x13,
                          0x64, 0x90, 0x14, 0xDB, 0xFF, 0xC3, 0xFE, 0x03,
                          0x97, 0xFA, 0x75, 0x08, 0x12, 0xF9, 0x8F, 0x84,
                          0x83, 0x17, 0xAA, 0x6F, 0xEF, 0x2C, 0x10, 0x1B,
                          0xBF, 0x31, 0x41, 0xC3, 0x54, 0x2F, 0x65, 0x50, 
                          0x95, 0xA9, 0x64, 0x22, 0x5E, 0xA4, 0xAF, 0xA9 }, 
  sc_GetCamKey383C[]  = { 0x02, 0x09, 0x03, 0x00, 0x40, 
                          0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                          0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                          0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                          0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static void XRotateLeft8Byte(uchar *buf)
{
  int k;
  uchar t1=buf[7];
  uchar t2=0;
  for(k=0; k<=7; k++)
  {
    t2=t1;
    t1=buf[k];
    buf[k]=(buf[k]<<1)|(t2>>7);
  }
}

static void ReverseSessionKeyCrypt(const uchar *camkey, uchar *key)
{
  uchar localkey[8], tmp1, tmp2;
  int idx1,idx2;

  memcpy(localkey, camkey, 8) ;
  for(idx1=0; idx1<8; idx1++)
  {
    for(idx2=0; idx2<8; idx2++)
    {
      tmp1 = CryptTable[key[7] ^ localkey[idx2] ^ idx1] ;
      tmp2 = key[0] ;
      key[0] = key[1] ;
      key[1] = key[2] ;
      key[2] = key[3] ;
      key[3] = key[4] ;
      key[4] = key[5] ;
      key[5] = key[6] ^ tmp1 ;
      key[6] = key[7] ;
      key[7] = tmp1 ^ tmp2 ;
    }
    XRotateLeft8Byte(localkey);
  } 
}

static time_t chid_date(ulong date, char *buf, int l)
{
  // Irdeto date starts 01.08.1997 which is
  // 870393600 seconds in unix calendar time
  time_t ut=870393600L+date*(24*3600);
  if (buf)
  {
    struct tm *t;
    t=gmtime(&ut);
    snprintf(buf, l, "%04d/%02d/%02d", t->tm_year+1900, t->tm_mon+1, t->tm_mday);
  }
  return(ut);
}

static int irdeto_do_cmd(uchar *buf, ushort good)
{
  int rc;
  if( (rc=reader_cmd2icc(buf, buf[4]+5)) )
    return(rc);			// result may be 0 (success) or negative
  if (cta_lr<2)
    return(0x7F7F);		// this should never happen
  return(good!=b2i(2, cta_res+cta_lr-2));
}

#define reader_chk_cmd(cmd, l) \
{ \
        if (reader_cmd2icc(cmd, sizeof(cmd))) return ERROR; \
  if (l && (cta_lr!=l)) return ERROR; }

static int irdeto_card_init2(void)
{
  int i, p;
  uchar buf[256]={0};

    /*
     * Provider
     */
    memset(reader[ridx].prid, 0xff, sizeof(reader[ridx].prid));
    for (buf[0]=i=p=0; i<reader[ridx].nprov; i++)
    {
      sc_GetProvider[3]=i;
      reader_chk_cmd(sc_GetProvider, 0);
//      if ((cta_lr==26) && (cta_res[0]!=0xf))
      if ((cta_lr==26) && ((!(i&1)) || (cta_res[0]!=0xf)))
      {
        reader[ridx].prid[i][4]=p++;
        memcpy(&reader[ridx].prid[i][0], cta_res, 4);
        sprintf((char *) buf+strlen((char *)buf), ",%06lx", b2i(3, &reader[ridx].prid[i][1]));
      }
      else
        reader[ridx].prid[i][0]=0xf;
    }
    if (p)
      cs_ri_log("providers: %d (%s)", p, buf+1);

    /*
     * ContryCode2
     */
    reader_chk_cmd(sc_GetCountryCode2, 0);
    if ((cta_lr>9) && !(cta_res[cta_lr-2]|cta_res[cta_lr-1]))
    {
      cs_debug("[irdeto-reader] max chids: %d, %d, %d, %d", cta_res[6], cta_res[7], cta_res[8], cta_res[9]);

      /*
       * Provider 2
       */
      for (i=p=0; i<reader[ridx].nprov; i++)
      {
        int j, k, chid, first=1;
        char t[32];
        if (reader[ridx].prid[i][4]!=0xff)
        {
          p++;
          sc_GetChanelIds[3]=i;
          for (j=0; j<10; j++)
          {
            sc_GetChanelIds[5]=j;
            reader_chk_cmd(sc_GetChanelIds, 0);
            if (cta_lr<61) break;
            for(k=0; k<cta_lr; k+=6)
            {
              chid=b2i(2, cta_res+k);
              if (chid && chid!=0xFFFF)
              {
                time_t date;
                chid_date(date=b2i(2, cta_res+k+2), t, 16);
                chid_date(date+cta_res[k+4], t+16, 16);
                if (first)
                {
                  cs_ri_log("provider: %d, id: %06X", p, b2i(3, &reader[ridx].prid[i][1]));
                  first=0;
                }
                cs_ri_log("chid: %04X, date: %s - %s", chid, t, t+16);
              }
            }
          }
        }
      }
    }
  
// maps the provider id for Betacrypt from FFFFFF to 000000,
// fixes problems with cascading CCcam and OSCam

  if ((reader[ridx].caid[0] >= 0x1700) && (reader[ridx].caid[0] <= 0x1799))
  {
    memset(reader[ridx].prid, 0xff, sizeof(reader[ridx].prid));
    for (i=0; i<reader[ridx].nprov; i++) 
    {
      reader[ridx].prid[i][0]=0;
      reader[ridx].prid[i][1]=0;
      reader[ridx].prid[i][2]=0;
      reader[ridx].prid[i][3]=i;
      reader[ridx].sa[i][0]=0x00; 
      reader[ridx].sa[i][1]=0xFF; 
      reader[ridx].sa[i][2]=0xFF;
      reader[ridx].sa[i][3]=0xFF;
    }
  }
  cs_log("[irdeto-reader] ready for requests");
  return OK;
}

int irdeto_card_init(ATR newatr)
{
	get_atr;
  int i, camkey=0;
  uchar buf[256]={0};

  if (memcmp(atr+4, "IRDETO", 6))
    return ERROR;
  cs_ri_log("detect Irdeto card");
  
  if(reader[ridx].has_rsa) // we use rsa from config as camkey
  {
  	cs_debug("[irdeto-reader] using camkey data from config");
  	memcpy(&sc_GetCamKey383C[5], reader[ridx].rsa_mod, 0x40);
  	memcpy(sc_CamKey, reader[ridx].nagra_boxkey, 8);
  	cs_debug("[irdeto-reader]      camkey: %s", cs_hexdump (0, sc_CamKey, 8));
  	cs_debug("[irdeto-reader] camkey-data: %s", cs_hexdump (0, &sc_GetCamKey383C[5], 32));
  	cs_debug("[irdeto-reader] camkey-data: %s", cs_hexdump (0, &sc_GetCamKey383C[37], 32));
  }

  /*
   * ContryCode
   */
  reader_chk_cmd(sc_GetCountryCode, 18);
  reader[ridx].acs=(cta_res[0]<<8)|cta_res[1];
  reader[ridx].caid[0]=(cta_res[5]<<8)|cta_res[6];
  cs_ri_log("caid: %04X, acs: %x.%02x%s",
         reader[ridx].caid[0], cta_res[0], cta_res[1], buf);

  /*
   * Ascii/Hex-Serial
   */
  reader_chk_cmd(sc_GetASCIISerial, 22);
  memcpy(buf, cta_res, 10);
  buf[10]=0;
  reader_chk_cmd(sc_GetHEXSerial, 18);
  memcpy(reader[ridx].hexserial, cta_res+12, 8); 
  reader[ridx].nprov=cta_res[10];
  cs_ri_log("ascii serial: %s, hex serial: %02X%02X%02X, hex base: %02X",
          buf, cta_res[12], cta_res[13], cta_res[14], cta_res[15]);

  /*
   * CardFile
   */
  for (sc_GetCardFile[2]=2;sc_GetCardFile[2]<4;sc_GetCardFile[2]++)
    reader_chk_cmd(sc_GetCardFile, 0);

  /*
   * CamKey
   */
  if ((atr[14]==0x03) && (atr[15]==0x84) && (atr[16]==0x55))
  {
    switch (reader[ridx].caid[0])
    {
      case 0x1702: camkey=1; break;
      case 0x1722: camkey=2; break;
      case 0x1762: camkey=3; break;
      default    : camkey=4; break;
    }
  }

  if ((reader[ridx].caid[0] >= 0x1700) && (reader[ridx].caid[0] <= 0x1799)) // Betacrypt
  {
    memset(reader[ridx].prid, 0xff, sizeof(reader[ridx].prid));
    for (i=0; i<reader[ridx].nprov; i++) 
    {
    	//values are needed for AU to work for Nagravision/Aladin/Betacrypt
      reader[ridx].prid[i][0]=0;
      reader[ridx].prid[i][1]=0;
      reader[ridx].prid[i][2]=0;
      reader[ridx].prid[i][3]=i;
      //reader[ridx].prid[i][4]=0; //not sure what to do with this one
      
	    //since shared address is not filled, we fill it here
		  reader[ridx].sa[i][0]=0x00; 
		  reader[ridx].sa[i][1]=0xFF; 
		  reader[ridx].sa[i][2]=0xFF;
		  reader[ridx].sa[i][3]=0xFF;
	  }
  }
  
  cs_debug("[irdeto-reader] set camkey for type=%d", camkey);

  switch (camkey)
  {
    case 1:
      reader_chk_cmd(sc_GetCamKey384CZ, 10);
      break;
    case 2:
      reader_chk_cmd(sc_GetCamKey384DZ, 10);
      break;
    case 3:
      reader_chk_cmd(sc_GetCamKey384FZ, 10);
      break;
    default:
      reader_chk_cmd(sc_GetCamKey383C, 0);
      break;
  }
	if (reader[ridx].cardmhz != 600)
		cs_log("WARNING: For Irdeto cards you will have to set 'cardmhz = 600' in oscam.server");
  return irdeto_card_init2();
}

int irdeto_do_ecm(ECM_REQUEST *er)
{
  static const uchar sc_EcmCmd[] = { 0x05, 0x00, 0x00, 0x02, 0x00 };
  uchar cta_cmd[272];

  memcpy(cta_cmd, sc_EcmCmd, sizeof(sc_EcmCmd));
  cta_cmd[4]=(er->ecm[2])-3;
  memcpy(cta_cmd+sizeof(sc_EcmCmd), &er->ecm[6], cta_cmd[4]);
  if (irdeto_do_cmd(cta_cmd, 0x9D00)) return ERROR;
  if (cta_lr<24) return ERROR;
  ReverseSessionKeyCrypt(sc_CamKey, cta_res+6);
  ReverseSessionKeyCrypt(sc_CamKey, cta_res+14);
  memcpy(er->cw, cta_res+6, 16);
  return OK;
}

int irdeto_get_emm_type(EMM_PACKET *ep, struct s_reader * rdr) {

	int i, ok = 0;
	int l = (ep->emm[3]&0x07);
	int mode=(ep->emm[3]>>3);

	cs_debug_mask(D_EMM, "Entered irdeto_get_emm_type ep->emm[3]=%02x",ep->emm[3]);

	switch (ep->emm[3]) {

		case 0xd0:
			// 0xd0 means global emm
			ep->type = GLOBAL;
			cs_debug_mask(D_EMM, "IRDETO EMM: GLOBAL");
			return TRUE;
		case 0xd2:
			// 0xd2 means shared emm, first 2 bytes of hexserial are transmitted in emm, seems to be the shared adr
			ep->type = SHARED;
			memset(ep->hexserial, 0, 8);
			//prid in hexserial instead of SA
			memcpy(ep->hexserial, ep->emm + 4, l);
			for(i = 0; i < rdr->nprov; i++) {
				ok = (!l || !memcmp(ep->hexserial, &rdr->prid[i][1], l));

				// FIXME: Betacrypt/Nagra Aladin reports wrong provider id
				if ((rdr->caid[0] >= 0x1700) && (rdr->caid[0] <= 0x1799))
					ok = 1;

				if (ok) break;
			}
			cs_debug_mask(D_EMM, "IRDETO EMM: SHARED, ep = %s, rdr = %s", cs_hexdump(1, ep->hexserial, l), 
				     cs_hexdump(1, rdr->hexserial, l));
			return (!l || !memcmp(ep->emm + 4, rdr->hexserial, l));
			
		case 0xd3:
			// 0xd3 means uniqe emm
			ep->type = UNIQUE;
			memset(ep->hexserial, 0, 8);
			memcpy(ep->hexserial, ep->emm + 4, l);
			cs_debug_mask(D_EMM, "IRDETO EMM: UNIQUE, ep = %s, rdr = %s", cs_hexdump(1, ep->hexserial, l),
				     cs_hexdump(1, rdr->hexserial, l));
			return (mode == rdr->hexserial[3] && (!l || !memcmp(ep->emm + 4, rdr->hexserial, l)));
		default:
			ep->type = UNKNOWN;
			cs_debug_mask(D_EMM, "IRDETO EMM: UNKNOWN");
			return TRUE;
	}

}

int irdeto_do_emm(EMM_PACKET *ep)
{
  static const uchar sc_EmmCmd[] = { 0x01,0x00,0x00,0x00,0x00 };
  uchar cta_cmd[272];

  int i, l=(ep->emm[3]&0x07), ok=0;
  int mode=(ep->emm[3]>>3);

  uchar *emm=ep->emm;
  if (mode&0x10)		// Hex addressed
  {
    ok=(mode==reader[ridx].hexserial[3] &&
       (!l || !memcmp(&emm[4], reader[ridx].hexserial, l)));
  }
  else				// Provider addressed
  {
    for(i=0; i<reader[ridx].nprov; i++)
    {
      ok=(mode==reader[ridx].prid[i][0] &&
         (!l || !memcmp(&emm[4], &reader[ridx].prid[i][1], l)));
      if (ok) break;
    }
  }

  if (ok)
  {
    l++;
    if (l<=ADDRLEN)
    {
      const int dataLen=SCT_LEN(emm)-5-l;		// sizeof of emm bytes (nanos)
      uchar *ptr=cta_cmd;
      memcpy(ptr, sc_EmmCmd, sizeof(sc_EmmCmd));	// copy card command
      ptr[4]=dataLen+ADDRLEN;				// set card command emm size
      ptr+=sizeof(sc_EmmCmd); emm+=3;
      memset(ptr, 0, ADDRLEN);				// clear addr range
      memcpy(ptr, emm, l);				// copy addr bytes
      ptr+=ADDRLEN; emm+=l;
      memcpy(ptr, &emm[2], dataLen);			// copy emm bytes
      return(irdeto_do_cmd(cta_cmd, 0) ? 0 : 1);
    }
    else
      cs_debug("[irdeto-reader] addrlen %d > %d", l, ADDRLEN);
  }
  return ERROR;
}

int irdeto_card_info(void)
{
	//original irdeto_card_info is not pure info, it is actually needed for init
	return OK;
}

