#include "globals.h"
#include "reader-common.h"

struct via_date {
  ushort day_s   : 5;
  ushort month_s : 4;
  ushort year_s  : 7;

  ushort day_e   : 5;
  ushort month_e : 4;
  ushort year_e  : 7;
};

static void parse_via_date(const uchar *buf, struct via_date *vd, int fend)
{
  ushort date;

  date = (buf[0]<<8) | buf[1];
  vd->day_s   = date & 0x1f;
  vd->month_s = (date>>5) & 0x0f;
  vd->year_s  = (date>>9) & 0x7f;

  if( fend )
  {
    date = (buf[2]<<8) | buf[3];
    vd->day_e   = date & 0x1f;
    vd->month_e = (date>>5) & 0x0f;
    vd->year_e  = (date>>9) & 0x7f;
  }
}

static void show_class(struct s_reader * reader, const char *p, const uchar *b, int l)
{
  int i, j;

  // b -> via date (4 bytes)
  b+=4;
  l-=4;

  j=l-1;
  for (; j>=0; j--)
    for (i=0; i<8; i++)
      if (b[j] & (1 << (i&7)))
      {
        uchar cls;
        struct via_date vd;
        parse_via_date(b-4, &vd, 1);
        cls=(l-(j+1))*8+i;
        if (p)
          cs_log("%sclass: %02X, expiry date: %04d/%02d/%02d - %04d/%02d/%02d", p, cls, 
                  vd.year_s+1980, vd.month_s, vd.day_s,
                  vd.year_e+1980, vd.month_e, vd.day_e);
	else
          cs_ri_log(reader, "class: %02X, expiry date: %04d/%02d/%02d - %04d/%02d/%02d", cls, 
                  vd.year_s+1980, vd.month_s, vd.day_s,
                  vd.year_e+1980, vd.month_e, vd.day_e);
      }
}

static void show_subs(struct s_reader * reader, const uchar *emm)
{  
  // emm -> A9, A6, B6

  switch( emm[0] )
  {
    case 0xA9:
      show_class(reader, "nano A9: ", emm+2, emm[1]);
      break;
/*
    {
      int i, j, byts;
      const uchar *oemm;

      oemm = emm;
      byts = emm[1]-4;
      emm+=6;

      j=byts-1;
      for( ; j>=0; j-- )
        for( i=0; i<8; i++ )
          if( emm[j] & (1 << (i&7)) )
          {
            uchar cls;
            struct via_date vd;
            parse_via_date(emm-4, &vd, 1);
            cls=(byts-(j+1))*8+i;
            cs_log("%sclass %02X: expiry date: %02d/%02d/%04d - %02d/%02d/%04d",
                    fnano?"nano A9: ":"", cls, 
                    vd.day_s, vd.month_s, vd.year_s+1980, 
                    vd.day_e, vd.month_e, vd.year_e+1980);
          }
      break;
    }
*/
    case 0xA6:
    {
      char szGeo[256];

      memset(szGeo, 0, 256);
      strncpy(szGeo, (char *)emm+2, emm[1]);
      cs_log("[viaccess-reader] nano A6: geo %s", szGeo);
      break;
    }
    case 0xB6:
    {
      uchar m; // modexp
      struct via_date vd;

      m=emm[emm[1]+1];
      parse_via_date(emm+2, &vd, 0);
      cs_log("[viaccess-reader] nano B6: modexp %d%d%d%d%d%d: %02d/%02d/%04d", (m&0x20)?1:0, 
             (m&0x10)?1:0,(m&0x08)?1:0,(m&0x04)?1:0,(m&0x02)?1:0,(m&0x01)?1:0,
             vd.day_s, vd.month_s, vd.year_s+1980);
      break;
    }
  }
}

static int chk_prov(struct s_reader * reader, uchar *id, uchar keynr)
{
  int i, j, rc;
  for (rc=i=0; (!rc) && (i<reader->nprov); i++)
    if(!memcmp(&reader->prid[i][1], id, 3))
      for (j=0; (!rc) && (j<16); j++)
        if (reader->availkeys[i][j]==keynr)
          rc=1;
  return(rc);
}

int viaccess_card_init(struct s_reader * reader, ATR newatr)
{
  get_atr;
  def_resp;
  int i;
  uchar buf[256];
  static uchar insac[] = { 0xca, 0xac, 0x00, 0x00, 0x00 }; // select data
  static uchar insb8[] = { 0xca, 0xb8, 0x00, 0x00, 0x00 }; // read selected data
  static uchar insa4[] = { 0xca, 0xa4, 0x00, 0x00, 0x00 }; // select issuer
  static uchar insc0[] = { 0xca, 0xc0, 0x00, 0x00, 0x00 }; // read data item

  static uchar insFAC[] = { 0x87, 0x02, 0x00, 0x00, 0x03 }; // init FAC
  static uchar FacDat[] = { 0x00, 0x00, 0x28 };

  if ((atr[0]!=0x3f) || (atr[1]!=0x77) || ((atr[2]!=0x18) && (atr[2]!=0x11) && (atr[2]!=0x19)) || (atr[9]!=0x68)) return ERROR;

  write_cmd(insFAC, FacDat);
  if( !(cta_res[cta_lr-2]==0x90 && cta_res[cta_lr-1]==0) )
    return ERROR;

//  switch((atr[atrsize-4]<<8)|atr[atrsize-3])
//  {
//    case 0x6268: ver="2.3"; break;
//    case 0x6668: ver="2.4(?)"; break;
//    case 0xa268:
//    default: ver="unknown"; break;
//  }
      
  reader->caid[0]=0x500;
  memset(reader->prid, 0xff, sizeof(reader->prid));
  insac[2]=0xa4; write_cmd(insac, NULL); // request unique id
  insb8[4]=0x07; write_cmd(insb8, NULL); // read unique id
  memcpy(reader->hexserial, cta_res+2, 5);
//  cs_log("[viaccess-reader] type: Viaccess, ver: %s serial: %llu", ver, b2ll(5, cta_res+2));
  cs_ri_log(reader, "type: Viaccess (%sstandard atr), caid: %04X, serial: %llu",
        atr[9]==0x68?"":"non-",reader->caid[0], b2ll(5, cta_res+2));

  i=0;
  insa4[2]=0x00; write_cmd(insa4, NULL); // select issuer 0
  buf[0]=0;
  while((cta_res[cta_lr-2]==0x90) && (cta_res[cta_lr-1]==0))
  {
    insc0[4]=0x1a; write_cmd(insc0, NULL); // show provider properties
    cta_res[2]&=0xF0;
    reader->prid[i][0]=0;
    memcpy(&reader->prid[i][1], cta_res, 3);
    memcpy(&reader->availkeys[i][0], cta_res+10, 16);
    sprintf((char *)buf+strlen((char *)buf), ",%06lX", b2i(3, &reader->prid[i][1]));
//cs_log("[viaccess-reader] buf: %s", buf);

    insac[2]=0xa5; write_cmd(insac, NULL); // request sa
    insb8[4]=0x06; write_cmd(insb8, NULL); // read sa
    memcpy(&reader->sa[i][0], cta_res+2, 4);

/*
    insac[2]=0xa7; write_cmd(insac, NULL); // request name
    insb8[4]=0x02; write_cmd(insb8, NULL); // read name nano + len
    l=cta_res[1];
    insb8[4]=l; write_cmd(insb8, NULL); // read name
    cta_res[l]=0;
cs_log("[viaccess-reader] name: %s", cta_res);
*/

    insa4[2]=0x02;
    write_cmd(insa4, NULL); // select next issuer
    i++;
  }
  reader->nprov=i;
  cs_ri_log(reader, "providers: %d (%s)", reader->nprov, buf+1);

  /* init the maybe existing aes key */
  aes_set_key((char *)reader->aes_key);

  /* disabling parental lock. assuming pin "0000" */
  if (cfg->ulparent) {
      static uchar inDPL[] = {0xca, 0x24, 0x02, 0x00, 0x09};
      static uchar cmDPL[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F};
      write_cmd(inDPL,cmDPL);
      if( !(cta_res[cta_lr-2]==0x90 && cta_res[cta_lr-1]==0) )
          cs_log("[viaccess-reader] Can't disable parental lock. Wrong PIN? I assumed 0000!");
      else
          cs_log("[viaccess-reader] Parental lock disabled");
  }

  cs_log("[viaccess-reader] ready for requests");
  memset(&reader->last_geo, 0, sizeof(reader->last_geo));
  return OK;
}

int viaccess_do_ecm(struct s_reader * reader, ECM_REQUEST *er)
{
  def_resp;
  static unsigned char insa4[] = { 0xca,0xa4,0x04,0x00,0x03 }; // set provider id
  static unsigned char ins88[] = { 0xca,0x88,0x00,0x00,0x00 }; // set ecm
  static unsigned char insf8[] = { 0xca,0xf8,0x00,0x00,0x00 }; // set geographic info 
  static unsigned char insc0[] = { 0xca,0xc0,0x00,0x00,0x12 }; // read dcw

  const uchar *ecm88Data=er->ecm+4; //XXX what is the 4th byte for ??
  int ecm88Len=SCT_LEN(er->ecm)-4;
  ulong provid=0;
  int rc=0;
  int hasD2 = 0;
  int curEcm88len=0;
  int nanoLen=0;
  const uchar *nextEcm;
  uchar keyToUse=0;
  uchar DE04[256];
  int D2KeyID=0;
  memset(DE04, 0, sizeof(DE04)); //fix dorcel de04 bug

  nextEcm=ecm88Data;
  
  while (ecm88Len && !rc) {
    
    // 80 33 nano 80 (ecm) + len (33)
    if(ecm88Data[0]==0x80) { // nano 80, give ecm len
        curEcm88len=ecm88Data[1];
        nextEcm=ecm88Data+curEcm88len+2;
        ecm88Data += 2;
        ecm88Len -= 2;
    }

    if(!curEcm88len) { //there was no nano 80 -> simple ecm
        curEcm88len=ecm88Len;
    }
    
    // d2 02 0d 02 -> D2 nano, len 2,  select the AES key to be used
    if(ecm88Data[0]==0xd2) {
        // FIXME: use the d2 arguments
        int len = ecm88Data[1] + 2;
        D2KeyID=ecm88Data[3];
        ecm88Data += len;
        ecm88Len -= len;
        curEcm88len -=len;
        hasD2 = 1;
    }
    else
        hasD2 = 0;

    // 40 07 03 0b 00  -> nano 40, len =7  ident 030B00 (tntsat), key #0  <== we're pointing here
    // 09 -> use key #9 
    // 05 67 00
    if ((ecm88Data[0]==0x90 || ecm88Data[0]==0x40) && (ecm88Data[1]==0x03 || ecm88Data[1]==0x07 ) )
    {
        uchar ident[3], keynr;
        //uchar buff[256]; // MAX_LEN
        uchar *ecmf8Data=0;
        int ecmf8Len=0;

        nanoLen=ecm88Data[1] + 2;
        
        memcpy (ident, &ecm88Data[2], sizeof(ident));
        provid = b2i(3, ident);
        ident[2]&=0xF0;
        keynr=ecm88Data[4]&0x0F;
        // 40 07 03 0b 00  -> nano 40, len =7  ident 030B00 (tntsat), key #0  <== we're pointing here
        // 09 -> use key #9 
        if(nanoLen>5) {
            keyToUse=ecm88Data[5];
            keynr=keyToUse;
            cs_debug("keyToUse = %d",keyToUse);
        }

        if (!chk_prov(reader, ident, keynr))
        {
          cs_debug("[viaccess-reader] ECM: provider or key not found on card");
          return ERROR;
        }
        
        ecm88Data+=nanoLen;
        ecm88Len-=nanoLen;
        curEcm88len-=nanoLen;

        // DE04
        if (ecm88Data[0]==0xDE && ecm88Data[1]==0x04)
        {
            memcpy (DE04, &ecm88Data[0], 6);
            ecm88Data+=6;
        }
        //

        if( reader->last_geo.provid != provid ) 
        {
          reader->last_geo.provid = provid;
          reader->last_geo.geo_len = 0;
          reader->last_geo.geo[0]  = 0;
          write_cmd(insa4, ident); // set provider
        }

        while(ecm88Len>0 && ecm88Data[0]<0xA0)
        {
          int nanoLen=ecm88Data[1]+2;
          if (!ecmf8Data)
            ecmf8Data=(uchar *)ecm88Data;
          ecmf8Len+=nanoLen;
          ecm88Len-=nanoLen;
          curEcm88len-=nanoLen;
          ecm88Data+=nanoLen;
        }
        if(ecmf8Len)
        {
          if( reader->last_geo.geo_len!=ecmf8Len || 
             memcmp(reader->last_geo.geo, ecmf8Data, reader->last_geo.geo_len))
          {
            memcpy(reader->last_geo.geo, ecmf8Data, ecmf8Len);
            reader->last_geo.geo_len= ecmf8Len;
            insf8[3]=keynr;
            insf8[4]=ecmf8Len;
            write_cmd(insf8, ecmf8Data);
          }
        }
        ins88[2]=ecmf8Len?1:0;
        ins88[3]=keynr;
        ins88[4]= curEcm88len;

        // DE04
        if (DE04[0]==0xDE)
        {
            memcpy(DE04+6, (uchar *)ecm88Data, curEcm88len-6);
            write_cmd(ins88, DE04); // request dcw
        }
        else
        {
            write_cmd(ins88, (uchar *)ecm88Data); // request dcw
        }
        //
        write_cmd(insc0, NULL);	// read dcw
        switch(cta_res[0])
        {
          case 0xe8: // even
            if(cta_res[1]==8) { memcpy(er->cw,cta_res+2,8); rc=1; }
            break;
          case 0xe9: // odd
            if(cta_res[1]==8) { memcpy(er->cw+8,cta_res+2,8); rc=1; }
            break;
          case 0xea: // complete
            if(cta_res[1]==16) { memcpy(er->cw,cta_res+2,16); rc=1; }
            break;
          default :
            ecm88Data=nextEcm;
            ecm88Len-=curEcm88len;
            cs_debug("[viaccess-reader] ECM: key to use is not the current one, trying next ECM");
        }
    }
    else {
        ecm88Data=nextEcm;
        ecm88Len-=curEcm88len;
        cs_debug("[viaccess-reader] ECM: Unknown ECM type");
    }
  }

  if (hasD2) {
    if(reader->aes_list) {
        cs_log("Decoding CW : using AES key id %d for provider %06x",D2KeyID,provid);
        return (aes_decrypt_from_list(reader->aes_list,0x500, (uint32) provid, D2KeyID,er->cw, 16));
    }
    else
        aes_decrypt(er->cw, 16);
  }

  return(rc?OK:ERROR);
}

int viaccess_get_emm_type(EMM_PACKET *ep, struct s_reader * rdr)
{
	cs_debug_mask(D_EMM, "Entered viaccess_get_emm_type ep->emm[0]=%02x",ep->emm[0]);

	switch (ep->emm[0]) {
		case 0x8E:
			ep->type=SHARED;
			memset(ep->hexserial, 0, 8);
			memcpy(ep->hexserial, ep->emm + 3, 3);
			cs_debug_mask(D_EMM, "VIACCESS EMM: SHARED");
			return(!memcmp(&rdr->sa[0][0], ep->hexserial, 3));

		case 0x8C:
			ep->type=UNIQUE;
			memset(ep->hexserial, 0, 8);
			memcpy(ep->hexserial, ep->emm + 3, 3);
			cs_debug_mask(D_EMM, "VIACCESS EMM: UNIQUE");
			return(!memcmp(rdr->hexserial + 1, ep->hexserial, 4));

		case 0x8D:
			ep->type=GLOBAL;
			cs_debug_mask(D_EMM, "VIACCESS EMM: GLOBAL");
			return TRUE;

		default:
			ep->type = UNKNOWN;
			cs_debug_mask(D_EMM, "VIACCESS EMM: UNKNOWN");
			return TRUE;
	}	
}

void viaccess_get_emm_filter(struct s_reader * rdr, uchar *filter)
{
	filter[0]=0xFF;
	filter[1]=3;

	filter[2]=GLOBAL;
	filter[3]=0;

	filter[4+0]     = 0x8D;
	filter[4+0+16]  = 0xFF;
	filter[4+1]     = 0xFF; // FIXME: dummy, flood client with EMM's
	filter[4+1+16]  = 0xFF;


	filter[36]=SHARED;
	filter[37]=0;

	filter[38+0]    = 0x8E;
	filter[38+0+16] = 0xFF;
	memcpy(filter+38+1, &rdr->sa[0][0], 3);
	memset(filter+38+1+16, 0xFF, 3);


	filter[70]=UNIQUE;
	filter[71]=0;

	filter[72+0]    = 0x8C;
	filter[72+0+16] = 0xFF;
	memcpy(filter+72+1, rdr->hexserial + 1, 4);
	memset(filter+72+1+16, 0xFF, 4);

	return;
}

int viaccess_do_emm(struct s_reader * reader, EMM_PACKET *ep)
{
  def_resp;
  static unsigned char insa4[] = { 0xca,0xa4,0x04,0x00,0x03 }; // set provider id
  static unsigned char insf0[] = { 0xca,0xf0,0x00,0x01,0x22 }; // set adf
  static unsigned char insf4[] = { 0xca,0xf4,0x00,0x01,0x00 }; // set adf, encrypted
  static unsigned char ins18[] = { 0xca,0x18,0x01,0x01,0x00 }; // set subscription
  static unsigned char ins1c[] = { 0xca,0x1c,0x01,0x01,0x00 }; // set subscription, encrypted
  static unsigned char insc8[] = { 0xca,0xc8,0x00,0x00,0x02 }; // read extended status
  static unsigned char insc8Data[] = { 0x00,0x00 }; // data for read extended status

  int emmLen=SCT_LEN(ep->emm)-7;
  int rc=0;

  ///cs_dump(ep->emm, emmLen+7, "RECEIVED EMM VIACCESS");

  int emmUpToEnd;
  uchar *emmParsed = ep->emm+7;
  int provider_ok = 0;
  uchar keynr = 0;
  int ins18Len = 0;
  uchar ins18Data[512];
  uchar insData[512];
  uchar *nano81Data = 0;
  uchar *nano91Data = 0;
  uchar *nano92Data = 0;
  uchar *nano9EData = 0;
  uchar *nanoF0Data = 0;

  for (emmUpToEnd=emmLen; (emmParsed[1] != 0) && (emmUpToEnd > 0); emmUpToEnd -= (2 + emmParsed[1]), emmParsed += (2 + emmParsed[1])) {
    ///cs_dump (emmParsed, emmParsed[1] + 2, "NANO");

    if (emmParsed[0]==0x90 && emmParsed[1]==0x03) {
      /* identification of the service operator */

      uchar soid[3], ident[3], i;

      for (i=0; i<3; i++) {
        soid[i]=ident[i]=emmParsed[2+i];
      }
      ident[2]&=0xF0;
      keynr=soid[2]&0x0F;
      if (chk_prov(reader, ident, keynr)) {
        provider_ok = 1;
      } else {
        cs_debug("[viaccess-reader] EMM: provider or key not found on card (%x, %x)", ident, keynr);
        return ERROR;
      }

      // as we are maybe changing the used provider, clear the cache, so the next ecm will re-select the correct one
      memset(&reader->last_geo, 0, sizeof(reader->last_geo));

      // set provider
      write_cmd(insa4, soid);             
      if( cta_res[cta_lr-2]!=0x90 || cta_res[cta_lr-1]!=0x00 ) {
        cs_dump(insa4, 5, "set provider cmd:");
        cs_dump(soid, 3, "set provider data:");
        cs_log("[viaccess-reader] update error: %02X %02X", cta_res[cta_lr-2], cta_res[cta_lr-1]);
        return ERROR;
      }
    } else if (emmParsed[0]==0x9e && emmParsed[1]==0x20) {
      /* adf */

      if (!nano91Data) {
        /* adf is not crypted, so test it */

        uchar custwp;
        uchar *afd;

        custwp=reader->sa[0][3];
        afd=(uchar*)emmParsed+2;

        if( afd[31-custwp/8] & (1 << (custwp & 7)) )
          cs_debug("[viaccess-reader] emm for our card %08X", b2i(4, &reader->sa[0][0]));
        else
          return SKIPPED;
      }

      // memorize
      nano9EData = emmParsed;

    } else if (emmParsed[0]==0x81) {
      nano81Data = emmParsed;
    } else if (emmParsed[0]==0x91 && emmParsed[1]==0x08) {
      nano91Data = emmParsed;
    } else if (emmParsed[0]==0x92 && emmParsed[1]==0x08) {
      nano92Data = emmParsed;
    } else if (emmParsed[0]==0xF0 && emmParsed[1]==0x08) {
      nanoF0Data = emmParsed;
    } else if (emmParsed[0]==0x1D && emmParsed[0]==0x01 && emmParsed[0]==0x01) {
      /* from cccam... skip it... */
    } else {
      /* other nanos */
      show_subs(reader, emmParsed);
   
      memcpy(ins18Data+ins18Len, emmParsed, emmParsed[1] + 2);
      ins18Len += emmParsed [1] + 2;
    }
  }

  if (!provider_ok) {
    cs_debug("[viaccess-reader] provider not found in emm, continue anyway");
    // force key to 1...
    keynr = 1;
    ///return ERROR;
  }

  if (!nanoF0Data) {
    cs_dump(ep->emm, ep->l, "can't find 0xf0 in emm...");
    return ERROR; // error
  }

  if (nano9EData) {
    if (!nano91Data) {
      // set adf
      insf0[3] = keynr;  // key
      write_cmd(insf0, nano9EData); 
      if( cta_res[cta_lr-2]!=0x90 || cta_res[cta_lr-1]!=0x00 ) {
        cs_dump(insf0, 5, "set adf cmd:");
        cs_dump(nano9EData, 0x22, "set adf data:");
        cs_log("[viaccess-reader] update error: %02X %02X", cta_res[cta_lr-2], cta_res[cta_lr-1]);
        return ERROR;
      }
    } else {
      // set adf crypte
      insf4[3] = keynr;  // key
      insf4[4] = nano91Data[1] + 2 + nano9EData[1] + 2;
      memcpy (insData, nano91Data, nano91Data[1] + 2);
      memcpy (insData + nano91Data[1] + 2, nano9EData, nano9EData[1] + 2);
      write_cmd(insf4, insData); 
      if(( cta_res[cta_lr-2]!=0x90 && cta_res[cta_lr-2]!=0x91) || cta_res[cta_lr-1]!=0x00 ) {
        cs_dump(insf4, 5, "set adf encrypted cmd:");
        cs_dump(insData, insf4[4], "set adf encrypted data:");
        cs_log("[viaccess-reader] update error: %02X %02X", cta_res[cta_lr-2], cta_res[cta_lr-1]);
        return ERROR;
      }
    }
  }

  if (!nano92Data) {
    // send subscription
    ins18[4] = ins18Len + nanoF0Data[1] + 2;
    memcpy (insData, ins18Data, ins18Len);
    memcpy (insData + ins18Len, nanoF0Data, nanoF0Data[1] + 2);
    write_cmd(ins18, insData);
    if( cta_res[cta_lr-2]==0x90 && cta_res[cta_lr-1]==0x00 ) {
      cs_debug("[viaccess-reader] update successfully written");
      rc=1; // written
    } else {
      cs_dump(ins18, 5, "set subscription cmd:");
      cs_dump(insData, ins18[4], "set subscription data:");
      cs_log("[viaccess-reader] update error: %02X %02X", cta_res[cta_lr-2], cta_res[cta_lr-1]);
    }
    
  } else {
    // send subscription encrypted

    if (!nano81Data) {
      cs_dump(ep->emm, ep->l, "0x92 found, but can't find 0x81 in emm...");
      return ERROR; // error
    }

    ins1c[3] = keynr;  // key
    ins1c[4] = nano92Data[1] + 2 + nano81Data[1] + 2 + nanoF0Data[1] + 2;
    memcpy (insData, nano92Data, nano92Data[1] + 2);
    memcpy (insData + nano92Data[1] + 2, nano81Data, nano81Data[1] + 2);
    memcpy (insData + nano92Data[1] + 2 + nano81Data[1] + 2, nanoF0Data, nanoF0Data[1] + 2);
    write_cmd(ins1c, insData); 
    if( cta_res[cta_lr-2]!=0x90 || cta_res[cta_lr-1]!=0x00 ) {
      /* maybe a 2nd level status, so read it */
      ///cs_dump(ins1c, 5, "set subscription encrypted cmd:");
      ///cs_dump(insData, ins1c[4], "set subscription encrypted data:");
      ///cs_log("[viaccess-reader] update error: %02X %02X", cta_res[cta_lr-2], cta_res[cta_lr-1]);

      write_cmd(insc8, insc8Data); 
      if( cta_res[0] != 0x00 || cta_res[1] != 00 || cta_res[cta_lr-2]!=0x90 || cta_res[cta_lr-1]!=0x00 ) {
        ///cs_dump(cta_res, cta_lr, "extended status error:");
        return ERROR;
      } else {
        cs_debug("[viaccess-reader] update successfully written (with extended status OK)");
        rc=1; // written
      }
    } else {
      cs_debug("[viaccess-reader] update successfully written");
      rc=1; // written
    }
  }

  /*
  Sub Main()
    Sc.Write("CA A4 04 00 03")
    RX
    Sc.Write("02 07 11")
    RX
    Sc.Write("CA F0 00 01 22")
    RX
    Sc.Write("9E 20")
    Sc.Write("10 10 08 8A 80 00 04 00 10 10 26 E8 54 80 1E 80")
    Sc.Write("00 01 00 00 00 00 00 50 00 00 80 02 22 00 08 50")
    RX
    Sc.Write("CA 18 01 01 11")
    RX
    Sc.Write("A9 05 34 DE 34 FF 80")
    Sc.Write("F0 08 1A 3E AF B5 2B EE E3 3B")
    RX

    End Sub
*/
  return rc;
}

int viaccess_card_info(struct s_reader * reader)
{
  def_resp;
  int i, l, scls, show_cls;
  static uchar insac[] = { 0xca, 0xac, 0x00, 0x00, 0x00 }; // select data
  static uchar insb8[] = { 0xca, 0xb8, 0x00, 0x00, 0x00 }; // read selected data
  static uchar insa4[] = { 0xca, 0xa4, 0x00, 0x00, 0x00 }; // select issuer
  static uchar insc0[] = { 0xca, 0xc0, 0x00, 0x00, 0x00 }; // read data item
  static uchar ins24[] = { 0xca, 0x24, 0x00, 0x00, 0x09 }; // set pin

  static uchar cls[] = { 0x00, 0x21, 0xff, 0x9f};
  static uchar pin[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04};

  show_cls=reader->show_cls;
  memset(&reader->last_geo, 0, sizeof(reader->last_geo));

  cs_log("[viaccess-reader] card detected"); 
  
  // set pin
  write_cmd(ins24, pin);

  insac[2]=0xa4; write_cmd(insac, NULL); // request unique id
  insb8[4]=0x07; write_cmd(insb8, NULL); // read unique id
  cs_log("[viaccess-reader] serial: %llu", b2ll(5, cta_res+2));

  scls=0;
  insa4[2]=0x00; write_cmd(insa4, NULL); // select issuer 0
  for (i=1; (cta_res[cta_lr-2]==0x90) && (cta_res[cta_lr-1]==0); i++)
  {
    ulong l_provid, l_sa;
    uchar l_name[64];
    insc0[4]=0x1a; write_cmd(insc0, NULL); // show provider properties
    cta_res[2]&=0xF0;
    l_provid=b2i(3, cta_res);

    insac[2]=0xa5; write_cmd(insac, NULL); // request sa
    insb8[4]=0x06; write_cmd(insb8, NULL); // read sa
    l_sa=b2i(4, cta_res+2);

    insac[2]=0xa7; write_cmd(insac, NULL); // request name
    insb8[4]=0x02; write_cmd(insb8, NULL); // read name nano + len
    l=cta_res[1];
    insb8[4]=l; write_cmd(insb8, NULL); // read name
    cta_res[l]=0;
    trim((char *)cta_res);
    if (cta_res[0])
      snprintf((char *)l_name, sizeof(l_name), ", name: %s", cta_res);
    else
      l_name[0]=0;

    // read GEO
    insac[2]=0xa6; write_cmd(insac, NULL); // request GEO
    insb8[4]=0x02; write_cmd(insb8, NULL); // read GEO nano + len
    l=cta_res[1];
    insb8[4]=l; write_cmd(insb8, NULL); // read geo
    cs_ri_log(reader, "provider: %d, id: %06X%s, sa: %08X, geo: %s",
           i, l_provid, l_name, l_sa, (l<4) ? "empty" : cs_hexdump(1, cta_res, l));

    // read classes subscription
    insac[2]=0xa9; insac[4]=4;
    write_cmd(insac, cls); // request class subs
    scls=0;
    while( (cta_res[cta_lr-2]==0x90) && (cta_res[cta_lr-1]==0) )
    {
      insb8[4]=0x02; write_cmd(insb8, NULL); // read class subs nano + len
      if( (cta_res[cta_lr-2]==0x90) && (cta_res[cta_lr-1]==0) )
      {
        int fshow;
        l=cta_res[1];
        //fshow=(client[cs_idx].dbglvl==D_DUMP)?1:(scls < show_cls)?1:0;
        fshow=(scls<show_cls);
        insb8[4]=l; write_cmd(insb8, NULL); // read class subs
        if( (cta_res[cta_lr-2]==0x90) && (fshow) && 
            (cta_res[cta_lr-1]==0x00 || cta_res[cta_lr-1]==0x08) )
        {
          show_class(reader, NULL, cta_res, cta_lr-2);
          scls++;
        }
      }
    }

    insac[4]=0;
    insa4[2]=0x02; 
    write_cmd(insa4, NULL); // select next provider
  }
  //return ERROR;
  return OK;
}
