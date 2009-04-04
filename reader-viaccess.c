#include "globals.h"
#include "reader-common.h"

extern uchar cta_cmd[], cta_res[];
extern ushort cta_lr;

#define CMD_LEN 5

struct geo_cache
{
  ulong provid;
  uchar geo[256];
  uchar geo_len;
};

static struct geo_cache last_geo;

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

static void show_class(const char *p, const uchar *b, int l)
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
          cs_ri_log("class: %02X, expiry date: %04d/%02d/%02d - %04d/%02d/%02d", cls, 
                  vd.year_s+1980, vd.month_s, vd.day_s,
                  vd.year_e+1980, vd.month_e, vd.day_e);
      }
}

static void show_subs(const uchar *emm)
{  
  // emm -> A9, A6, B6

  switch( emm[0] )
  {
    case 0xA9:
      show_class("nano A9: ", emm+2, emm[1]);
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
      cs_log("nano A6: geo %s", szGeo);
      break;
    }
    case 0xB6:
    {
      uchar m; // modexp
      struct via_date vd;

      m=emm[emm[1]+1];
      parse_via_date(emm+2, &vd, 0);
      cs_log("nano B6: modexp %d%d%d%d%d%d: %02d/%02d/%04d", (m&0x20)?1:0, 
             (m&0x10)?1:0,(m&0x08)?1:0,(m&0x04)?1:0,(m&0x02)?1:0,(m&0x01)?1:0,
             vd.day_s, vd.month_s, vd.year_s+1980);
      break;
    }
  }
}

static int chk_prov(uchar *id, uchar keynr)
{
  int i, j, rc;
  for (rc=i=0; (!rc) && (i<reader[ridx].nprov); i++)
    if(!memcmp(&reader[ridx].prid[i][1], id, 3))
      for (j=0; (!rc) && (j<16); j++)
        if (reader[ridx].availkeys[i][j]==keynr)
          rc=1;
  return(rc);
}

static int card_write(uchar *cmd, uchar *data, int wflag)
{
  int l;
  uchar buf[256];
  memcpy(buf, cmd, CMD_LEN);
  l=wflag ? cmd[4] : 0;
  if (l && data) memcpy(buf+CMD_LEN, data, l);
  l=reader_cmd2icc(buf, CMD_LEN+l);
  return(l);
}

#define write_cmd(cmd, data) \
{ \
  if (card_write(cmd, data, 1)) return(0); \
}

#define read_cmd(cmd, data) \
{ \
  if (card_write(cmd, data, 0)) return(0); \
}

int viaccess_card_init(uchar *atr, int atrsize)
{
  int i;
  uchar buf[256];
  static uchar insac[] = { 0xca, 0xac, 0x00, 0x00, 0x00 }; // select data
  static uchar insb8[] = { 0xca, 0xb8, 0x00, 0x00, 0x00 }; // read selected data
  static uchar insa4[] = { 0xca, 0xa4, 0x00, 0x00, 0x00 }; // select issuer
  static uchar insc0[] = { 0xca, 0xc0, 0x00, 0x00, 0x00 }; // read data item

  static uchar insFAC[] = { 0x87, 0x02, 0x00, 0x00, 0x03 }; // init FAC
  static uchar FacDat[] = { 0x00, 0x00, 0x28 };

  if ((atr[0]!=0x3f) || (atr[1]!=0x77) || (atr[2]!=0x18) || (atr[9]!=0x68)) return(0);

  write_cmd(insFAC, FacDat);
  if( !(cta_res[cta_lr-2]==0x90 && cta_res[cta_lr-1]==0) )
    return(0);

//  switch((atr[atrsize-4]<<8)|atr[atrsize-3])
//  {
//    case 0x6268: ver="2.3"; break;
//    case 0x6668: ver="2.4(?)"; break;
//    case 0xa268:
//    default: ver="unknown"; break;
//  }
      
  reader[ridx].caid[0]=0x500;
  memset(reader[ridx].prid, 0xff, sizeof(reader[ridx].prid));
  insac[2]=0xa4; write_cmd(insac, NULL); // request unique id
  insb8[4]=0x07; read_cmd(insb8, NULL); // read unique id
  memcpy(reader[ridx].hexserial, cta_res+2, 5);
//  cs_log("type: viaccess, ver: %s serial: %llu", ver, b2ll(5, cta_res+2));
  cs_ri_log("type: viaccess(%sstandard atr), caid: %04X, serial: %llu",
        atr[9]==0x68?"":"non-",reader[ridx].caid[0], b2ll(5, cta_res+2));

  i=0;
  insa4[2]=0x00; write_cmd(insa4, NULL); // select issuer 0
  buf[0]=0;
  while((cta_res[cta_lr-2]==0x90) && (cta_res[cta_lr-1]==0))
  {
    insc0[4]=0x1a; read_cmd(insc0, NULL); // show provider properties
    cta_res[2]&=0xF0;
    reader[ridx].prid[i][0]=0;
    memcpy(&reader[ridx].prid[i][1], cta_res, 3);
    memcpy(&reader[ridx].availkeys[i][0], cta_res+10, 16);
    sprintf((char *)buf+strlen((char *)buf), ",%06lX", b2i(3, &reader[ridx].prid[i][1]));
//cs_log("buf: %s", buf);

    insac[2]=0xa5; write_cmd(insac, NULL); // request sa
    insb8[4]=0x06; read_cmd(insb8, NULL); // read sa
    memcpy(&reader[ridx].sa[i][0], cta_res+2, 4);

/*
    insac[2]=0xa7; write_cmd(insac, NULL); // request name
    insb8[4]=0x02; read_cmd(insb8, NULL); // read name nano + len
    l=cta_res[1];
    insb8[4]=l; read_cmd(insb8, NULL); // read name
    cta_res[l]=0;
cs_log("name: %s", cta_res);
*/

    insa4[2]=0x02;
    write_cmd(insa4, NULL); // select next issuer
    i++;
  }
  reader[ridx].nprov=i;
  cs_ri_log("providers: %d (%s)", reader[ridx].nprov, buf+1);
  cs_log("ready for requests");
  memset(&last_geo, 0, sizeof(last_geo));
  return(1);
}

int viaccess_do_ecm(ECM_REQUEST *er)
{
  static unsigned char insa4[] = { 0xca,0xa4,0x04,0x00,0x03 }; // set provider id
  static unsigned char ins88[] = { 0xca,0x88,0x00,0x00,0x00 }; // set ecm
  static unsigned char insf8[] = { 0xca,0xf8,0x00,0x00,0x00 }; // set geographic info 
  static unsigned char insc0[] = { 0xca,0xc0,0x00,0x00,0x12 }; // read dcw

  const uchar *ecm88Data=er->ecm+4; //XXX what is the 4th byte for ??
  int ecm88Len=SCT_LEN(er->ecm)-4;
  ulong provid;
  int rc=0;

  if (ecm88Data[0]==0x90 && ecm88Data[1]==0x03)
  {
    uchar ident[3], keynr;
    //uchar buff[256]; // MAX_LEN
    uchar *ecmf8Data=0;
    int ecmf8Len=0;

    memcpy (ident, &ecm88Data[2], sizeof(ident));
    provid = b2i(3, ident);
    ident[2]&=0xF0;
    keynr=ecm88Data[4]&0x0F;
    if (!chk_prov(ident, keynr))
    {
      cs_debug("smartcardviaccess ecm: provider or key not found on card");
      return(0);
    }
    ecm88Data+=5;
    ecm88Len-=5;

    if( last_geo.provid != provid ) 
    {
      last_geo.provid = provid;
      last_geo.geo_len = 0;
      last_geo.geo[0]  = 0;
      write_cmd(insa4, ident); // set provider
    }

    while(ecm88Len>0 && ecm88Data[0]<0xA0)
    {
      int nanoLen=ecm88Data[1]+2;
      if (!ecmf8Data)
        ecmf8Data=(uchar *)ecm88Data;
      ecmf8Len+=nanoLen;
      ecm88Len-=nanoLen;
      ecm88Data+=nanoLen;
    }
    if(ecmf8Len)
    {
      if( last_geo.geo_len!=ecmf8Len || 
         memcmp(last_geo.geo, ecmf8Data, last_geo.geo_len))
      {
        memcpy(last_geo.geo, ecmf8Data, ecmf8Len);
        last_geo.geo_len= ecmf8Len;
        insf8[3]=keynr;
        insf8[4]=ecmf8Len;
        write_cmd(insf8, ecmf8Data);
      }
    }
    ins88[2]=ecmf8Len?1:0;
    ins88[3]=keynr;
    ins88[4]=ecm88Len;
    write_cmd(ins88, (uchar *)ecm88Data);	// request dcw
    read_cmd(insc0, NULL);	// read dcw
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
    }
  }
  return(rc?1:0);
}

int viaccess_do_emm(EMM_PACKET *ep)
{
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
      if (chk_prov(ident, keynr)) {
        provider_ok = 1;
      } else {
        cs_debug("smartcardviaccess emm: provider or key not found on card (%x, %x)", ident, keynr);
        return 0;
      }

      // set provider
      write_cmd(insa4, soid);             
      if( cta_res[cta_lr-2]!=0x90 || cta_res[cta_lr-1]!=0x00 ) {
        cs_dump(insa4, 5, "set provider cmd:");
        cs_dump(soid, 3, "set provider data:");
        cs_log("update error: %02X %02X", cta_res[cta_lr-2], cta_res[cta_lr-1]);
        return 0;
      }
    } else if (emmParsed[0]==0x9e && emmParsed[1]==0x20) {
      /* adf */

      if (!nano91Data) {
        /* adf is not crypted, so test it */

        uchar custwp;
        uchar *afd;

        custwp=reader[ridx].sa[0][3];
        afd=(uchar*)emmParsed+2;

        if( afd[31-custwp/8] & (1 << (custwp & 7)) )
          cs_debug("emm for our card %08X", b2i(4, &reader[ridx].sa[0][0]));
        else
          return 2; // skipped
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
      show_subs(emmParsed);
   
      memcpy(ins18Data+ins18Len, emmParsed, emmParsed[1] + 2);
      ins18Len += emmParsed [1] + 2;
    }
  }

  if (!provider_ok) {
    cs_debug("viaccess: provider not found in emm... continue anyway...");
    // force key to 1...
    keynr = 1;
    ///return 0;
  }

  if (!nano9EData) {
    cs_dump(ep->emm, ep->l, "can't find 0x9e in emm, confidential used?");
    return 0; // error
  }

  if (!nanoF0Data) {
    cs_dump(ep->emm, ep->l, "can't find 0xf0 in emm...");
    return 0; // error
  }

  if (!nano91Data) {
    // set adf
    insf0[3] = keynr;  // key
    write_cmd(insf0, nano9EData); 
    if( cta_res[cta_lr-2]!=0x90 || cta_res[cta_lr-1]!=0x00 ) {
      cs_dump(insf0, 5, "set adf cmd:");
      cs_dump(nano9EData, 0x22, "set adf data:");
      cs_log("update error: %02X %02X", cta_res[cta_lr-2], cta_res[cta_lr-1]);
      return 0;
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
      cs_log("update error: %02X %02X", cta_res[cta_lr-2], cta_res[cta_lr-1]);
      return 0;
    }
  }

  if (!nano92Data) {
    // send subscription
    ins18[4] = ins18Len + nanoF0Data[1] + 2;
    memcpy (insData, ins18Data, ins18Len);
    memcpy (insData + ins18Len, nanoF0Data, nanoF0Data[1] + 2);
    write_cmd(ins18, insData);
    if( cta_res[cta_lr-2]==0x90 && cta_res[cta_lr-1]==0x00 ) {
      cs_debug("update successfully written");
      rc=1; // written
    } else {
      cs_dump(ins18, 5, "set subscription cmd:");
      cs_dump(insData, ins18[4], "set subscription data:");
      cs_log("update error: %02X %02X", cta_res[cta_lr-2], cta_res[cta_lr-1]);
    }
    
  } else {
    // send subscription encrypted

    if (!nano81Data) {
      cs_dump(ep->emm, ep->l, "0x92 found, but can't find 0x81 in emm...");
      return 0; // error
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
      ///cs_log("update error: %02X %02X", cta_res[cta_lr-2], cta_res[cta_lr-1]);

      read_cmd(insc8, insc8Data); 
      if( cta_res[0] != 0x00 || cta_res[1] != 00 || cta_res[cta_lr-2]!=0x90 || cta_res[cta_lr-1]!=0x00 ) {
        ///cs_dump(cta_res, cta_lr, "extended status error:");
        return 0;
      } else {
        cs_debug("update successfully written (with extended status OK)");
        rc=1; // written
      }
    } else {
      cs_debug("update successfully written");
      rc=1; // written
    }
  }

  memset(&last_geo, 0, sizeof(last_geo));

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

int viaccess_card_info(void)
{
  int i, l, scls, show_cls;
  static uchar insac[] = { 0xca, 0xac, 0x00, 0x00, 0x00 }; // select data
  static uchar insb8[] = { 0xca, 0xb8, 0x00, 0x00, 0x00 }; // read selected data
  static uchar insa4[] = { 0xca, 0xa4, 0x00, 0x00, 0x00 }; // select issuer
  static uchar insc0[] = { 0xca, 0xc0, 0x00, 0x00, 0x00 }; // read data item
  static uchar ins24[] = { 0xca, 0x24, 0x00, 0x00, 0x09 }; // set pin

  static uchar cls[] = { 0x00, 0x21, 0xff, 0x9f};
  static uchar pin[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04};

  show_cls=reader[ridx].show_cls;
  memset(&last_geo, 0, sizeof(last_geo));

  // set pin
  write_cmd(ins24, pin);

  insac[2]=0xa4; write_cmd(insac, NULL); // request unique id
  insb8[4]=0x07; read_cmd(insb8, NULL); // read unique id
  cs_log("serial: %llu", b2ll(5, cta_res+2));

  scls=0;
  insa4[2]=0x00; write_cmd(insa4, NULL); // select issuer 0
  for (i=1; (cta_res[cta_lr-2]==0x90) && (cta_res[cta_lr-1]==0); i++)
  {
    ulong l_provid, l_sa;
    uchar l_name[64];
    insc0[4]=0x1a; read_cmd(insc0, NULL); // show provider properties
    cta_res[2]&=0xF0;
    l_provid=b2i(3, cta_res);

    insac[2]=0xa5; write_cmd(insac, NULL); // request sa
    insb8[4]=0x06; read_cmd(insb8, NULL); // read sa
    l_sa=b2i(4, cta_res+2);

    insac[2]=0xa7; write_cmd(insac, NULL); // request name
    insb8[4]=0x02; read_cmd(insb8, NULL); // read name nano + len
    l=cta_res[1];
    insb8[4]=l; read_cmd(insb8, NULL); // read name
    cta_res[l]=0;
    trim((char *)cta_res);
    if (cta_res[0])
      snprintf((char *)l_name, sizeof(l_name), ", name: %s", cta_res);
    else
      l_name[0]=0;

    // read GEO
    insac[2]=0xa6; write_cmd(insac, NULL); // request GEO
    insb8[4]=0x02; read_cmd(insb8, NULL); // read GEO nano + len
    l=cta_res[1];
    insb8[4]=l; read_cmd(insb8, NULL); // read geo
    cs_ri_log("provider: %d, id: %06X%s, sa: %08X, geo: %s",
           i, l_provid, l_name, l_sa, (l<4) ? "empty" : cs_hexdump(1, cta_res, l));

    // read classes subscription
    insac[2]=0xa9; insac[4]=4;
    write_cmd(insac, cls); // request class subs
    scls=0;
    while( (cta_res[cta_lr-2]==0x90) && (cta_res[cta_lr-1]==0) )
    {
      insb8[4]=0x02; read_cmd(insb8, NULL); // read class subs nano + len
      if( (cta_res[cta_lr-2]==0x90) && (cta_res[cta_lr-1]==0) )
      {
        int fshow;
        l=cta_res[1];
        //fshow=(client[cs_idx].dbglvl==D_DUMP)?1:(scls < show_cls)?1:0;
        fshow=(scls<show_cls);
        insb8[4]=l; read_cmd(insb8, NULL); // read class subs
        if( (cta_res[cta_lr-2]==0x90) && (fshow) && 
            (cta_res[cta_lr-1]==0x00 || cta_res[cta_lr-1]==0x08) )
        {
          show_class(NULL, cta_res, cta_lr-2);
          scls++;
        }
      }
    }

    insac[4]=0;
    insa4[2]=0x02; 
    write_cmd(insa4, NULL); // select next provider
  }

  return 0;
}
