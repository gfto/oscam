#include "globals.h"
#include "reader-common.h"

extern uchar cta_cmd[], cta_res[];
extern ushort cta_lr;

#define CMD_LEN 5

static unsigned int Conax_ToDate(char data0, char data1) 
{ /* decimal: yyyymmdd */
  int y,m,d;
  unsigned int l;

  y= 1990+ ((data1>>4) + ((data0>>5)&0x7)*10);
  m= data1&0xf;
  d= data0&0x1f;
  l=  (y*100+m)*100+d;
  return l;
}

static char *chid_date(uchar *ptr, char *buf, int l)
{
  if (buf)
  {
    snprintf(buf, l, "%04d/%02d/%02d",
                     1990+(ptr[1]>>4)+(((ptr[0]>>5)&7)*10), ptr[1]&0xf, ptr[0]&0x1f);
  }
  return(buf);
}


static int card_write(uchar *cmd, uchar *data, int wflag)
{
  int l;
  uchar buf[MAX_LEN];
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

static int read_record(uchar *cmd, uchar *data)
{
  uchar insCA[] = {0xDD, 0xCA, 0x00, 0x00, 0x00};

  write_cmd(cmd, data);		// select record
  if (cta_res[0]!=0x98)
    return(-1);
  insCA[4]=cta_res[1];		// get len
  read_cmd(insCA, NULL);	// read record
  if ((cta_res[cta_lr-2]!=0x90) || (cta_res[cta_lr-1]))
    return(-1);
  return(cta_lr-2);
}

int conax_card_init(uchar *atr, int atrsize)
{
  int i, j, n;
  uchar atr_0b00[] = { '0', 'B', '0', '0' };
  uchar ins26[] = {0xDD, 0x26, 0x00, 0x00, 0x03, 0x10, 0x01, 0x01};
//  uchar ins82[] = {0xDD, 0x82, 0x00, 0x00, 0x14, 0x11, 0x12, 0x01, 0xB0, 0x0F, 0xFF, 0xFF, 0xDD, 0x00, 0x00, 0x09, 0x04, 0x0B, 0x00, 0xE0, 0x30, 0x1B, 0x64, 0x3D, 0xFE};
  uchar ins82[]= {0xDD, 0x82, 0x00, 0x00, 0x10, 0x11, 0x0e, 0x01, 0xb0, 0x0f, 0xff, 0xff, 0xc5, 0x00, 0x00, 0x09, 0x04, 0x0b, 0x00, 0xe0, 0x30};
  uchar cardver=0;

  if ((memcmp(atr+3, atr_0b00, sizeof(atr_0b00))) &&
      (memcmp(atr+4, atr_0b00, sizeof(atr_0b00))))
    return(0);

  reader[ridx].caid[0]=0xB00;

  if ((n=read_record(ins26, ins26+5))<0) return(0);	// read caid, card-version
  for (i=0; i<n; i+=cta_res[i+1]+2)
    switch(cta_res[i])
    {
      case 0x20: cardver=cta_res[i+2]; break;
      case 0x28: reader[ridx].caid[0]=(cta_res[i+2]<<8)|cta_res[i+3];
    }

  if ((n=read_record(ins82, ins82+5))<0) return(0);	// read serial
  for (j=0, i=2; i<n; i+=cta_res[i+1]+2)
    switch(cta_res[i])
    {
      case 0x23: if (!j) memcpy(reader[ridx].hexserial, &cta_res[i+3], 6);
                 j++;
    }

  cs_ri_log("type: conax, caid: %04X, serial: %llu, card: v%d",
         reader[ridx].caid[0], b2ll(6, reader[ridx].hexserial), cardver);
  cs_log("ready for requests");
  return(1);
}

int conax_do_ecm(ECM_REQUEST *er)
{
  int i, n, rc=0;
  unsigned char insA2[] = { 0xDD,0xA2,0x00,0x00,0x00 };
  unsigned char insCA[] = { 0xDD,0xCA,0x00,0x00,0x00 };
  unsigned char buf[256];

  if ((n=CheckSctLen(er->ecm, 3))<0)
    return(0);
  buf[0]=0x14;
  buf[1]=n+1;
  buf[2]=0;
  memcpy(buf+3, er->ecm, n);
  insA2[4]=n+3;
  write_cmd(insA2, buf);
  while ((cta_res[cta_lr-2]==0x98) &&
         ((insCA[4]=cta_res[cta_lr-1])>0) && (insCA[4]!=0xFF))
  {
    read_cmd(insCA, NULL);
    if ((cta_res[cta_lr-2]==0x98) ||
        ((cta_res[cta_lr-2]==0x90) && (!cta_res[cta_lr-1])))
    {
      for(i=0; i<cta_lr-2; i+=cta_res[i+1]+2)
        if ((cta_res[i]==0x25) &&	// access: is cw
            (cta_res[i+1]>=0xD) &&	// 0xD: 5 header + 8 cw
            !((n=cta_res[i+4])&0xFE))	// cw idx must be 0 or 1
        {
          rc|=(1<<n);
          memcpy(er->cw+(n<<3), cta_res+i+7, 8);
        }
    }
  }
  return(rc==3);
}

int conax_do_emm(EMM_PACKET *ep)
{
  int rc=0;
  return(rc);
}

int conax_card_info(void)
{
  int type, i, j, k, n=0;
  ushort provid;
  char provname[32], pdate[32];
  uchar insC6[] = {0xDD, 0xC6, 0x00, 0x00, 0x03, 0x1C, 0x01, 0x00};
  uchar ins26[] = {0xDD, 0x26, 0x00, 0x00, 0x03, 0x1C, 0x01, 0x01};
  uchar insCA[] = {0xDD, 0xCA, 0x00, 0x00, 0x00};
  char *txt[] = { "provider", "ppvevent" };
  uchar *cmd[] = { insC6, ins26 };

  for (type=0; type<2; type++)
  {
    n=0;
    write_cmd(cmd[type], cmd[type]+5);
    while (cta_res[cta_lr-2]==0x98)
    {
      insCA[4]=cta_res[1];		// get len
      read_cmd(insCA, NULL);		// read
      if ((cta_res[cta_lr-2]==0x90) || (cta_res[cta_lr-2]==0x98))
      {
        for (j=0; j<cta_lr-2; j+=cta_res[j+1]+2)
        {
          provid=(cta_res[j+2+type]<<8) | cta_res[j+3+type];
          for (k=0, i=j+4+type; (i<j+cta_res[j+1]) && (k<2); i+=cta_res[i+1]+2)
          {
            int l;
            switch(cta_res[i])
            {
              case 0x01: l=(cta_res[i+1]<(sizeof(provname)-1)) ?
                           cta_res[i+1] : sizeof(provname)-1;
                         memcpy(provname, cta_res+i+2, l);
                         provname[l]='\0';
                         break;
              case 0x30: chid_date(cta_res+i+2, pdate+(k++<<4), 15);
                         break;
            }
          }
          cs_ri_log("%s: %d, id: %04X, date: %s - %s, name: %s",
                    txt[type], ++n, provid, pdate, pdate+16, trim(provname));
        }
      }
    }
  }
  return(1);
}
