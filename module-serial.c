#include "globals.h"
#include <termios.h>
extern struct s_reader *reader;

#define HSIC_CRC 0xA5
#define SSSP_MAX_PID 8

#define P_HSIC	    1	// Humax Sharing Interface Client
#define P_SSSP	    2	// Simple Serial Sharing Protocol
#define P_BOMBA	    3	// This is not really a Protocol
#define P_DSR95	    4	// DSR9500 with SID
#define P_GS	    5	// GS7001
#define P_ALPHA	    6	// AlphaStar Receivers
#define P_DSR95_OLD 7	// DSR9500 without SID
#define P_GBOX      8	// Arion with gbox
#define P_MAX	    P_GBOX
#define P_AUTO	    0xFF

#define P_DSR_AUTO    0
#define P_DSR_GNUSMAS 1
#define P_DSR_OPEN    2
#define P_DSR_PIONEER 3
#define P_DSR_WITHSID 4
#define P_DSR_UNKNOWN 5

#define IS_ECM	0	// incoming data is ECM
#define IS_DCW	1	// incoming data is DCW
#define IS_PMT	2	// incoming data is PMT
#define IS_LGO	3	// incoming data is client logon
#define IS_ECHO 4	// incoming data is DCW echo from Samsung
#define IS_CAT  5	// incoming data is CAT
#define IS_BAD	0xFF	// incoming data is unknown

static const char *proto_txt[]={"unknown", "hsic", "sssp", "bomba", "dsr9500", "gs", 
                          "alpha", "dsr9500old", "gbox"};
static const char *dsrproto_txt[]={"unknown", "samsung", "openbox", "pioneer",
                             "extended", "unknown"};
static const char *incomplete="incomplete request (%d bytes)";
static int connected=0;
static struct timeb tps, tpe;
static char oscam_ser_usr[32]={0};
static char oscam_ser_device[64]={0};
static speed_t oscam_ser_baud=0;
static int oscam_ser_delay=0;
static int oscam_ser_timeout=50;
static int oscam_ser_proto=0;
int serial_errors=0;
static int dsr9500type=P_DSR_AUTO;
static int samsung_0a=0;   // number of 0A in ALL dcw sent into samsung
static int samsung_dcw=0;  // number of dcw sent into samsung before echo or ecm is received

typedef struct s_gbox
{
  int cat_len;
  int pmt_len;
  int ecm_len;
} GCC_PACK GBOX_LENS;

typedef struct s_sssp
{
  ushort caid;
  ushort pid;
  ulong  prid;
} GCC_PACK SSSP_TAB;


GBOX_LENS gbox_lens;
SSSP_TAB sssp_tab[SSSP_MAX_PID];
ushort sssp_srvid;
int sssp_num=0, sssp_fix=0;

static int oscam_ser_alpha_convert(uchar *buf, int l)
{
  int i;
  if (buf[0]==0x7E)		// normalize
  {
    l-=2;
    memmove(buf, buf+1, l);	// remove BOT/EOT
    for (i=0; i<l; i++)
      if (buf[i]==0x20)
      {
        memmove(buf+i, buf+i+1, --l);
        buf[i]^=0x20;
      }
  }
  else				// to alphastar
  {
    memmove(buf+1, buf, l++);	// insert BOT
    buf[0]=0x7E;
    for (i=1; i<l; i++)
      if ((buf[i]==0x20) || (buf[i]==0x7E) || (buf[i]==0x7F))
      {
        buf[i]^=0x20;
        memmove(buf+i+1, buf+i, l++);
        buf[i++]=0x20;
      }
    buf[l++]=0x7F;		// insert EOT
  }
  return(l);
}

static void oscam_ser_disconnect(void);

static int oscam_ser_parse_url(char *url)
{
  char *service, *usr, *dev, *baud=NULL, *dummy, *para;

  oscam_ser_proto=P_AUTO;
  if( (dummy=strstr(url, "://")) )
  {
    int i;
    service=url;
    url=dummy+3;
    *dummy=0;
    for (i=1; i<=P_MAX; i++)
      if (!strcmp(service, proto_txt[i]))
        oscam_ser_proto=i;
  }
  if ((!client[cs_idx].is_server) && (oscam_ser_proto==P_AUTO)) return(0);
  switch(oscam_ser_proto)	// set the defaults
  {
    case P_GS:
      oscam_ser_timeout=500;
      oscam_ser_baud=B19200;
      break;
    default:
      oscam_ser_timeout=50;
#ifdef B115200
      oscam_ser_baud=B115200;
#else
      oscam_ser_baud=B9600;
#endif
  }

  switch( oscam_ser_proto )
  {
    case P_DSR95:
      dsr9500type=(client[cs_idx].is_server)?P_DSR_AUTO:P_DSR_WITHSID;
      break;
    case P_DSR95_OLD:
      dsr9500type=P_DSR_AUTO;
      oscam_ser_proto=P_DSR95;
  }

  usr=url;
  if( (dev=strchr(usr, '@')) )
  {
    *dev++='\0';
    if( (dummy=strchr(usr, ':')) )	// fake pwd
      *dummy++='\0';
    if ((client[cs_idx].is_server) && (!usr[0])) return(0);
  }
  else
  {
    if (client[cs_idx].is_server) return(0);	// user needed in server-mode
    dev=usr;
  }
  if( (baud=strchr(dev, ':'))	)// port = baud
    *baud++='\0';
  dummy=baud ? baud : dev;
  if( (para=strchr(dummy, '?')) )
  {
    char *ptr1, *ptr2;
    *para++='\0';
    for (ptr1=strtok(para, "&"); ptr1; ptr1=strtok(NULL, "&"))
    {
      if (!(ptr2=strchr(ptr1, '='))) continue;
      *ptr2++='\0';
      strtolower(ptr1);
      if (!strcmp("delay"  , ptr1)) oscam_ser_delay  =atoi(ptr2);
      if (!strcmp("timeout", ptr1)) oscam_ser_timeout=atoi(ptr2);
    }
  }
  if (baud)
  {
    trim(baud);
#ifdef B115200
    if (!strcmp(baud, "115200"))
      oscam_ser_baud=B115200;
    else
#endif
#ifdef B57600
    if (!strcmp(baud, "57600"))
      oscam_ser_baud=B57600;
    else
#endif
    if (!strcmp(baud, "38400"))
      oscam_ser_baud=B38400;
    else if (!strcmp(baud, "19200"))
      oscam_ser_baud=B19200;
    else if (!strcmp(baud, "9600"))
      oscam_ser_baud=B9600;
  }
  cs_strncpy(oscam_ser_usr, usr, sizeof(oscam_ser_usr));
  cs_strncpy(oscam_ser_device, dev, sizeof(oscam_ser_device));
  return(oscam_ser_baud);
}

static void oscam_ser_set_baud(struct termios *tio, speed_t baud)
{
  cfsetospeed(tio, baud);
  cfsetispeed(tio, baud);
}

static int oscam_ser_set_serial_device(int fd)
{
  struct termios tio;

  memset(&tio, 0, sizeof(tio));
  //  tio.c_cflag = (CS8 | CREAD | HUPCL | CLOCAL);
  tio.c_cflag = (CS8 | CREAD | CLOCAL);
  tio.c_iflag = IGNPAR;
  tio.c_cc[VMIN] = 1;
  tio.c_cc[VTIME] = 0;
//#if !defined(OS_CYGWIN32)
  oscam_ser_set_baud(&tio, B1200);
  tcsetattr(fd, TCSANOW, &tio);
  cs_sleepms(500);
//#endif
  oscam_ser_set_baud(&tio, oscam_ser_baud);
  return(tcsetattr(fd, TCSANOW, &tio));
}

static int oscam_ser_poll(int event)
{
  int msec;
  struct pollfd pfds;
  struct timeb tpc;
  cs_ftime(&tpc);
  msec=1000*(tpe.time-tpc.time)+tpe.millitm-tpc.millitm;
  if (msec<0)
    return(0);
  pfds.fd=client[cs_idx].pfd;
  pfds.events=event;
  pfds.revents=0;
  if (poll(&pfds, 1, msec)!=1)
    return(0);
  else
    return(((pfds.revents)&event)==event);
}

static int oscam_ser_write(uchar *buf, int n)
{
  int i;
  for (i=0; (i<n) && (oscam_ser_poll(POLLOUT)); i++)
  {
    if (oscam_ser_delay)
      cs_sleepms(oscam_ser_delay);
    if (write(client[cs_idx].pfd, buf+i, 1)<1)
      break;
  }
  return(i);
}

static int oscam_ser_send(uchar *buf, int l)
{
  int n;
  if (!client[cs_idx].pfd) return(0);
  cs_ftime(&tps);
  tpe=tps;
  tpe.millitm+=oscam_ser_timeout+(l*(oscam_ser_delay+1));
  tpe.time+=(tpe.millitm/1000);
  tpe.millitm%=1000;
  n=oscam_ser_write(buf, l);
  cs_ftime(&tpe);
  cs_ddump(buf, l, "send %d of %d bytes to %s in %d msec", n, l, remote_txt(),
                    1000*(tpe.time-tps.time)+tpe.millitm-tps.millitm);
  if (n!=l)
    cs_log("transmit error. send %d of %d bytes only !", n, l);
  return(n);
}

static int oscam_ser_selrec(uchar *buf, int n, int l, int *c)
{
  int i;
  if (*c+n>l)
    n=l-*c;
  if (n<=0) return(0);
  for (i=0; (i<n) && (oscam_ser_poll(POLLIN)); i++)
    if (read(client[cs_idx].pfd, buf+*c, 1)<1 )
      return(0);
    else
      (*c)++;
  return(i==n);
}

static int oscam_ser_recv(uchar *xbuf, int l)
{
  int s, p, n, r;
  uchar job=IS_BAD;
  static uchar lb;
  static int have_lb=0;
  uchar *buf=xbuf+1;

  if (!client[cs_idx].pfd) return(-1);
  cs_ftime(&tps);
  tpe=tps;
  tpe.millitm+=oscam_ser_timeout;
  tpe.time+=(tpe.millitm/1000);
  tpe.millitm%=1000;
  buf[0]=lb;
  for (s=p=r=0, n=have_lb; (s<4) && (p>=0); s++)
  {
    switch(s)
    {
      case 0:		// STAGE 0: skip known garbage from DSR9500
        if (oscam_ser_selrec(buf, 2-n, l, &n))
        {
          if ((buf[0]==0x0A) && (buf[1]==0x0D))
            p=(-4);
          if ((buf[0]==0x0D) && (buf[1]==0x0A))
            p=(-4);
        }
        else
          p=(-3);
        have_lb=0;
        break;
      case 1:		// STAGE 1: identify protocol
        p=(-3);
        if (oscam_ser_selrec(buf, 1, l, &n)) // now we have 3 bytes in buf
        {
          p=(-2);
          if (client[cs_idx].is_server)		 // HERE IS SERVER
          {
            job=IS_ECM;		// assume ECM
            switch(buf[0])
            {
              case 0x00: if( (buf[1]==0x01)&&(buf[2]==0x00) )
                           { p=P_GS; job=IS_LGO; tpe.time++; } break;
              case 0x01: if( (buf[1]&0xf0)==0xb0 ) p=P_GBOX;
                         else  {p=P_SSSP; job=IS_PMT;}
                         break;	// pmt-request
              case 0x02: p=P_HSIC; break;
              case 0x03: switch(oscam_ser_proto)
                         {
                           case P_SSSP  :
                           case P_GS    :
                           case P_DSR95 : p=oscam_ser_proto; break;
                           case P_AUTO  : p=(buf[1]<0x30) ? P_SSSP : P_DSR95;
                                          break;	// auto for GS is useless !!
                         } break;
              case 0x04: p=P_DSR95; job=IS_ECHO; dsr9500type=P_DSR_GNUSMAS; break;
              case 0x7E: p=P_ALPHA; if (buf[1]!=0x80) job=IS_BAD; break;
              case 0x80:
              case 0x81: p=P_BOMBA; break;
            }
          }
          else				// HERE IS CLIENT
          {
            job=IS_DCW;		// assume DCW
            switch(oscam_ser_proto)
            {
              case P_HSIC : if ((buf[0]==4) && (buf[1]==4)) p=P_HSIC; break;
              case P_BOMBA: p=P_BOMBA; break;
              case P_DSR95: if (buf[0]==4) p=P_DSR95; break;
              case P_ALPHA: if (buf[0]==0x88) p=P_ALPHA; break;
            }
          }
          if ((oscam_ser_proto!=p) && (oscam_ser_proto!=P_AUTO))
            p=(-2);
        }
        break;
      case 2:		// STAGE 2: examine length
        if (client[cs_idx].is_server) switch(p)
        {
          case P_SSSP  : r=(buf[1]<<8)|buf[2]; break;
          case P_BOMBA : r=buf[2]; break;
          case P_HSIC  : if (oscam_ser_selrec(buf, 12, l, &n)) r=buf[14];
                         else p=(-1);
                         break;
          case P_DSR95 : if( job==IS_ECHO )
                         {
                           r=17*samsung_dcw-3+samsung_0a;
                           samsung_dcw=samsung_0a=0;
                         }
                         else 
                         {
                           if (oscam_ser_selrec(buf, 16, l, &n))
                           {
                             uchar b;
                             if (cs_atob(&b, (char *)buf+17, 1)<0)
                               p=(-2);
                             else {
                               r=(b<<1);
                               r+=(dsr9500type==P_DSR_WITHSID)?4:0;
                             }
                           }
                           else p=(-1);
                         }
                         break;
          case P_GS    : if (job==IS_LGO)
                           r=5;
                         else
                         {
                           if (oscam_ser_selrec(buf, 1, l, &n))
                             r=(buf[3]<<8)|buf[2];
                           else p=(-1);
                         }
                         break;
          case P_ALPHA : r=-0x7F;	// char specifying EOT
                         break;
          case P_GBOX  : r=((buf[1]&0xf)<<8) | buf[2];
                         gbox_lens.cat_len = r;
                         break;
          default      : dsr9500type=P_DSR_AUTO;
        }
        else switch(p)
        {
          case P_HSIC   : r=(buf[2]==0x3A) ? 20 : 0; break; // 3A=DCW / FC=ECM was wrong
          case P_BOMBA  : r=13; break;
          case P_DSR95  : r=14; break;
          case P_ALPHA  : r=(buf[1]<<8)|buf[2]; break;	// should be 16 always
        }
        break;
      case 3:		// STAGE 3: get the rest ...
        if (r>0)	// read r additional bytes
        {
          int all = n+r;
          if( !oscam_ser_selrec(buf, r, l, &n) )
          {
            cs_debug("not all data received, waiting another 50 ms");
            tpe.millitm+=50;
            if( !oscam_ser_selrec(buf, all-n, l, &n) )
              p=(-1);
          }
          // auto detect DSR9500 protocol
          if( client[cs_idx].is_server && p==P_DSR95 && dsr9500type==P_DSR_AUTO )
          {
            tpe.millitm+=20;
            if( oscam_ser_selrec(buf, 2, l, &n) ) 
            {
              if( cs_atoi((char *)buf+n-2, 1, 1)==0xFFFFFFFF )
              {
                switch( (buf[n-2]<<8)|buf[n-1] )
                {
                  case 0x0A0D : dsr9500type=P_DSR_OPEN; break;
                  case 0x0D0A : dsr9500type=P_DSR_PIONEER; break;
                  default     : dsr9500type=P_DSR_UNKNOWN; break;
                }
              }else{
                if( oscam_ser_selrec(buf, 2, l, &n) )
                  if( cs_atoi((char *)buf+n-2, 1, 1)==0xFFFFFFFF )
                    dsr9500type=P_DSR_UNKNOWN;
                  else
                    dsr9500type=P_DSR_WITHSID;
                else {
                  dsr9500type=P_DSR_UNKNOWN;
                  p=(-1);
                }
              }
            }
            else 
              dsr9500type=P_DSR_GNUSMAS;
            if( p )
              cs_log("detected dsr9500-%s type receiver", 
                      dsrproto_txt[dsr9500type]);
          } 
          // gbox
          if( client[cs_idx].is_server && p==P_GBOX )
          {
            int j;
            for( j=0; (j<3) && (p>0); j++)
              switch( j )
              {
                case 0: // PMT head
                  if( !oscam_ser_selrec(buf, 3, l, &n) )
                    p=(-1);
                  else if( !(buf[n-3]==0x02 && (buf[n-2]&0xf0)==0xb0) )
                    p=(-2);
                  break;
                case 1: // PMT + ECM header
                  gbox_lens.pmt_len=((buf[n-2]&0xf)<<8)|buf[n-1];
                  if( !oscam_ser_selrec(buf, gbox_lens.pmt_len+3, l, &n) ) 
                    p=(-1);
                  break;
                case 2: // ECM + ECM PID
                  gbox_lens.ecm_len=((buf[n-2]&0xf)<<8)|buf[n-1];
                  if( !oscam_ser_selrec(buf, gbox_lens.ecm_len+4, l, &n) ) 
                    p=(-1);
              }
          } // gbox
        } 
        else if (r<0)	// read until specified char (-r)
        {
          while((buf[n-1]!=(-r)) && (p>0))
            if (!oscam_ser_selrec(buf, 1, l, &n))
              p=(-1);
        }
        break;
    }
  }
  if (p==(-2) || p==(-1)) {
    oscam_ser_selrec(buf, l-n, l, &n);	// flush buffer
    serial_errors++;
  }
  cs_ftime(&tpe);
  cs_ddump(buf, n, "received %d bytes from %s in %d msec", n, remote_txt(),
                    1000*(tpe.time-tps.time)+tpe.millitm-tps.millitm);
  client[cs_idx].last=tpe.time;
  switch(p)
  {
    case (-1): if (client[cs_idx].is_server&&(n>2)&&(buf[0]==2)&&(buf[1]==2)&&(buf[2]==2))
               {
                 oscam_ser_disconnect();
                 cs_log("humax powered on");	// this is nice ;)
               }
               else
                 cs_log(incomplete, n);
               break;
    case (-2): cs_debug("unknown request or garbage"); 
               break;
  }
  xbuf[0]=(uchar) ((job<<4) | p);
  return((p<0)?0:n+1);
}

/*
 *	server functions
 */

static void oscam_ser_disconnect_client()
{
  uchar mbuf[1024];
  switch(connected ? connected : oscam_ser_proto)
  {
    case P_GS:
      mbuf[0] = 0x01;
      mbuf[1] = 0x00;
      mbuf[2] = 0x00;
      mbuf[3] = 0x00;
      oscam_ser_send(mbuf, 4);
      break;
  }
  dsr9500type=P_DSR_AUTO;
  serial_errors=0;
}

static void oscam_ser_init_client()
{
  uchar mbuf[1024];
  switch(oscam_ser_proto)		// sure, does not work in auto-mode
  {
    case P_GS:
      oscam_ser_disconnect_client(); // send disconnect first
      cs_sleepms(300);		        // wait a little bit
      mbuf[0] = 0x00;
      mbuf[1] = 0x00;
      mbuf[2] = 0x00;
      mbuf[3] = 0x00;
      oscam_ser_send(mbuf, 4);	// send connect
      break;
  }
}

static void oscam_ser_disconnect()
{
  oscam_ser_disconnect_client();
  if (connected)
    cs_log("%s disconnected (%s)", username(cs_idx), proto_txt[connected]);
  connected=0;
}

static void oscam_ser_auth_client(int proto)
{
  int ok = 0;
  // After reload base account ptrs may be placed in other address,
  // and we may can't find it in this process. 
  // Simply save valid account.
  struct s_auth *account=0; 

  if (connected==proto)
    return;
  if (connected)
    oscam_ser_disconnect();
  connected=proto;
  if( !account )
  {
    client[cs_idx].usr[0]=0;
    for (ok=0, account=cfg->account; (account) && (!ok); account=account->next)
      if( (ok=!strcmp(oscam_ser_usr, account->usr)) )
        break;
  }
  cs_auth_client(ok ? account : (struct s_auth *)(-1), proto_txt[connected]);
}

static void oscam_ser_send_dcw(ECM_REQUEST *er)
{
  uchar mbuf[1024];
  int i;
  uchar crc;
  if (er->rc<4)		// found
    switch(connected)
    {
      case P_HSIC:
        for (i=0, crc=HSIC_CRC; i<16; i++)
          crc^=er->cw[i];
        memset(mbuf   , 0x04  ,  2);
        memset(mbuf+2 , 0x3a  ,  2);
        memcpy(mbuf+4 , er->cw, 16);
        memcpy(mbuf+20, &crc  ,  1);
        memset(mbuf+21, 0x1b  ,  2);
        oscam_ser_send(mbuf, 23);
        break;
      case P_SSSP:
        mbuf[0]=0xF2;
        mbuf[1]=0;
        mbuf[2]=16;
        memcpy(mbuf+3, er->cw, 16);
        oscam_ser_send(mbuf, 19);
        if (!sssp_fix)
        {
          mbuf[0]=0xF1;
          mbuf[1]=0;
          mbuf[2]=2;
          memcpy(mbuf+3, i2b(2, er->pid), 2);
          oscam_ser_send(mbuf, 5);
          sssp_fix=1;
        }
        break;
      case P_GBOX:
      case P_BOMBA:
        oscam_ser_send(er->cw, 16);
        break;
      case P_DSR95:
        mbuf[0]=4;
        memcpy(mbuf+1, er->cw, 16);
        oscam_ser_send(mbuf, 17);
        if( dsr9500type==P_DSR_GNUSMAS )
        {
          int i;
          samsung_0a=0;
          for( i=1; i<17; i++ )
            if( mbuf[i]==0x0A )
              samsung_0a++;
          samsung_dcw++;
        }
        break;
      case P_GS:
        mbuf[0]=0x03;
        mbuf[1]=0x08;
        mbuf[2]=0x10;
        mbuf[3]=0x00;
        memcpy(mbuf+4, er->cw, 16);
        oscam_ser_send(mbuf, 20);
        break;
      case P_ALPHA:
        mbuf[0]=0x88;
        mbuf[1]=0x00;
        mbuf[2]=0x10;
        memcpy(mbuf+3, er->cw, 16);
        oscam_ser_send(mbuf, 19);
        break;
    } 
  else			// not found
    switch(connected)
    {
      case P_GS:
        mbuf[0]=0x03;
        mbuf[1]=0x09;
        mbuf[2]=0x00;
        mbuf[3]=0x00;
        oscam_ser_send(mbuf, 4);
        break;
    }
  serial_errors=0; // clear error counter
}

static void oscam_ser_process_pmt(uchar *buf, int l)
{
  int i;
  uchar sbuf[32];

  switch(connected)
  {
    case P_SSSP:
      sssp_fix=0;
      memset(sssp_tab, 0, sizeof(sssp_tab));
      sssp_srvid=b2i(2, buf+3);
      for (i=9, sssp_num=0; (i<l) && (sssp_num<SSSP_MAX_PID); i+=7, sssp_num++)
      {
        memcpy(sbuf+3+(sssp_num<<1), buf+i+2, 2);
        sssp_tab[sssp_num].caid=b2i(2, buf+i  );
        sssp_tab[sssp_num].pid =b2i(2, buf+i+2);
        sssp_tab[sssp_num].prid=b2i(3, buf+i+4);
      }
      sbuf[0]=0xF1;
      sbuf[1]=0;
      sbuf[2]=(sssp_num<<1);
      oscam_ser_send(sbuf, sbuf[2]+3);
      break;
  }
}

static void oscam_ser_client_logon(uchar *buf, int l)
{
  uchar gs_logon[]={0, 1, 0, 0, 2, 1, 0, 0};
  switch(connected)
  {
    case P_GS:
      if ((l>=8) && (!memcmp(buf, gs_logon, 8)))
      {
        buf[0] = 0x02;
        buf[1] = 0x04;
        buf[2] = 0x00;
        buf[3] = 0x00;
        oscam_ser_send(buf, 4);
      }
      break;
  }
}

static int oscam_ser_check_ecm(ECM_REQUEST *er, uchar *buf, int l)
{
  int i;

  if (l<16)
  {
    cs_log(incomplete, l);
    return(1);
  }

  switch(connected)
  {
    case P_HSIC:
      er->l    = l-12;
      er->caid = b2i(2, buf+1 );
      er->prid = b2i(3, buf+3 );
      er->pid  = b2i(2, buf+6 );
      er->srvid= b2i(2, buf+10);
      memcpy(er->ecm, buf+12, er->l);
      break;
    case P_SSSP:
      er->pid=b2i(2, buf+3);
      for (i=0; (i<8) && (sssp_tab[i].pid!=er->pid); i++);
      if (i>=sssp_num)
      {
        cs_debug("illegal request, unknown pid=%04X", er->pid);
        return(2);
      }
      er->l    = l-5;
      er->srvid= sssp_srvid;
      er->caid = sssp_tab[i].caid;
      er->prid = sssp_tab[i].prid;
      memcpy(er->ecm, buf+5, er->l);
      break;
    case P_BOMBA:
      er->l=l;
      memcpy(er->ecm, buf, er->l);
      break;
    case P_DSR95:
      buf[l]='\0';	// prepare for trim
      trim((char *)buf+13);	// strip spc, nl, cr ...
      er->l=strlen((char *)buf+13)>>1;
      er->prid=cs_atoi((char *)buf+3, 3, 0);	// ignore errors
      er->caid=cs_atoi((char *)buf+9, 2, 0);	// ignore errors
      if (cs_atob(er->ecm, (char *)buf+13, er->l)<0)
      {
        cs_log("illegal characters in ecm-request");
        return(1);
      }
      if( dsr9500type==P_DSR_WITHSID )
      {
        er->l-=2;
        er->srvid=cs_atoi((char *)buf+13+(er->l<<1), 2, 0);
      }
      break;
    case P_GS:
      er->l     = ((buf[3]<<8)|buf[2]) - 6;
      er->srvid =  (buf[5]<<8)|buf[4]; // sid
      er->caid  =  (buf[7]<<8)|buf[6];
      er->prid  = 0;
      if (er->l>256) er->l=256;
      memcpy(er->ecm, buf+10, er->l);
      break;
    case P_ALPHA:
      l=oscam_ser_alpha_convert(buf, l);
      er->l     = b2i(2, buf+1 )-2;
      er->caid  = b2i(2, buf+3 );
      if ((er->l!=l-5) || (er->l>257))
      {
        cs_log(incomplete, l);
        return(1);
      }
      memcpy(er->ecm, buf+5, er->l);
      break;
    case P_GBOX:
      er->srvid = b2i(2, buf+gbox_lens.cat_len+3+3);
      er->l = gbox_lens.ecm_len+3;
      memcpy(er->ecm, buf+gbox_lens.cat_len+3+gbox_lens.pmt_len+3, er->l);
      break;
  }
  return(0);
}

static void oscam_ser_process_ecm(uchar *buf, int l)
{
  ECM_REQUEST *er;

  if (!(er=get_ecmtask()))
    return;

  switch(oscam_ser_check_ecm(er, buf, l))
  {
    case 2: er->rc=9; return;	// error without log
    case 1: er->rc=9;		      // error with log
  }
  get_cw(er);
}


static void oscam_ser_server()
{
  int n;
  uchar mbuf[1024];

  connected=0;
  oscam_ser_init_client();

  while ((n=process_input(mbuf, sizeof(mbuf), cfg->cmaxidle))>=0)
  {
    if (serial_errors > 3)
    {
      cs_log("too many errors, reiniting...");
      break;
    }
    if (n>0)
    {
      oscam_ser_auth_client(mbuf[0] & 0xF);
      switch (mbuf[0]>>4)
      {
        case IS_ECM:
          oscam_ser_process_ecm(mbuf+1, n-1);
          break;
        case IS_PMT:
          oscam_ser_process_pmt(mbuf+1, n-1);
          break;
        case IS_LGO:
          oscam_ser_client_logon(mbuf+1, n-1);
          break;
      }
    }
  }
  oscam_ser_disconnect();
}

static int init_oscam_ser_device(char *device)
{
  int fd;

  fd=open(device, O_RDWR | O_NOCTTY | O_SYNC | O_NONBLOCK);
  if (fd>0)
  {
    fcntl(fd, F_SETFL, 0);
    if (oscam_ser_set_serial_device(fd)<0) cs_log("ERROR ioctl");
    if (tcflush(fd, TCIOFLUSH)<0) cs_log("ERROR flush");
  }
  else
  {
    fd=0;
    cs_log("ERROR opening %s", device);
  }
  return(fd);
}

static void oscam_ser_fork(char *url)
{
  //static char logtxt[32];

  client[cs_idx].is_server=1;
  if ((!url) || (!url[0])) return;
  if (!oscam_ser_parse_url(url)) return;
 // snprintf(logtxt, sizeof(logtxt)-1, ", %s@%s",
 //          oscam_ser_proto>P_MAX ? "auto" : proto_txt[oscam_ser_proto], oscam_ser_device);
 // ph[idx].logtxt=logtxt;

  while(1)
  {
    client[cs_idx].au=(-1);
    client[cs_idx].usr[0]='\0';
    client[cs_idx].login=time((time_t *)0);
    client[cs_idx].pfd=init_oscam_ser_device(oscam_ser_device);
    if (client[cs_idx].pfd)
      oscam_ser_server();
    else
      cs_sleepms(60000);	// retry in 1 min. (USB-Device ?)
    if (client[cs_idx].pfd) close(client[cs_idx].pfd);
  }
}

void init_oscam_ser(int ctyp)
{
	char sdevice[512];
	cs_strncpy(sdevice, cfg->ser_device, sizeof(sdevice));

	//TODO: untested (threaded)
	char *p;
	while( (p=strrchr(sdevice, 1)) )
	{
		*p = 0;
		if ((!p + 1) || (!(p + 1)[0])) return;
		if (!oscam_ser_parse_url(p + 1)) return;
		int i=cs_fork(0, ctyp);
		client[i].typ='c';
		client[i].ip=0;
		client[i].ctyp=ctyp;
		pthread_create(&client[i].thread, NULL, (void *)oscam_ser_fork, (void *)p + 1);
		pthread_detach(client[i].thread);
	}

	if (!sdevice[0]) return;
	if (!oscam_ser_parse_url(sdevice)) return;

	int i=cs_fork(0, ctyp);
	client[i].typ='c';
	client[i].ip=0;
	client[i].ctyp=ctyp;
	pthread_create(&client[i].thread, NULL, (void *)oscam_ser_fork, (void *)sdevice);
	pthread_detach(client[i].thread);
}

/*
 *	client functions
 */

static int oscam_ser_client_init()
{
  if ((!reader[client[cs_idx].ridx].device[0])) cs_exit(1);
  if (!oscam_ser_parse_url(reader[client[cs_idx].ridx].device)) cs_exit(1);
  client[cs_idx].pfd=init_oscam_ser_device(oscam_ser_device);
  return((client[cs_idx].pfd>0) ? 0 : 1);
}

static int oscam_ser_send_ecm(ECM_REQUEST *er, uchar *buf)
{
  switch(oscam_ser_proto)
  {
    case P_HSIC:
      memset(buf, 0, 12);
      buf[0]=2;
      memcpy(buf+ 1, i2b(2, er->caid ), 2);
      memcpy(buf+ 3, i2b(3, er->prid ), 3);
      memcpy(buf+ 6, i2b(2, er->pid  ), 2);
      memcpy(buf+10, i2b(2, er->srvid), 2);
      memcpy(buf+12, er->ecm, er->l);
      oscam_ser_send(buf, 12+er->l);
      break;
    case P_BOMBA:
      oscam_ser_send(er->ecm, er->l);
      break;
    case P_DSR95:
      if( dsr9500type==P_DSR_WITHSID )
      {
        sprintf((char *)buf, "%c%08lX%04X%s%04X\n\r",
          3, er->prid, er->caid, cs_hexdump(0, er->ecm, er->l), er->srvid);
        oscam_ser_send(buf, (er->l<<1)+19); // 1 + 8 + 4 + l*2 + 4 + 2
      }
      else
      {
        sprintf((char *)buf, "%c%08lX%04X%s\n\r",
          3, er->prid, er->caid, cs_hexdump(0, er->ecm, er->l));
        oscam_ser_send(buf, (er->l<<1)+15); // 1 + 8 + 4 + l*2 + 2
      }
      break;
    case P_ALPHA:
      buf[0]=0x80;
      memcpy(buf+1, i2b(2, 2+er->l), 2);
      memcpy(buf+3, i2b(2, er->caid), 2);
      memcpy(buf+5, er->ecm, er->l);
      oscam_ser_send(buf, oscam_ser_alpha_convert(buf, 5+er->l));
      break;
  }
  return(0);
}

static void oscam_ser_process_dcw(uchar *dcw, int *rc, uchar *buf, int l)
{
  switch(oscam_ser_proto)
  {
    case P_HSIC:
      if ((l>=23) && (buf[2]==0x3A) && (buf[3]==0x3A))
      {
        int i;
        uchar crc;
        for (i=4, crc=HSIC_CRC; i<20; i++)
          crc^=buf[i];
        if (crc==buf[20])
        {
          memcpy(dcw, buf+4, 16);
          *rc=1;
        }
      }
      break;
    case P_BOMBA:
      if (l>=16)
      {
        memcpy(dcw, buf, 16);
        *rc=1;
      }
      break;
    case P_DSR95:
      if ((l>=17) && (buf[0]==4))
      {
        memcpy(dcw, buf+1, 16);
        *rc=1;
      }
      break;
    case P_ALPHA:
      if ((l>=19) && (buf[0]==0x88))
      {
        memcpy(dcw, buf+3, 16);
        *rc=1;
      }
      break;
  }
}

static int oscam_ser_recv_chk(uchar *dcw, int *rc, uchar *buf, int n)
{
  *rc=(-1);
  switch (buf[0]>>4)
  {
    case IS_DCW:
      oscam_ser_process_dcw(dcw, rc, buf+1, n-1);
      break;
  }
  return((*rc<0) ? (-1) : 0);	// idx not supported in serial module
}

/*
 *	protocol structure
 */

void module_oscam_ser(struct s_module *ph)
{
  strcpy(ph->desc, "serial");
  ph->type=MOD_CONN_SERIAL;
  ph->multi=1;
  ph->watchdog=0;
  ph->s_handler=init_oscam_ser;
  ph->recv=oscam_ser_recv;
  ph->send_dcw=oscam_ser_send_dcw;
  ph->c_multi=0;
  ph->c_init=oscam_ser_client_init;
  ph->c_recv_chk=oscam_ser_recv_chk;
  ph->c_send_ecm=oscam_ser_send_ecm;
  ph->num=R_SERIAL;
}
