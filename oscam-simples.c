#include "globals.h"

static AES_KEY	aeskey;

void aes_set_key(char *key)
{
  AES_set_decrypt_key((const unsigned char *)key, 128, &aeskey);
  AES_set_encrypt_key((const unsigned char *)key, 128, &client[cs_idx].aeskey);
}

void aes_decrypt(uchar *buf, int n)
{
  int i;
  for(i=0; i<n; i+=16)
    AES_decrypt(buf+i, buf+i, &aeskey);
}

void aes_encrypt_idx(int idx, uchar *buf, int n)
{
  int i;
  for(i=0; i<n; i+=16)
    AES_encrypt(buf+i, buf+i, &client[idx].aeskey);
}

char *remote_txt(void)
{
  if (is_server)
    return("client");
  else
    return("remote server");
}

char *trim(txt)
char *txt;
{
  register int l;
  register char *p1, *p2;

  if (*txt==' ')
  {
    for (p1=p2=txt;
        (*p1==' ') || (*p1=='\t') || (*p1=='\n') || (*p1=='\r');
         p1++);
    while (*p1)
      *p2++=*p1++;
    *p2='\0';
  }
  if ((l=strlen(txt))>0)
    for (p1=txt+l-1;
        (*p1==' ') || (*p1=='\t') || (*p1=='\n') || (*p1=='\r');
         *p1--='\0');

  return(txt);
}

char *strtolower(char *txt)
{
  char *p;
  for (p=txt; *p; p++)
    if (isupper((uchar)*p)) *p=tolower((uchar)*p);
  return(txt);
}

int gethexval(char c)
{
  if ((c>='0') && (c<='9')) return(c-'0');
  if ((c>='A') && (c<='F')) return(c-'A'+10);
  if ((c>='a') && (c<='f')) return(c-'a'+10);
  return(-1);
}

int cs_atob(uchar *buf, char *asc, int n)
{
  int i, rc;
  for (i=0; i<n; i++)
  {
    if ((rc=(gethexval(asc[i<<1])<<4)|gethexval(asc[(i<<1)+1]))&0x100)
      return(-1);
    buf[i]=rc;
  }
  return(n);
}

ulong cs_atoi(char *asc, int l, int val_on_err)
{
  int i, n=0;
  ulong rc=0;
  for (i=((l-1)<<1), errno=0; (i>=0) && (n<4); i-=2)
  {
    int b;
    b=(gethexval(asc[i])<<4) | gethexval(asc[i+1]);
    if (b<0)
    {
      errno=EINVAL;
      rc=(val_on_err) ? 0xFFFFFFFF : 0;
      break;
    }
    rc|=b<<(n<<3);
    n++;
  }
  return(rc);
}

int byte_atob(char *asc)
{
  int rc;

  if (strlen(trim(asc))!=2)
    rc=(-1);
  else
    if ((rc=(gethexval(asc[0])<<4)|gethexval(asc[1]))&0x100)
      rc=(-1);
  return(rc);
}

long word_atob(char *asc)
{
  long rc;

  if (strlen(trim(asc))!=4)
    rc=(-1);
  else
  {
    rc=gethexval(asc[0])<<12 | gethexval(asc[1])<<8 |
       gethexval(asc[2])<<4  | gethexval(asc[3]);
    if (rc&0x10000)
      rc=(-1);
  }
  return(rc);
}

int key_atob(char *asc, uchar *bin)
{
  int i, n1, n2, rc;
  for (i=rc=0; i<32; i+=2)
  {
    if ((n1=gethexval(asc[i  ]))<0) rc=(-1);
    if ((n2=gethexval(asc[i+1]))<0) rc=(-1);
    bin[i>>1]=(n1<<4)+(n2&0xff);
  }
  return(rc);
}

int key_atob14(char *asc, uchar *bin)
{
  int i, n1, n2, rc;
  for (i=rc=0; i<28; i+=2)
  {
    if ((n1=gethexval(asc[i  ]))<0) rc=(-1);
    if ((n2=gethexval(asc[i+1]))<0) rc=(-1);
    bin[i>>1]=(n1<<4)+(n2&0xff);
  }
  return(rc);
}

int key_atob_l(char *asc, uchar *bin, int l)
{
  int i, n1, n2, rc;
  for (i=rc=0; i<l; i+=2)
  {
    if ((n1=gethexval(asc[i  ]))<0) rc=(-1);
    if ((n2=gethexval(asc[i+1]))<0) rc=(-1);
    bin[i>>1]=(n1<<4)+(n2&0xff);
  }
  return(rc);
}

char *key_btoa(char *asc, uchar *bin)
{
  int i;//, n1, n2, rc;
  static char buf[33];
  if (!asc)
    asc=buf;
  for (i=0; i<16; i++)
    sprintf(asc+(i<<1), "%02X", bin[i]);
  return(asc);
}

char *cs_hexdump(int m, uchar *buf, int n)
{
  int i;
  static char dump[520];

  dump[i=0]='\0';
  m=(m)?3:2;
  if (m*n>=(int)sizeof(dump)) n=(sizeof(dump)/m)-1;
  while (i<n)
    sprintf(dump+(m*i++), "%02X%s", *buf++, (m>2)?" ":"");
  return(dump);
}

static int inet_byteorder=0;
in_addr_t cs_inet_order(in_addr_t n)
{
  if (!inet_byteorder)
    inet_byteorder=((inet_addr("1.2.3.4")+1)==inet_addr("1.2.3.5")) ? 1 : 2;
  switch (inet_byteorder)
  {
    case 1:
      break;
    case 2:
      n=((n&0xff000000) >> 24 ) |
        ((n&0x00ff0000) >>  8 ) |
        ((n&0x0000ff00) <<  8 ) |
        ((n&0x000000ff) << 24 );
      break;
  }
  return(n);
}

char *cs_inet_ntoa(in_addr_t n)
{
  struct in_addr in;
  in.s_addr=cs_inet_order(n);
  return((char *)inet_ntoa(in));
}

in_addr_t cs_inet_addr(char *txt)
{
  if (!inet_byteorder)
    inet_byteorder=((inet_addr("1.2.3.4")+1)==inet_addr("1.2.3.5")) ? 1 : 2;
  if (inet_byteorder == 1)
    return(inet_addr(txt));
  else
    return(inet_network(txt));
}

ulong b2i(int n, uchar *b)
{
  switch(n)
  {
    case 2:
      return ((b[0]<<8) | b[1]);
    case 3:
      return ((b[0]<<16) | (b[1]<<8) | b[2]);
    case 4:
      return (((b[0]<<24) | (b[1]<<16) | (b[2]<<8) | b[3]) & 0xffffffffL);
    default:
      cs_log("Error in b2i, n=%i",n);
  }
  return 0;
}

ullong b2ll(int n, uchar *b)
{
  int i;
  ullong k=0;
  for(i=0; i<n; k+=b[i++])
    k<<=8;
  return(k);
}

uchar *i2b(int n, ulong i)
{
  static uchar b[4];
  switch(n)
  {
    case 2:
      b[0]=(i>> 8) & 0xff;
      b[1]=(i    ) & 0xff;
      break;
    case 3:
      b[0]=(i>>16) & 0xff;
      b[1]=(i>> 8) & 0xff;
      b[2]=(i    ) & 0xff;
    case 4:
      b[0]=(i>>24) & 0xff;
      b[1]=(i>>16) & 0xff;
      b[2]=(i>> 8) & 0xff;
      b[3]=(i    ) & 0xff;
      break;
  }
  return(b);
}

ulong a2i(char *asc, int bytes)
{
  int i, n;
  ulong rc;
  for (rc=i=0, n=strlen(trim(asc))-1; i<(abs(bytes)<<1); n--, i++)
    if (n>=0)
    {
      int rcl;
      if ((rcl=gethexval(asc[n]))<0)
      {
        errno=EINVAL;
        return(0x1F1F1F);
      }
      rc|=(rcl<<(i<<2));
    }
    else
      if (bytes<0)
        rc|=(0xf<<(i<<2));
  errno=0;
  return(rc);
}

int boundary(int exp, int n)
{
  return((((n-1)>>exp)+1)<<exp);
}

void cs_ftime(struct timeb *tp)
{
#ifdef NO_FTIME
  struct timeval tv;
  gettimeofday(&tv, (struct timezone *)0);
  tp->time=tv.tv_sec;
  tp->millitm=tv.tv_usec/1000;
#else
  ftime(tp);
#endif
}

void cs_sleepms(unsigned int msec)
{
	//does not interfere with signals like sleep and usleep do
	struct timespec req_ts;
	req_ts.tv_sec = msec/1000;
	req_ts.tv_nsec = (msec % 1000) * 1000000L;
	nanosleep (&req_ts, NULL);
}

int bytes_available(int fd)
{
  struct pollfd pfds;
  pfds.fd=fd;
  pfds.events=POLLIN;
  pfds.revents=0;
  if (poll(&pfds, 1, 0)!=1)
    return(0);
  else
    return(((pfds.revents)&POLLIN)==POLLIN);
}


#ifdef OS_CYGWIN32
#include <windows.h>
void cs_setpriority(int prio)
{
  HANDLE WinId;
  ulong wprio;
  switch((prio+20)/10)
  {
    case  0: wprio=REALTIME_PRIORITY_CLASS;	break;
    case  1: wprio=HIGH_PRIORITY_CLASS;		break;
    case  2: wprio=NORMAL_PRIORITY_CLASS;	break;
    default: wprio=IDLE_PRIORITY_CLASS;		break;
  }
  WinId=GetCurrentProcess();
  SetPriorityClass(WinId, wprio);
}
#else
void cs_setpriority(int prio)
{
#ifdef PRIO_PROCESS
  setpriority(PRIO_PROCESS, 0, prio);  // ignore errors
#endif
}
#endif

/* Clears the s_ip structure provided. The pointer will be set to NULL so everything is cleared.*/
void clear_sip(struct s_ip **sip){
        struct s_ip *cip = *sip, *lip;
        for (*sip = NULL; cip != NULL; cip = lip){
                lip = cip->next;
                free(cip);
        }
}

/* Clears the s_ptab struct provided by setting nfilts and nprids to zero. */
void clear_ptab(struct s_ptab *ptab){
        int i;
        for (i = 0; i < ptab->nports; i++) {
                ptab->ports[i].ftab.nfilts = 0;
                ptab->ports[i].ftab.filts[0].nprids = 0;
        }
        ptab->nports = 0;
}

/* Clears the s_ftab struct provided by setting nfilts and nprids to zero. */
void clear_ftab(struct s_ftab *ftab){
        int i, j;
        for (i = 0; i < CS_MAXFILTERS; i++) {
                ftab->filts[i].caid = 0;
                for (j = 0; j < CS_MAXPROV; j++)
                        ftab->filts[i].prids[j] = 0;
                ftab->filts[i].nprids = 0;
        }
        ftab->nfilts = 0;
}

/* Clears given caidtab */
void clear_caidtab(struct s_caidtab *ctab){
        int i;
        for (i = 0; i < CS_MAXCAIDTAB; i++) {
                ctab->caid[i] = 0;
                ctab->mask[i] = 0;
                ctab->cmap[i] = 0;
        }
}

/* Clears given tuntab */
void clear_tuntab(struct s_tuntab *ttab){
        int i;
        for (i = 0; i < CS_MAXTUNTAB; i++) {
                ttab->bt_caidfrom[i] = 0;
                ttab->bt_caidto[i] = 0;
                ttab->bt_srvid[i] = 0;
        }
}

/* 
* Ordinary strncpy does not terminate the string if the source 
* is exactly as long or longer as the specified size. This can raise security issues.
* This function is a replacement which makes sure that a \0 is always added. 
* num should be the real size of char array (do not subtract -1). 
*/
void cs_strncpy(char * destination, const char * source, size_t num){
        uint32 l, size = strlen(source);
        if(size > num - 1) l = num - 1;
        else l = size;
        memcpy(destination, source, l);
        destination[l] = '\0';
}
