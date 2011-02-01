//FIXME Not checked on threadsafety yet; after checking please remove this line
#include <sys/time.h>
#include "globals.h"
#include "module-cccam.h"

void aes_set_key(char *key)
{
  AES_set_decrypt_key((const unsigned char *)key, 128, &cur_client()->aeskey_decrypt);
  AES_set_encrypt_key((const unsigned char *)key, 128, &cur_client()->aeskey);
}

void aes_decrypt(uchar *buf, int n)
{
  int i;
  for(i=0; i<n; i+=16)
    AES_decrypt(buf+i, buf+i, &cur_client()->aeskey_decrypt);
}

void aes_encrypt_idx(struct s_client *cl, uchar *buf, int n)
{
  int i;
  for(i=0; i<n; i+=16)
    AES_encrypt(buf+i, buf+i, &cl->aeskey);
}

void add_aes_entry(struct s_reader *rdr, ushort caid, uint32 ident, int keyid, uchar *aesKey)
{
    AES_ENTRY *new_entry;
    AES_ENTRY *next,*current;

    // create de AES key entry for the linked list
    if(!cs_malloc(&new_entry, sizeof(AES_ENTRY), -1)) return;

    memcpy(new_entry->plainkey, aesKey, 16);
    new_entry->caid=caid;
    new_entry->ident=ident;
    new_entry->keyid=keyid;
    if(memcmp(aesKey,"\xFF\xFF",2)) {
        AES_set_decrypt_key((const unsigned char *)aesKey, 128, &(new_entry->key));
        // cs_log("adding key : %s",cs_hexdump(1,aesKey,16));
    }
    else {
        memset(&new_entry->key,0,sizeof(AES_KEY));
        // cs_log("adding fake key");
    }
    new_entry->next=NULL;

    //if list is empty, new_entry is the new head
    if(!rdr->aes_list) {
        rdr->aes_list=new_entry;
        return;
    }

    //happend it to the list
    current=rdr->aes_list;
    next=current->next;
    while(next) {
        current=next;
        next=current->next;
        }

    current->next=new_entry;

}

void parse_aes_entry(struct s_reader *rdr,char *value) {
    ushort caid;
    ushort dummy;
    uint32 ident;
    int len;
    char *tmp;
    int nb_keys,key_id;
    uchar aes_key[16];
    char *save=NULL;

    tmp=strtok_r(value,"@",&save);
    caid=a2i(tmp,2);
    tmp=strtok_r(NULL,":",&save);
    ident=a2i(tmp,3);
    
    // now we need to split the key ane add the entry to the reader.
    nb_keys=0;
    key_id=0;
    while((tmp=strtok_r(NULL,",",&save))) {
        dummy=0;
        len=strlen(tmp);
        if(len!=32) {
            dummy=a2i(tmp,1);
            // FF means the card will do the AES decrypt
            // 00 means we don't have the aes.
            if((dummy!=0xFF && dummy!=0x00) || len>2) {
                key_id++;
                cs_log("AES key length error .. not adding");
                continue;
            }
            if(dummy==0x00) {
                key_id++;
                continue;
            }
        }
        nb_keys++;
        if(dummy)
            memset(aes_key,0xFF,16);
        else
            key_atob_l(tmp,aes_key,32);
        // now add the key to the reader... TBD
        add_aes_entry(rdr,caid,ident,key_id,aes_key);
        key_id++;
    }
    
    cs_log("%d AES key(s) added on reader %s for %04x:%06x", nb_keys, rdr->label, caid, ident);
}

void parse_aes_keys(struct s_reader *rdr,char *value)
{
    // value format is caid1@ident1:key0,key1;caid2@indent2:key0,key1
    char *entry;
    char *save=NULL;
    
    rdr->aes_list=NULL;
    for (entry=strtok_r(value, ";",&save); entry; entry=strtok_r(NULL, ";",&save)) {
        parse_aes_entry(rdr,entry);
    }
    
    /*
    AES_ENTRY *current;
    current=rdr->aes_list;
    while(current) {
        cs_log("**************************");
        cs_log("current = %p",current);
        cs_log("CAID = %04x",current->caid);
        cs_log("IDENT = %06x",current->ident);
        cs_log("keyID = %d",current->keyid);
        cs_log("next = %p",current->next);
        cs_log("**************************");
        current=current->next;
    }
    */
}

int aes_decrypt_from_list(AES_ENTRY *list, ushort caid, uint32 provid,int keyid, uchar *buf, int n)
{
    AES_ENTRY *current;
    AES_KEY   dummy;
    int i;
    int ok=1;
    int error=0;

    current=list;
    while(current) {
        if(current->caid==caid && current->ident==provid && current->keyid==keyid)
            break;
        current=current->next;
    }

    if(!current) {
        cs_log("AES Decrypt : key id %d not found for CAID %04X , provider %06x",keyid,caid,provid);
        return error; // we don't have the key to decode this buffer.
        }
    else {
        // hack for card that do the AES decrypt themsleves
        memset(&dummy,0,sizeof(AES_KEY));
        if(!memcmp(&current->key,&dummy,sizeof(AES_KEY))) {
            return ok;
        }
        // decode the key
        for(i=0; i<n; i+=16)
            AES_decrypt(buf+i, buf+i, &(current->key));
    }
    return ok; // all ok, key decoded.
}

int aes_present(AES_ENTRY *list, ushort caid, uint32 provid,int keyid)
{
    AES_ENTRY *current;
    int ok=1;
    int error=0;

    current=list;
    while(current) {
        if(current->caid==caid && current->ident==provid && current->keyid==keyid)
            break;
        current=current->next;
    }

    if(!current) {
        cs_log("AES Decrypt : key id %d not found for CAID %04X , provider %06x",keyid,caid,provid);
        return error; // we don't have the key to decode this buffer.
        }
    
    return ok;
}

void aes_clear_entries(struct s_reader *rdr)
{

    AES_ENTRY *current;
    AES_ENTRY *next;

    current=NULL;
    next=rdr->aes_list;
    while(next) {
        current=next;
        next=current->next;
        free(current);
    }
    rdr->aes_list=NULL;
}

char *remote_txt(void)
{
  if (cur_client()->typ == 'c')
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

/*
 * dynamic word_atob
 * converts an 1-4 digit asc hexstring
 */
long dyn_word_atob(char *asc)
{
	long rc = (-1);
	int i, len = strlen(trim(asc));

	if (len <= 4 && len > 0) {
		for(i = 0, rc = 0; i < len; i++)
			rc = rc << 4 | gethexval(asc[i]);

		if (rc & 0x10000)
			rc = (-1);
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

char *cs_hexdump(int m, const uchar *buf, int n)
{
  //TODO: not threadsafe
  int i;
  char *dump = (char *)cur_client()->dump;

  dump[i=0]='\0';
  m=(m)?3:2;
  if (m*n>=(int)sizeof(cur_client()->dump)) n=(sizeof(cur_client()->dump)/m)-1;
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
  in.s_addr=n;
  return((char *)inet_ntoa(in));
}

in_addr_t cs_inet_addr(char *txt)
{
    return(inet_addr(txt));
}


int check_ip(struct s_ip *ip, in_addr_t n)
{
	struct s_ip *p_ip;
	int ok = 0;
	for (p_ip=ip; (p_ip) && (!ok); p_ip=p_ip->next)
		ok=((cs_inet_order(n)>=cs_inet_order(p_ip->ip[0])) && (cs_inet_order(n)<=cs_inet_order(p_ip->ip[1])));

	return ok;
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
  uchar *b = cur_client()->dump;
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

void cs_sleepus(unsigned int usec)
{
	//does not interfere with signals like sleep and usleep do
	struct timespec req_ts;
	req_ts.tv_sec = usec/1000000;
	req_ts.tv_nsec = (usec % 1000000) * 1000L;
	nanosleep (&req_ts, NULL);
}

int bytes_available(int fd)
{
   fd_set rfds;
   fd_set erfds;
   int select_ret;
   int in_fd;

   in_fd=fd;
   
   FD_ZERO(&rfds);
   FD_SET(in_fd, &rfds);
   
   FD_ZERO(&erfds);
   FD_SET(in_fd, &erfds);
   
   select_ret = select(in_fd+1, &rfds, NULL, &erfds, NULL);
   if (select_ret==-1)
   {
     cs_log("ERROR reading from fd %d select_ret=%i, errno=%d",in_fd, select_ret, errno);
     return 0;
   }
      
   if (FD_ISSET(in_fd, &erfds))
   {
    cs_log("ERROR reading from fd %d select_ret=%i, errno=%d",in_fd, select_ret, errno);
    return 0;
   }
   if (FD_ISSET(in_fd,&rfds))
     return 1;
   else
     return 0;
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

/* Checks an array if it is filled (a value > 0) and returns the last position (1...length) where something was found.
   length specifies the maximum length to check for. */
int check_filled(uchar *value, int length){
	if(value == NULL) return 0;
	int i, j = 0;
	for (i = 0; i < length; ++i){
		if(value[i] > 0) j = i + 1;
	}
	return j;
}

/* This function encapsulates malloc. It automatically adds an error message to the log if it failed and calls cs_exit(quiterror) if quiterror > -1. 
   result will be automatically filled with the new memory position or NULL on failure. */
void *cs_malloc(void *result, size_t size, int quiterror){
	void **tmp = (void *)result;
	*tmp = malloc (size);
	if(*tmp == NULL){
		cs_log("Couldn't allocate memory (errno=%d)!", errno);
		if(quiterror > -1) cs_exit(quiterror);
	} else {
		memset(*tmp, 0, size);
	}
	return *tmp;
}

/* This function encapsulates realloc. It automatically adds an error message to the log if it failed and calls cs_exit(quiterror) if quiterror > -1.
	result will be automatically filled with the new memory position or NULL on failure. If a failure occured, the existing memory in result will be freed. */
void *cs_realloc(void *result, size_t size, int quiterror){
	void **tmp = (void *)result, **tmp2 = (void *)result;
	*tmp = realloc (*tmp, size);
	if(*tmp == NULL){
		cs_log("Couldn't allocate memory (errno=%d)!", errno);
		free(*tmp2);
		if(quiterror > -1) cs_exit(quiterror);
	}
	return *tmp;
}

#ifdef WEBIF
/* Converts a char to it's hex representation. See urlencode and char_to_hex on how to use it.*/
char to_hex(char code){
	static const char hex[] = "0123456789abcdef";
	return hex[(int)code & 15];
}

/* Converts a char array to a char array with hex values (needed for example for md5).
	Note that result needs to be at least (p_array_len * 2) + 1 large. */
void char_to_hex(const unsigned char* p_array, unsigned int p_array_len, unsigned char *result) {
	result[p_array_len*2] = '\0';
	const unsigned char* p_end = p_array + p_array_len;
	size_t pos=0;
	const unsigned char* p;
	for( p = p_array; p != p_end; p++, pos+=2 ) {
		result[pos] = to_hex(*p >> 4);
		result[pos+1] = to_hex(*p & 15);
	}
}

/* Creates a random string with specified length. Note that dst must be one larger than size to hold the trailing \0*/
void create_rand_str(char *dst, int size){
	int i;
	for (i = 0; i < size; ++i){
		dst[i] = (rand() % 94) + 32;
	}
	dst[i] = '\0';
}
#endif

/* Converts a uint64 value (you may also cast smaller types) to a char array in bitwise representation.
   Note that the result array MUST be at least size+1 bit large and that this function assumes values
   to be only positive! The result of e.g. uint64 7 is
   11100000000000000000000000000000000000000000000000000000000000000 this means the array is reversed */
void uint64ToBitchar(uint64 value, int size, char *result){
	int pos;
	for (pos=0;pos<size;pos++) result[pos]='0';
	result[pos] = '\0';

	pos=0;
	while (value > 0 && pos < size){
		if(value % 2 == 1) result[pos]='1';
		else result[pos]='0';
		value=value / (uint64)2;
		pos++;
	}
}

/* Return 1 if the file exists, else 0 */
int file_exists(const char * filename){
	FILE *file;
	if ((file = fopen(filename, "r"))){
		fclose(file);
		return 1;
	}
	return 0;
}

/* Clears the s_ip structure provided. The pointer will be set to NULL so everything is cleared.*/
void clear_sip(struct s_ip **sip){
	struct s_ip *cip = *sip, *lip;
	for (*sip = NULL; cip != NULL; cip = lip){
		lip = cip->next;
		free(cip);
	}
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

/* Clears the s_ptab struct provided by setting nfilts and nprids to zero. */
void clear_ptab(struct s_ptab *ptab){
	int i;
	for (i = 0; i < ptab->nports; i++) {
		ptab->ports[i].ftab.nfilts = 0;
		ptab->ports[i].ftab.filts[0].nprids = 0;
	}
	ptab->nports = 0;
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
/* Overwrites destfile with tmpfile. If forceBakOverWrite = 0, the bakfile will not be overwritten if it exists, else it will be.*/
int safe_overwrite_with_bak(char *destfile, char *tmpfile, char *bakfile, int forceBakOverWrite){
	if (file_exists(destfile)) {
		if(forceBakOverWrite != 0 && file_exists(bakfile)){
			if(remove(bakfile) < 0) cs_log("Error removing backup conf file %s (errno=%d)! Will try to proceed nonetheless...", bakfile, errno);
		}
		if(file_exists(bakfile)){
			if(remove(destfile) < 0) {
				cs_log("Error removing original conf file %s (errno=%d). Will maintain original one!", destfile, errno);
				if(remove(tmpfile) < 0) cs_log("Error removing temp conf file %s (errno=%d)!", tmpfile, errno);
				return(1);
			}
		} else {
			if(rename(destfile, bakfile) < 0){
				cs_log("Error renaming original conf file %s to %s (errno=%d). Will maintain original one!", destfile, bakfile, errno);
				if(remove(tmpfile) < 0) cs_log("Error removing temp conf file %s (errno=%d)!", tmpfile, errno);
				return(1);
			}
		}
		if(rename(tmpfile, destfile) < 0){
			cs_log("Error renaming new conf file %s to %s (errno=%d). The config will be missing upon next startup as this is non-recoverable!", tmpfile, destfile, errno);
			return(1);
		}
	} else {
		if(rename(tmpfile, destfile) < 0){
			cs_log("Error renaming new conf file %s to %s (errno=%d). The config will be missing upon next startup as this is non-recoverable!", tmpfile, destfile, errno);
			return(1);
		}
	}
	return(0);
}

/* Replacement of fprintf which adds necessary whitespace to fill up the varname to a fixed width.
   If varname is longer than varnameWidth, no whitespace is added*/
void fprintf_conf(FILE *f, int varnameWidth, const char *varname, const char *fmtstring, ...){
	int varlen = strlen(varname);
	int max = (varlen > varnameWidth) ? varlen : varnameWidth;
	char varnamebuf[max + 3];
	char *ptr = varnamebuf + varlen;
	va_list argptr;

	strcpy(varnamebuf, varname);
	while(varlen < varnameWidth){
		ptr[0] = ' ';
		++ptr;
		++varlen;
	}
	strcpy(ptr, "= ");
	if (fwrite(varnamebuf, sizeof(char), strlen(varnamebuf), f)){
		if(strlen(fmtstring) > 0){
			va_start(argptr, fmtstring);
			vfprintf(f, fmtstring, argptr);
			va_end(argptr);
		}
	}
}

/* Ordinary strncpy does not terminate the string if the source is exactly as long or longer as the specified size. This can raise security issues.
   This function is a replacement which makes sure that a \0 is always added. num should be the real size of char array (do not subtract -1). */
void cs_strncpy(char * destination, const char * source, size_t num){
	uint32 l, size = strlen(source);
	if(size > num - 1) l = num - 1;
	else l = size;
	memcpy(destination, source, l);
	destination[l] = '\0';
}

char *get_servicename(int srvid, int caid){
	int i;
	struct s_srvid *this = cfg.srvid;
	static char name[83];

	for (name[0] = 0; this && (!name[0]); this = this->next)
		if (this->srvid == srvid)
			for (i=0; i<this->ncaid; i++)
				if (this->caid[i] == caid)
					cs_strncpy(name, this->name, 32);

	if (!name[0]) sprintf(name, "%04X:%04X unknown", caid, srvid);
	if (!srvid) name[0] = '\0';
	return(name);
}

char *get_tiername(int tierid, int caid){
	int i;
	struct s_tierid *this = cfg.tierid;
	static char name[83];

	for (name[0] = 0; this && (!name[0]); this = this->next)
		if (this->tierid == tierid)
			for (i=0; i<this->ncaid; i++)
				if (this->caid[i] == caid)
					cs_strncpy(name, this->name, 32);

	//if (!name[0]) sprintf(name, "%04X:%04X unknown", caid, tierid);
	if (!tierid) name[0] = '\0';
	return(name);
}

char *get_provider(int caid, ulong provid){
	struct s_provid *this = cfg.provid;
	static char name[83];

	for (name[0] = 0; this && (!name[0]); this = this->next) {
		if (this->caid == caid && this->provid == provid) {
			snprintf(name, 83, "%s", this->prov);
			if (this->sat[0]) {
				strcat(name, " / ");
				strcat(name, this->sat);
			}
			if (this->lang[0]) {
				strcat(name, " / ");
				strcat(name, this->lang);
			}
		}
	}

	if (!name[0]) snprintf(name, 83, "%04X:%06lX unknown", caid, provid);
	if (!caid) name[0] = '\0';
	return(name);
}

void make_non_blocking(int fd) {
    int fl;
    fl=fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK | O_NDELAY);
}

unsigned int seed;

uchar fast_rnd() {
	unsigned int offset = 12923;
	unsigned int multiplier = 4079;

	seed = seed * multiplier + offset;
	return (uchar) (seed % 0xFF);
}

void init_rnd() {
	 seed = (unsigned int) time((time_t*)0);
}

int hexserialset(struct s_reader *rdr)
{
	int i;

	if (!rdr) return 0;

	for (i = 0; i < 8; i++)
		if (rdr->hexserial[i])
			return 1;
	return 0;
}

static char *netw_ext_prot[] = { "cccam", "cccam ext", "newcamd524" };

char *reader_get_type_desc(struct s_reader * rdr, int extended)
{
	static char *typtxt[] = { "unknown", "mouse", "mouse", "sc8in1", "mp35", "mouse", "internal", "smartreader", "pcsc" };
	char *desc = typtxt[0];

	if (rdr->crdr.active==1)
		return rdr->crdr.desc;

	if (rdr->typ & R_IS_NETWORK) {
		if (rdr->ph.desc)
			desc = rdr->ph.desc;
	} else {
		desc = typtxt[rdr->typ];
	}

	if ((rdr->typ == R_NEWCAMD) && (rdr->ncd_proto == NCD_524))
		desc = netw_ext_prot[2];

	else if (rdr->typ == R_CCCAM) {
		if (rdr->client) {
			if (rdr->client && rdr->client->cc && ((struct cc_data *)rdr->client->cc)->extended_mode)
				desc = netw_ext_prot[extended];
			else
				desc = netw_ext_prot[0];
		} else {
			desc = netw_ext_prot[0];
		}
	}

	return (desc);
}

char *monitor_get_proto(struct s_client *cl)
{
	char *ctyp;
	switch(cl->typ) {
		case 's'	: ctyp = "server"; break;
		case 'p'	:
		case 'r'	: ctyp = reader_get_type_desc(cl->reader, 1); break;
		case 'c'	:
			if (cl->cc && ((struct cc_data *)cl->cc)->extended_mode) {
				ctyp = netw_ext_prot[1];
				break;
			}
		default		: ctyp = ph[cl->ctyp].desc;
	}
	return(ctyp);
}

/*
 * resolve clienttype for newcamdprotocol
 */
char *get_ncd_client_name(char *client_id)
{
        static const int max_id_idx = 31;
        static const char const *ncd_service_ids[] = { "0000", "5644", "4C43", "4333", "7264", "6762", "6D67", "7763", "6E73", "6378", "6B61",
                                           "6576", "4343", "5456", "414C", "0666", "0667", "9911", "434C", "4765", "5342",
                                           "6E65", "4E58", "4453", "8888", "7363", "0669", "0665", "0769", "4543", "6D63",
                                           "6B63" };

        static char *ncd_service_names[] = { "generic", "vdr-sc", "LCE", "camd3", "radegast", "gbox2CS", "mgcamd", //actually a const so threadsafe
                                             "WinCSC", "NewCS", "cx", "Kaffeine", "evocamd", "CCcam", "Tecview",
                                             "AlexCS", "rqcamd", "rq-echo-client", "ACamd", "Cardlink", "Octagon", "SBCL",
                                             "NextYE2k", "NextYE2k", "DiabloCam/UW", "OSCam", "Scam", "rq-sssp-client/CW",
                                             "rq-sssp-client/CS", "JlsRq", "eyetvCamd", "mpcs", "kpcs", "unknown - please report" };

        int idx = 0;
        for (idx = 0; idx <= max_id_idx; idx++) {
		if(!memcmp(ncd_service_ids[idx], client_id, 4))
                        return ncd_service_names[idx];

        }

        return ncd_service_names[max_id_idx+1];
}

char *strnew(char *str)
{
  if (!str)
    return NULL;
    
  char *newstr = cs_malloc(&newstr, strlen(str)+1, 1);
  strcpy(newstr, str);
  
  return newstr;
}

void hexserial_to_newcamd(uchar *source, uchar *dest, ushort caid)
{
  caid = caid >> 8;
  if ((caid == 0x17) || (caid == 0x06))    // Betacrypt or Irdeto
  {
    // only 4 Bytes Hexserial for newcamd clients (Hex Base + Hex Serial)
    // first 2 Byte always 00
    dest[0]=0x00; //serial only 4 bytes
    dest[1]=0x00; //serial only 4 bytes
    // 1 Byte Hex Base (see reader-irdeto.c how this is stored in "source")
    dest[2]=source[3];
    // 3 Bytes Hex Serial (see reader-irdeto.c how this is stored in "source")
    dest[3]=source[0];
    dest[4]=source[1];
    dest[5]=source[2];
  }
  else if ((caid == 0x05) || (caid == 0x0D))
  {
    dest[0] = 0x00;
    memcpy(dest+1, source, 5);
  }
  else
    memcpy(dest, source, 6);
}

void newcamd_to_hexserial(uchar *source, uchar *dest, ushort caid)
{
  caid = caid >> 8;
  if ((caid == 0x17) || (caid == 0x06)) {
    memcpy(dest, source+3, 3);
    dest[3] = source[2];
		dest[4] = 0;
		dest[5] = 0;
  }
  else if ((caid == 0x05) || (caid == 0x0D)) {
    memcpy(dest, source+1, 5);
		dest[5] = 0;
	}
  else
    memcpy(dest, source, 6);
}
