//FIXME Not checked on threadsafety yet; after checking please remove this line
#include "globals.h"
#include "module-cccam.h"

/* Gets the client associated to the calling thread. */
struct s_client *cur_client(void){
	return (struct s_client *) pthread_getspecific(getclient);
}

/* Gets the unique thread number from the client. Used in monitor and newcamd. */
int32_t get_threadnum(struct s_client *client) {
	struct s_client *cl;
	int32_t count=0;

	for (cl=first_client->next; cl ; cl=cl->next) {
		if (cl->typ==client->typ)
			count++;
		if(cl==client)
			return count;
	}
	return 0;
}

/* Gets the tmp dir */
char *get_tmp_dir(){
  if (cs_tmpdir[0])
    return cs_tmpdir;

#ifdef OS_CYGWIN32
  char *d = getenv("TMPDIR");
  if (!d || !d[0])
    d = getenv("TMP");
  if (!d || !d[0])
    d = getenv("TEMP");
  if (!d || !d[0])
    getcwd(cs_tmpdir, sizeof(cs_tmpdir)-1);

  cs_strncpy(cs_tmpdir, d, sizeof(cs_tmpdir));
  char *p = cs_tmpdir;
  while(*p) p++;
  p--;
  if (*p != '/' && *p != '\\')
    strcat(cs_tmpdir, "/");
  strcat(cs_tmpdir, "_oscam");
#else
  cs_strncpy(cs_tmpdir, "/tmp/.oscam", sizeof(cs_tmpdir));
#endif
  mkdir(cs_tmpdir, S_IRWXU);
  return cs_tmpdir;
}

/* Checks if the client still exists or has been cleaned. Returns 1 if it is ok, else 0. */
int8_t check_client(struct s_client *client){
	struct s_client *cl2;
	for (cl2=first_client->next; cl2 != NULL; cl2=cl2->next)
		if (client == cl2)
			break;
	if(cl2 != client || client->cleaned) return 0;
	else return 1;
}

void aes_set_key(char *key)
{
  AES_set_decrypt_key((const unsigned char *)key, 128, &cur_client()->aeskey_decrypt);
  AES_set_encrypt_key((const unsigned char *)key, 128, &cur_client()->aeskey);
}

void aes_decrypt(uchar *buf, int32_t n)
{
  int32_t i;
  for(i=0; i<n; i+=16)
    AES_decrypt(buf+i, buf+i, &cur_client()->aeskey_decrypt);
}

void aes_encrypt_idx(struct s_client *cl, uchar *buf, int32_t n)
{
  int32_t i;
  for(i=0; i<n; i+=16)
    AES_encrypt(buf+i, buf+i, &cl->aeskey);
}

/* Creates an AES_ENTRY and adds it to the given linked list. */
void add_aes_entry(AES_ENTRY **list, uint16_t caid, uint32_t ident, int32_t keyid, uchar *aesKey)
{
    AES_ENTRY *new_entry, *next,*current;

    // create the AES key entry for the linked list
    if(!cs_malloc(&new_entry, sizeof(AES_ENTRY), -1)) return;

    memcpy(new_entry->plainkey, aesKey, 16);
    new_entry->caid=caid;
    new_entry->ident=ident;
    new_entry->keyid=keyid;
    if(memcmp(aesKey,"\xFF\xFF",2)) {
        AES_set_decrypt_key((const unsigned char *)aesKey, 128, &(new_entry->key));
        // cs_log("adding key : %s",cs_hexdump(1,aesKey,16, tmp, sizeof(tmp)));
    }
    else {
        memset(&new_entry->key,0,sizeof(AES_KEY));
        // cs_log("adding fake key");
    }
    new_entry->next=NULL;

    //if list is empty, new_entry is the new head
    if(!*list) {
        *list=new_entry;
        return;
    }

    //append it to the list
    current=*list;
    next=current->next;
    while(next) {
        current=next;
        next=current->next;
    }

    current->next=new_entry;

}

/* Parses a single AES_KEYS entry and assigns it to the given list.
   The expected format for value is caid1@ident1:key0,key1 */
void parse_aes_entry(AES_ENTRY **list, char *label, char *value) {
    uint16_t caid, dummy;
    uint32_t ident;
    int32_t len;
    char *tmp;
    int32_t nb_keys,key_id;
    uchar aes_key[16];
    char *save=NULL;

    tmp=strtok_r(value,"@",&save);
    caid=a2i(tmp,2);
    tmp=strtok_r(NULL,":",&save);
    ident=a2i(tmp,3);
    
    // now we need to split the key and add the entry to the reader.
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
        add_aes_entry(list,caid,ident,key_id,aes_key);
        key_id++;
    }
    
    cs_log("%d AES key(s) added on reader %s for %04x:%06x", nb_keys, label, caid, ident);
}

/* Clears all entries from an AES list*/
void aes_clear_entries(AES_ENTRY **list){
    AES_ENTRY *current, *next;

    current=NULL;
    next=*list;
    while(next) {
        current=next;
        next=current->next;
        add_garbage(current);
    }
    *list=NULL;
}

/* Parses multiple AES_KEYS entrys in a reader section and assigns them to the reader.
   The expected format for value is caid1@ident1:key0,key1;caid2@ident2:key0,key1 */
void parse_aes_keys(struct s_reader *rdr, char *value){
   char *entry;
    char *save=NULL;
    AES_ENTRY *newlist = NULL, *savelist = rdr->aes_list;

    for (entry=strtok_r(value, ";",&save); entry; entry=strtok_r(NULL, ";",&save)) {
        parse_aes_entry(&newlist, rdr->label, entry);
    }
    rdr->aes_list = newlist;
    aes_clear_entries(&savelist);    
    
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

int32_t aes_decrypt_from_list(AES_ENTRY *list, uint16_t caid, uint32_t provid,int32_t keyid, uchar *buf, int32_t n)
{
    AES_ENTRY *current;
    AES_KEY   dummy;
    int32_t i;
    int32_t ok=1;
    int32_t error=0;

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

int32_t aes_present(AES_ENTRY *list, uint16_t caid, uint32_t provid,int32_t keyid)
{
    AES_ENTRY *current;
    int32_t ok=1;
    int32_t error=0;

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

char *remote_txt(void)
{
  if (cur_client()->typ == 'c')
    return("client");
  else
    return("remote server");
}

char *trim(char *txt)
{
	int32_t l;
	char *p1, *p2;

	if (*txt==' ') {
		for (p1=p2=txt; (*p1==' ') || (*p1=='\t') || (*p1=='\n') || (*p1=='\r'); p1++);
		while (*p1)
			*p2++=*p1++;
		*p2='\0';
	}
	if ((l=strlen(txt))>0)
		for (p1=txt+l-1; l>0 && ((*p1==' ') || (*p1=='\t') || (*p1=='\n') || (*p1=='\r')); *p1--='\0', l--);

	return(txt);
}



int32_t gethexval(char c)
{
  if ((c>='0') && (c<='9')) return(c-'0');
  if ((c>='A') && (c<='F')) return(c-'A'+10);
  if ((c>='a') && (c<='f')) return(c-'a'+10);
  return(-1);
}

int32_t comp_timeb(struct timeb *tpa, struct timeb *tpb)
{
  if (tpa->time>tpb->time) return(1);
  if (tpa->time<tpb->time) return(-1);
  if (tpa->millitm>tpb->millitm) return(1);
  if (tpa->millitm<tpb->millitm) return(-1);
  return(0);
}

int32_t cs_atob(uchar *buf, char *asc, int32_t n)
{
  int32_t i, rc;
  for (i=0; i<n; i++)
  {
    if ((rc=(gethexval(asc[i<<1])<<4)|gethexval(asc[(i<<1)+1]))&0x100)
      return(-1);
    buf[i]=rc;
  }
  return(n);
}

uint32_t cs_atoi(char *asc, int32_t l, int32_t val_on_err)
{
  int32_t i, n=0;
  uint32_t rc=0;
  for (i=((l-1)<<1), errno=0; (i>=0) && (n<4); i-=2)
  {
    int32_t b;
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

int32_t byte_atob(char *asc)
{
  int32_t rc;

  if (strlen(trim(asc))!=2)
    rc=(-1);
  else
    if ((rc=(gethexval(asc[0])<<4)|gethexval(asc[1]))&0x100)
      rc=(-1);
  return(rc);
}

int32_t word_atob(char *asc)
{
  int32_t rc;

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
int32_t dyn_word_atob(char *asc)
{
	int32_t rc = (-1);
	int32_t i, len = strlen(trim(asc));

	if (len <= 4 && len > 0) {
		for(i = 0, rc = 0; i < len; i++)
			rc = rc << 4 | gethexval(asc[i]);

		if (rc & 0x10000)
			rc = (-1);
	}
	return(rc);
}

int32_t key_atob_l(char *asc, uchar *bin, int32_t l)
{
  int32_t i, n1, n2, rc;
  for (i=rc=0; i<l; i+=2)
  {
    if ((n1=gethexval(asc[i  ]))<0) rc=(-1);
    if ((n2=gethexval(asc[i+1]))<0) rc=(-1);
    bin[i>>1]=(n1<<4)+(n2&0xff);
  }
  return(rc);
}

char *cs_hexdump(int32_t m, const uchar *buf, int32_t n, char *target, int32_t len)
{
  int32_t i = 0;

  target[0]='\0';
  m=(m)?3:2;
  if (m*n>=len) n=(len/m)-1;
  while (i<n){
    snprintf(target+(m*i), len-(m*i), "%02X%s", *buf++, (m>2)?" ":"");
    ++i;
  }
  return(target);
}

static int32_t inet_byteorder=0;
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


int32_t check_ip(struct s_ip *ip, in_addr_t n)
{
	struct s_ip *p_ip;
	int32_t ok = 0;
	for (p_ip=ip; (p_ip) && (!ok); p_ip=p_ip->next)
		ok=((cs_inet_order(n)>=cs_inet_order(p_ip->ip[0])) && (cs_inet_order(n)<=cs_inet_order(p_ip->ip[1])));

	return ok;
}

uint32_t b2i(int32_t n, uchar *b)
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

uint64_t b2ll(int32_t n, uchar *b)
{
  int32_t i;
  uint64_t k=0;
  for(i=0; i<n; k+=b[i++])
    k<<=8;
  return(k);
}

uchar *i2b_buf(int32_t n, uint32_t i, uchar *b)
{
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

uint32_t a2i(char *asc, int32_t bytes)
{
  int32_t i, n;
  uint32_t rc;
  for (rc=i=0, n=strlen(trim(asc))-1; i<(abs(bytes)<<1); n--, i++)
    if (n>=0)
    {
      int32_t rcl;
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

int32_t boundary(int32_t exp, int32_t n)
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

void cs_sleepms(uint32_t msec)
{
	//does not interfere with signals like sleep and usleep do
	struct timespec req_ts;
	req_ts.tv_sec = msec/1000;
	req_ts.tv_nsec = (msec % 1000) * 1000000L;
	int32_t olderrno = errno;		// Some OS (especially MacOSX) seem to set errno to ETIMEDOUT when sleeping
	nanosleep (&req_ts, NULL);
	errno = olderrno;
}

void cs_sleepus(uint32_t usec)
{
	//does not interfere with signals like sleep and usleep do
	struct timespec req_ts;
	req_ts.tv_sec = usec/1000000;
	req_ts.tv_nsec = (usec % 1000000) * 1000L;
	int32_t olderrno = errno;		// Some OS (especially MacOSX) seem to set errno to ETIMEDOUT when sleeping
	nanosleep (&req_ts, NULL);
	errno = olderrno;
}

#ifdef OS_CYGWIN32
#include <windows.h>
void cs_setpriority(int32_t prio)
{
  HANDLE WinId;
  uint32_t wprio;
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
void cs_setpriority(int32_t prio)
{
#ifdef PRIO_PROCESS
  setpriority(PRIO_PROCESS, 0, prio);  // ignore errors
#endif
}
#endif

/* Checks an array if it is filled (a value > 0) and returns the last position (1...length) where something was found.
   length specifies the maximum length to check for. */
int32_t check_filled(uchar *value, int32_t length){
	if(value == NULL) return 0;
	int32_t i, j = 0;
	for (i = 0; i < length; ++i){
		if(value[i] > 0) j = i + 1;
	}
	return j;
}

/* This function encapsulates malloc. It automatically adds an error message to the log if it failed and calls cs_exit(quiterror) if quiterror > -1. 
   result will be automatically filled with the new memory position or NULL on failure. */
void *cs_malloc(void *result, size_t size, int32_t quiterror){
	void **tmp = (void *)result;
	*tmp = malloc (size);
	if(*tmp == NULL){
		cs_log("Couldn't allocate memory (errno=%d %s)!", errno, strerror(errno));
		if(quiterror > -1) cs_exit(quiterror);
	} else {
		memset(*tmp, 0, size);
	}
	return *tmp;
}

/* This function encapsulates realloc. It automatically adds an error message to the log if it failed and calls cs_exit(quiterror) if quiterror > -1.
	result will be automatically filled with the new memory position or NULL on failure. If a failure occured, the existing memory in result will be freed. */
void *cs_realloc(void *result, size_t size, int32_t quiterror){
	void **tmp = (void *)result, **tmp2 = (void *)result;
	*tmp = realloc (*tmp, size);
	if(*tmp == NULL){
		cs_log("Couldn't allocate memory (errno=%d %s)!", errno, strerror(errno));
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
void char_to_hex(const unsigned char* p_array, uint32_t p_array_len, unsigned char *result) {
	result[p_array_len*2] = '\0';
	const unsigned char* p_end = p_array + p_array_len;
	uint32_t pos=0;
	const unsigned char* p;
	for( p = p_array; p != p_end; p++, pos+=2 ) {
		result[pos] = to_hex(*p >> 4);
		result[pos+1] = to_hex(*p & 15);
	}
}

/* Creates a random string with specified length. Note that dst must be one larger than size to hold the trailing \0*/
void create_rand_str(char *dst, int32_t size){
	int32_t i;
	for (i = 0; i < size; ++i){
		dst[i] = (rand() % 94) + 32;
	}
	dst[i] = '\0';
}
#endif

/* Return 1 if the file exists, else 0 */
int32_t file_exists(const char * filename){
	FILE *file;
	if ((file = fopen(filename, "r"))){
		fclose(file);
		return 1;
	}
	return 0;
}

/* Clears the s_ip structure provided. The pointer will be set to NULL so everything is cleared.*/
void clear_sip(struct s_ip **sip){
	struct s_ip *cip = *sip;
	for (*sip = NULL; cip != NULL; cip = cip->next){
		add_garbage(cip);
	}
}

/* Clears the s_ftab struct provided by setting nfilts and nprids to zero. */
void clear_ftab(struct s_ftab *ftab){
	int32_t i, j;
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
	int32_t i = ptab->nports;
	ptab->nports = 0;
	for (; i >= 0; --i) {
		ptab->ports[i].ftab.nfilts = 0;
		ptab->ports[i].ftab.filts[0].nprids = 0;
	}	
}

/* Clears given caidtab */
void clear_caidtab(struct s_caidtab *ctab){
	memset(ctab, 0, sizeof(struct s_caidtab));
	int32_t i;
	for (i = 1; i < CS_MAXCAIDTAB; ctab->mask[i++] = 0xffff);
}

/* Clears given tuntab */
void clear_tuntab(struct s_tuntab *ttab){
	memset(ttab, 0, sizeof(struct s_tuntab));
}

/* Copies a file from srcfile to destfile. If an error occured before writing, -1 is returned, else -2. On success, 0 is returned.*/
int32_t file_copy(char *srcfile, char *destfile){
	FILE *src, *dest;
  int32_t ch;
  if((src = fopen(srcfile, "r"))==NULL) {
  	cs_log("Error opening file %s for reading (errno=%d %s)!", srcfile, errno, strerror(errno));
    return(-1);
  }
  if((dest = fopen(destfile, "w"))==NULL) {
  	cs_log("Error opening file %s for writing (errno=%d %s)!", destfile, errno, strerror(errno));
  	fclose(src);
    return(-1);
  }

	while(1){
		ch = fgetc(src);
		if(ch==EOF){
			break;
		}	else {
			fputc(ch, dest);
			if(ferror(dest)) {
				cs_log("Error while writing to file %s (errno=%d %s)!", destfile, errno, strerror(errno));
				fclose(src);
				fclose(dest);
				return(-2);
			}
		}
	}
	fclose(src);
	fclose(dest);
	return(0);
}

/* Overwrites destfile with tmpfile. If forceBakOverWrite = 0, the bakfile will not be overwritten if it exists, else it will be.*/
int32_t safe_overwrite_with_bak(char *destfile, char *tmpfile, char *bakfile, int32_t forceBakOverWrite){
	int32_t rc;
	if (file_exists(destfile)) {
		if(forceBakOverWrite != 0 || !file_exists(bakfile)){
			if(file_copy(destfile, bakfile) < 0){
				cs_log("Error copying original config file %s to %s. The original config will be left untouched!", destfile, bakfile);
				if(remove(tmpfile) < 0) cs_log("Error removing temp config file %s (errno=%d %s)!", tmpfile, errno, strerror(errno));
				return(1);
			}
		}
	}
	if((rc = file_copy(tmpfile, destfile)) < 0){
		cs_log("An error occured while writing the new config file %s.", destfile);
		if(rc == -2) cs_log("The config will be missing or only partly filled upon next startup as this is a non-recoverable error! Please restore from backup or try again.", destfile);
		if(remove(tmpfile) < 0) cs_log("Error removing temp config file %s (errno=%d %s)!", tmpfile, errno, strerror(errno));
		return(1);
	}
	if(remove(tmpfile) < 0) cs_log("Error removing temp config file %s (errno=%d %s)!", tmpfile, errno, strerror(errno));
	return(0);
}

/* Ordinary strncpy does not terminate the string if the source is exactly as long or longer as the specified size. This can raise security issues.
   This function is a replacement which makes sure that a \0 is always added. num should be the real size of char array (do not subtract -1). */
void cs_strncpy(char * destination, const char * source, size_t num){
	uint32_t l, size = strlen(source);
	if(size > num - 1) l = num - 1;
	else l = size;
	memcpy(destination, source, l);
	destination[l] = '\0';
}

/* This function is similar to strncpy but is case insensitive when comparing. */
int32_t cs_strnicmp(const char * str1, const char * str2, size_t num){
	uint32_t i, len1 = strlen(str1), len2 = strlen(str2);
	int32_t diff;
	for(i = 0; i < len1 && i < len2 && i < num; ++i){
		diff = toupper(str1[i]) - toupper(str2[i]);
		if (diff != 0) return diff;
	}
	return 0;
}

/* Converts the string txt to it's lower case representation. */
char *strtolower(char *txt){
  char *p;
  for (p=txt; *p; p++)
    if (isupper((uchar)*p)) *p=tolower((uchar)*p);
  return(txt);
}

/* Allocates a new empty string and copies str into it. You need to free() the result. */
char *strnew(char *str){
  if (!str)
    return NULL;
    
  char *newstr = cs_malloc(&newstr, strlen(str)+1, 1);
  cs_strncpy(newstr, str, strlen(str)+1);
  
  return newstr;
}

/* Gets the servicename. Make sure that buf is at least 32 bytes large. */
char *get_servicename(struct s_client *cl, uint16_t srvid, uint16_t caid, char *buf){
	int32_t i;
	struct s_srvid *this;
	buf[0] = '\0';

	if (!srvid)
		return(buf);

	if (cl && cl->last_srvidptr && cl->last_srvidptr->srvid==srvid)
		for (i=0; i < cl->last_srvidptr->ncaid; i++)
			if (cl->last_srvidptr->caid[i] == caid && cl->last_srvidptr->name){
				cs_strncpy(buf, cl->last_srvidptr->name, 32);
				return(buf);
			}

	for (this = cfg.srvid[srvid>>12]; this && (!buf[0]); this = this->next)
		if (this->srvid == srvid)
			for (i=0; i < this->ncaid; i++)
				if (this->caid[i] == caid && this->name) {
					cs_strncpy(buf, this->name, 32);
					cl->last_srvidptr = this;
					return(buf);
				}

	if (!buf[0]) {
		snprintf(buf, 32, "%04X:%04X unknown", caid, srvid);
		cl->last_srvidptr = NULL;
	}
	return(buf);
}

/* Gets the tier name. Make sure that buf is at least 83 bytes long. */
char *get_tiername(uint16_t tierid, uint16_t caid, char *buf){
	int32_t i;
	struct s_tierid *this = cfg.tierid;

	for (buf[0] = 0; this && (!buf[0]); this = this->next)
		if (this->tierid == tierid)
			for (i=0; i<this->ncaid; i++)
				if (this->caid[i] == caid)
					cs_strncpy(buf, this->name, 32);

	//if (!name[0]) sprintf(name, "%04X:%04X unknown", caid, tierid);
	if (!tierid) buf[0] = '\0';
	return(buf);
}

/* Gets the provider name. Make sure that buf is at least 83 bytes long. */
char *get_provider(uint16_t caid, uint32_t provid, char *buf){
	struct s_provid *this = cfg.provid;

	for (buf[0] = 0; this && (!buf[0]); this = this->next) {
		if (this->caid == caid && this->provid == provid) {
			snprintf(buf, 83, "%s", this->prov);
			if (this->sat[0]) {
				strcat(buf, " / ");
				strcat(buf, this->sat);
			}
			if (this->lang[0]) {
				strcat(buf, " / ");
				strcat(buf, this->lang);
			}
		}
	}

	if (!buf[0]) snprintf(buf, 83, "%04X:%06X unknown", caid, provid);
	if (!caid) buf[0] = '\0';
	return(buf);
}

uint32_t seed;

/* A fast random number generator. Depends on initialization of seed from init_rnd(). 
   Only use this if you don't need good random numbers (so don't use in security critical situations). */
uchar fast_rnd() {
	uint32_t offset = 12923;
	uint32_t multiplier = 4079;

	seed = seed * multiplier + offset;
	return (uchar) (seed % 0xFF);
}

/* Initializes the random number generator and the seed for the fast_rnd() function. */
void init_rnd() {
	srand((uint32_t)time((time_t *)NULL));
	seed = (uint32_t) time((time_t*)0);
}

int32_t hexserialset(struct s_reader *rdr)
{
	int32_t i;

	if (!rdr) return 0;

	for (i = 0; i < 8; i++)
		if (rdr->hexserial[i])
			return 1;
	return 0;
}

static char *netw_ext_prot[] = { "cccam", "cccam ext", "newcamd524" };

char *reader_get_type_desc(struct s_reader * rdr, int32_t extended __attribute__((unused)))
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

#ifdef MODULE_CCCAM
	else if (rdr->typ == R_CCCAM) {
		desc = netw_ext_prot[0];
		struct s_client *cl = rdr->client;
		if (cl) {
			struct cc_data *cc = cl->cc;
			if (cc && cc->extended_mode)
				desc = netw_ext_prot[extended];
		}
	}
#endif

	return (desc);
}

char *monitor_get_proto(struct s_client *cl)
{
	char *ctyp;
	switch(cl->typ) {
		case 's'	: ctyp = "server"; break;
		case 'h'	: ctyp = "http"; break;
		case 'p'	:
		case 'r'	: ctyp = reader_get_type_desc(cl->reader, 1); break;
#ifdef CS_ANTICASC
		case 'a'	: ctyp = "anticascader"; break;
#endif
#ifdef MODULE_CCCAM
		case 'c'	:
			if (cl->cc && ((struct cc_data *)cl->cc)->extended_mode) {
				ctyp = netw_ext_prot[1];
				break;
			}
#endif
		default		: ctyp = ph[cl->ctyp].desc;
	}
	return(ctyp);
}

/*
 * resolve clienttype for newcamdprotocol
 */
char *get_ncd_client_name(char *client_id)
{
        static const int32_t max_id_idx = 32;
        static const char const *ncd_service_ids[] = { "0000", "5644", "4C43", "4333", "7264", "6762", "6D67", "7763", "6E73", "6378", "6B61",
                                           "6576", "4343", "5456", "414C", "0666", "0667", "9911", "434C", "4765", "5342",
                                           "6E65", "4E58", "4453", "8888", "7363", "0669", "0665", "0769", "4543", "6D63",
                                           "6B63", "6502" };

        static char *ncd_service_names[] = { "generic", "vdr-sc", "LCE", "camd3", "radegast", "gbox2CS", "mgcamd", //actually a const so threadsafe
                                             "WinCSC", "NewCS", "cx", "Kaffeine", "evocamd", "CCcam", "Tecview",
                                             "AlexCS", "rqcamd", "rq-echo-client", "ACamd", "Cardlink", "Octagon", "SBCL",
                                             "NextYE2k", "NextYE2k", "DiabloCam/UW", "OSCam", "Scam", "rq-sssp-client/CW",
                                             "rq-sssp-client/CS", "JlsRq", "eyetvCamd", "mpcs", "kpcs", "Tvheadend", "unknown - please report" };

        int32_t idx = 0;
        for (idx = 0; idx <= max_id_idx; idx++) {
		if(!memcmp(ncd_service_ids[idx], client_id, 4))
                        return ncd_service_names[idx];

        }

        return ncd_service_names[max_id_idx+1];
}


void hexserial_to_newcamd(uchar *source, uchar *dest, uint16_t caid)
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

void newcamd_to_hexserial(uchar *source, uchar *dest, uint16_t caid)
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

/**
 * creates a lock
 **/
void cs_lock_create(CS_MUTEX_LOCK *l, int16_t timeout, const char *name)
{
	memset(l, 0, sizeof(CS_MUTEX_LOCK));
	l->timeout = timeout;
	l->name = name;
	pthread_mutex_init(&l->lock, NULL);
	pthread_cond_init(&l->writecond, NULL);
	pthread_cond_init(&l->readcond, NULL);
#ifdef WITH_MUTEXDEBUG
	cs_debug_mask_nolock(D_TRACE, "lock %s created", name);
#endif
}

void cs_lock_destroy(CS_MUTEX_LOCK *l)
{
	l->name = NULL;
	pthread_mutex_destroy(&l->lock);
	pthread_cond_destroy(&l->writecond);
	pthread_cond_destroy(&l->readcond);
#ifdef WITH_MUTEXDEBUG
	cs_debug_mask_nolock(D_TRACE, "lock %s destroyed", l->name);
#endif
}

void cs_rwlock_int(CS_MUTEX_LOCK *l, int8_t type) {
	struct timespec ts;
	int8_t ret = 0;

	if (!l || !l->name)
		return;

	ts.tv_sec = time(NULL) + l->timeout;
	ts.tv_nsec = 0;

	pthread_mutex_lock(&l->lock);

	if (type == WRITELOCK) {
		l->writelock++;
		// if read- or writelock is busy, wait for unlock
		if (l->writelock > 1 || l->readlock > 0)
			ret = pthread_cond_timedwait(&l->writecond, &l->lock, &ts);
	} else {
		l->readlock++;
		// if writelock is busy, wait for unlock
		if (l->writelock > 0)
			ret = pthread_cond_timedwait(&l->readcond, &l->lock, &ts);
	}

	if (ret > 0) {
		// lock wasn't returned within time, assume locking thread to
		// be stuck or finished, so enforce lock.
		l->writelock = (type==WRITELOCK) ? 1 : 0;
		l->readlock = (type==WRITELOCK) ? 0 : 1;
		cs_log_nolock("WARNING lock %s timed out.", l->name);
	}
	
	pthread_mutex_unlock(&l->lock);
#ifdef WITH_MUTEXDEBUG
	cs_debug_mask_nolock(D_TRACE, "lock %s locked", l->name);
#endif
	return;
}

void cs_rwunlock_int(CS_MUTEX_LOCK *l, int8_t type) {

	if (!l || !l->name)
		return;

	pthread_mutex_lock(&l->lock);

	if (type == WRITELOCK)
		l->writelock--;
	else
		l->readlock--;

	if (l->writelock < 0) l->writelock = 0;
	if (l->readlock < 0) l->readlock = 0;

	// waiting writelocks always have priority. If one is waiting, signal it
	if (l->writelock)
		pthread_cond_signal(&l->writecond);
	// Otherwise signal a waiting readlock (if any)
	else if (l->readlock && type != READLOCK)
		pthread_cond_broadcast(&l->readcond);

	pthread_mutex_unlock(&l->lock);

#ifdef WITH_MUTEXDEBUG
	const char *typetxt[] = { "", "write", "read" };
	cs_debug_mask_nolock(D_TRACE, "%slock %s: released", typetxt[type], l->name);
#endif
}

int8_t cs_try_rwlock_int(CS_MUTEX_LOCK *l, int8_t type) {
	if (!l || !l->name)
		return 0;

	int8_t status = 0;

	pthread_mutex_lock(&l->lock);

	if (type==WRITELOCK) {
		if (l->writelock || l->readlock)
			status = 1;
		else
			l->writelock++;
	}
	else {
		if (l->writelock)
			status = 1;
		else
			l->readlock++;
	}

	pthread_mutex_unlock(&l->lock);

#ifdef WITH_MUTEXDEBUG
	const char *typetxt[] = { "", "write", "read" };
	cs_debug_mask_nolock(D_TRACE, "try_%slock %s: status=%d", typetxt[type], l->name, status);
#endif
	return status;
}

/* Returns the ip from the given hostname. If gethostbyname is configured in the config file, a lock 
   will be held until the ip has been resolved. */
uint32_t cs_getIPfromHost(const char *hostname){
	uint32_t result = 0;
	//Resolve with gethostbyname:
	if (cfg.resolve_gethostbyname) {
		cs_writelock(&gethostbyname_lock);
		struct hostent *rht = gethostbyname(hostname);
		if (!rht)
			cs_log("can't resolve %s", hostname);
		else
			result=((struct in_addr*)rht->h_addr)->s_addr;
		cs_writeunlock(&gethostbyname_lock);
	}	else { //Resolve with getaddrinfo:
		struct addrinfo hints, *res = NULL;
		memset(&hints, 0, sizeof(hints));
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_family = AF_INET;
		hints.ai_protocol = IPPROTO_TCP;

		int32_t err = getaddrinfo(hostname, NULL, &hints, &res);
		if (err != 0 || !res || !res->ai_addr) {
			cs_log("can't resolve %s, error: %s", hostname, err ? gai_strerror(err) : "unknown");
		} else {
			result=((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr;
		}
		if (res) freeaddrinfo(res);
	}
	return result;
}

void setTCPTimeouts(int32_t socket){
	int32_t flag = 1;
	// this is not only for a real keepalive but also to detect closed connections so it should not be configurable
	if(setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag)) && errno != EBADF){
		cs_log("Setting SO_KEEPALIVE failed, errno=%d, %s", errno, strerror(errno));
	}
#if defined(TCP_KEEPIDLE) && defined(TCP_KEEPCNT) && defined(TCP_KEEPINTVL)
	flag = 180;
	if(setsockopt(socket, SOL_TCP, TCP_KEEPIDLE, &flag, sizeof(flag)) && errno != EBADF){	//send first keepalive packet after 3 minutes of last package received (keepalive packets included)
		cs_log("Setting TCP_KEEPIDLE failed, errno=%d, %s", errno, strerror(errno));
	}
	flag = 3;
	if(setsockopt(socket, SOL_TCP, TCP_KEEPCNT, &flag, sizeof(flag)) && errno != EBADF){		//send up to 3 keepalive packets out (in interval TCP_KEEPINTVL), then disconnect if no response
		cs_log("Setting TCP_KEEPCNT failed, errno=%d, %s", errno, strerror(errno));
	}
	flag = 5;
	if(setsockopt(socket, SOL_TCP, TCP_KEEPINTVL, &flag, sizeof(flag)) && errno != EBADF){;		//send a keepalive packet out every 5 seconds (until answer has been received or TCP_KEEPCNT has been reached)
		cs_log("Setting TCP_KEEPINTVL failed, errno=%d, %s", errno, strerror(errno));
	}
#endif
	struct timeval tv;
	tv.tv_sec = 60;
	tv.tv_usec = 0;
	if(setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval)) && errno != EBADF){;
		cs_log("Setting SO_SNDTIMEO failed, errno=%d, %s", errno, strerror(errno));
	}
	tv.tv_sec = 600;
	tv.tv_usec = 0;
	if(setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval)) && errno != EBADF){;
		cs_log("Setting SO_RCVTIMEO failed, errno=%d, %s", errno, strerror(errno));
	}
}


struct s_reader *get_reader_by_label(char *lbl){
	struct s_reader *rdr;
	LL_ITER itr = ll_iter_create(configured_readers);
	while((rdr = ll_iter_next(&itr)))
	  if (strcmp(lbl, rdr->label) == 0) break;
	return rdr;
}

struct s_client *get_client_by_name(char *name) {
	struct s_client *cl;
	for (cl = first_client; cl ; cl = cl->next) {
		if (strcmp(name, cl->account->usr) == 0)
			return cl;
	}
	return NULL;
}

struct s_auth *get_account_by_name(char *name) {
	struct s_auth *account;
	for (account=cfg.account; (account); account=account->next) {
		if(strcmp(name, account->usr) == 0)
			return account;
	}
	return NULL;
}

int8_t is_valid_client(struct s_client *client) {
	struct s_client *cl;
	for (cl=first_client; cl ; cl=cl->next) {
		if (cl==client)
			return 1;
	}
	return 0;
}

int8_t check_fd_for_data(int32_t fd) {
	int32_t rc;
	struct pollfd pfd[1];

	pfd[0].fd = fd;
	pfd[0].events = POLLIN | POLLPRI | POLLHUP;
	rc = poll(pfd, 1, 0);

	if (rc == -1)
		cs_log("check_fd_for_data(fd=%d) failed: (errno=%d %s)", fd, errno, strerror(errno));

	if (rc == -1 || rc == 0)
		return rc;

	if (pfd[0].revents & POLLHUP)
		return -2;

	return 1;
}

void add_ms_to_timespec(struct timespec *timeout, int32_t msec) {
	struct timeval now;
	gettimeofday(&now, NULL);

	int32_t nano_secs	= ((now.tv_usec * 1000) + ((msec % 1000) * 1000 * 1000));

	timeout->tv_sec = now.tv_sec + (msec / 1000) + (nano_secs / 1000000000);
	timeout->tv_nsec = nano_secs % 1000000000;
}

int32_t add_ms_to_timeb(struct timeb *tb, int32_t ms) {
	tb->time += ms / 1000;
	tb->millitm += ms % 1000;

	if (tb->millitm >= 1000) {
		tb->millitm -= 1000;
		tb->time++;
	}

	struct timeb tb_now;
	cs_ftime(&tb_now);

	int32_t secs, msecs;
	secs = tb->time - tb_now.time;

	msecs = tb->millitm - tb_now.millitm;

	if (msecs<0) {
		secs--;
		msecs += 1000;
	}

	return ((secs * 1000) + msecs);
}
