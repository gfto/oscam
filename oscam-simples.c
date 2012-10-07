//FIXME Not checked on threadsafety yet; after checking please remove this line
#include "globals.h"
#include "module-cccam.h"
#include "oscam-client.h"
#include "oscam-garbage.h"
#include "oscam-string.h"

extern struct s_cardsystem cardsystems[CS_MAX_MOD];

char *remote_txt(void)
{
  if (cur_client()->typ == 'c')
    return("client");
  else
    return("remote server");
}

int32_t comp_timeb(struct timeb *tpa, struct timeb *tpb)
{
	return ((tpa->time - tpb->time) * 1000) + (tpa->millitm - tpb->millitm);
}

/* Checks if year is a leap year. If so, 1 is returned, else 0. */
static int8_t is_leap(unsigned y){
	return (y % 4) == 0 && ((y % 100) != 0 || (y % 400) == 0);
}

/* Drop-in replacement for timegm function as some plattforms strip the function from their libc.. */
time_t cs_timegm(struct tm *tm){
	time_t result = 0;
	int32_t i;

	if (tm->tm_mon > 12 || tm->tm_mon < 0 || tm->tm_mday > 31 || tm->tm_min > 60 ||	tm->tm_sec > 60 || tm->tm_hour > 24) {
		return 0;
	}

	for (i = 70; i < tm->tm_year; ++i)
		result += is_leap(i + 1900) ? 366 : 365;

	for (i = 0; i < tm->tm_mon; ++i){
		if(i == 0 || i == 2 || i == 4 || i == 6 || i == 7 || i == 9 || i == 11) result += 31;
		else if(i == 3 || i == 5 || i == 8 || i == 10) result += 30;
		else if(is_leap(tm->tm_year + 1900)) result += 29;
		else result += 28;
	}

	result += tm->tm_mday - 1;
	result *= 24;
	result += tm->tm_hour;
	result *= 60;
	result += tm->tm_min;
	result *= 60;
	result += tm->tm_sec;
	return result;
}

/* Drop-in replacement for gmtime_r as some plattforms strip the function from their libc. */
struct tm *cs_gmtime_r(const time_t *timep, struct tm *r) {
	const int16_t daysPerMonth[13] =
  { 0,
    (31),
    (31+28),
    (31+28+31),
    (31+28+31+30),
    (31+28+31+30+31),
    (31+28+31+30+31+30),
    (31+28+31+30+31+30+31),
    (31+28+31+30+31+30+31+31),
    (31+28+31+30+31+30+31+31+30),
    (31+28+31+30+31+30+31+31+30+31),
    (31+28+31+30+31+30+31+31+30+31+30),
    (31+28+31+30+31+30+31+31+30+31+30+31),
  };
  time_t i;
  time_t work=*timep%86400;
  r->tm_sec=work%60; work/=60;
  r->tm_min=work%60; r->tm_hour=work/60;
  work=*timep/86400;
  r->tm_wday=(4+work)%7;
  for (i=1970; ; ++i) {
    time_t k = is_leap(i)?366:365;
    if (work>=k)
      work-=k;
    else
      break;
  }
  r->tm_year=i-1900;
  r->tm_yday=work;

  r->tm_mday=1;
  if (is_leap(i) && (work>58)) {
    if (work==59) r->tm_mday=2; /* 29.2. */
    work-=1;
  }

  for (i=11; i && (daysPerMonth[i]>work); --i) ;
  r->tm_mon=i;
  r->tm_mday+=work-daysPerMonth[i];
  return r;
}

/* Drop-in replacement for ctime_r as some plattforms strip the function from their libc. */
char *cs_ctime_r(const time_t *timep, char* buf) {
	struct tm t;
	localtime_r(timep, &t);
	strftime(buf, 26, "%c\n", &t);
  return buf;
}

void cs_ftime(struct timeb *tp)
{
  struct timeval tv;
  gettimeofday(&tv, (struct timezone *)0);
  tp->time=tv.tv_sec;
  tp->millitm=tv.tv_usec/1000;
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

#if defined(__CYGWIN__)
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

/* Gets the servicename. Make sure that buf is at least 32 bytes large. */
char *get_servicename(struct s_client *cl, uint16_t srvid, uint16_t caid, char *buf){
	int32_t i;
	struct s_srvid *this;
	buf[0] = '\0';

	if (!srvid || (srvid>>12) >= 16) //cfg.srvid[16]
		return(buf);

	if (cl && cl->last_srvidptr && cl->last_srvidptr->srvid==srvid)
		for (i=0; i < cl->last_srvidptr->ncaid; i++)
			if (cl->last_srvidptr->caid[i] == caid && cl->last_srvidptr->name){
				cs_strncpy(buf, cl->last_srvidptr->name, 32);
				return(buf);
			}

	for (this = cfg.srvid[srvid>>12]; this; this = this->next)
		if (this->srvid == srvid)
			for (i=0; i < this->ncaid; i++)
				if (this->caid[i] == caid && this->name && cl) {
					cs_strncpy(buf, this->name, 32);
					cl->last_srvidptr = this;
					return(buf);
				}

	if (!buf[0]) {
		snprintf(buf, 32, "%04X:%04X unknown", caid, srvid);
		if (cl) cl->last_srvidptr = NULL;
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

/* Gets the provider name. */
char *get_provider(uint16_t caid, uint32_t provid, char *buf, uint32_t buflen){
	struct s_provid *this = cfg.provid;

	for (buf[0] = 0; this && (!buf[0]); this = this->next) {
		if (this->caid == caid && this->provid == provid) {
			snprintf(buf, buflen, "%s%s%s%s%s", this->prov,
					this->sat[0] ? " / " : "", this->sat,
					this->lang[0] ? " / " : "", this->lang);
		}
	}

	if (!buf[0]) snprintf(buf, buflen, "%04X:%06X unknown", caid, provid);
	if (!caid) buf[0] = '\0';
	return(buf);
}

// Add provider description. If provider was already present, do nothing.
void add_provider(uint16_t caid, uint32_t provid, const char *name, const char *sat, const char *lang)
{
	struct s_provid **ptr;
	for (ptr = &cfg.provid; *ptr; ptr = &(*ptr)->next) {
		if ((*ptr)->caid == caid && (*ptr)->provid == provid)
			return;
	}

	struct s_provid *prov;
	if (!cs_malloc(&prov, sizeof(struct s_provid)))
		return;

	prov->provid = provid;
	prov->caid = caid;
	cs_strncpy(prov->prov, name, sizeof(prov->prov));
	cs_strncpy(prov->sat, sat, sizeof(prov->sat));
	cs_strncpy(prov->lang, lang, sizeof(prov->lang));
	*ptr = prov;
}

uint32_t seed;

/* A fast random number generator. Depends on initialization of seed from init_rnd().
   Only use this if you don't need good random numbers (so don't use in security critical situations). */
uchar fast_rnd(void) {
	uint32_t offset = 12923;
	uint32_t multiplier = 4079;

	seed = seed * multiplier + offset;
	return (uchar) (seed % 0xFF);
}

/* Initializes the random number generator and the seed for the fast_rnd() function. */
void init_rnd(void) {
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

char *reader_get_type_desc(struct s_reader * rdr, int32_t extended __attribute__((unused)))
{
	static char *typtxt[] = { "unknown", "mouse", "mouse", "sc8in1", "mp35", "mouse", "internal", "smartreader", "pcsc" };
	char *desc = typtxt[0];

	if (rdr->crdr.active==1)
		return rdr->crdr.desc;

	if (is_network_reader(rdr) || rdr->typ == R_SERIAL) {
		if (rdr->ph.desc)
			desc = rdr->ph.desc;
	} else if (rdr->typ >= 0 && rdr->typ < (int32_t)(sizeof(typtxt)/sizeof(char *))){
		desc = typtxt[rdr->typ];
	}

	if ((rdr->typ == R_NEWCAMD) && (rdr->ncd_proto == NCD_524))
		desc = "newcamd524";

#ifdef MODULE_CCCAM
	else if (extended && rdr->typ == R_CCCAM) {
		struct s_client *cl = rdr->client;
		if (cl) {
			struct cc_data *cc = cl->cc;
			if (cc && cc->extended_mode)
				desc = "cccam ext";
		}
	}
#endif

	return (desc);
}

void hexserial_to_newcamd(uchar *source, uchar *dest, uint16_t caid)
{
  if (caid == 0x5581 || caid == 0x4aee) // Bulcrypt
  {
    dest[0] = 0x00;
    dest[1] = 0x00;
    memcpy(dest + 2, source, 4);
    return;
  }
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

struct s_reader *get_reader_by_label(char *lbl){
	struct s_reader *rdr;
	LL_ITER itr = ll_iter_create(configured_readers);
	while((rdr = ll_iter_next(&itr)))
	  if (strcmp(lbl, rdr->label) == 0) break;
	return rdr;
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

	return comp_timeb(tb, &tb_now);
}

int32_t ecmfmt(uint16_t caid, uint32_t prid, uint16_t chid, uint16_t pid, uint16_t srvid, uint16_t l, uint16_t checksum, char *result, size_t size)
{
	if (!cfg.ecmfmt)
		return snprintf(result, size, "%04X&%06X/%04X/%04X/%02X:%04X", caid, prid, chid, srvid, l, htons(checksum));

	uint32_t s=0, zero=0, flen=0, value=0;
	char *c = cfg.ecmfmt, fmt[5] = "%04X";
	while (*c) {
		switch(*c)
		{
			case '0': zero=1; value=0; break;
			case 'c': flen=4; value=caid; break;
			case 'p': flen=6; value=prid; break;
			case 'i': flen=4; value=chid; break;
			case 'd': flen=4; value=pid; break;
			case 's': flen=4; value=srvid; break;
			case 'l': flen=2; value=l; break;
			case 'h': flen=4; value=htons(checksum); break;
			case '\\':
				c++;
				flen=0;
				value=*c;
				break;
			default:  flen=0; value=*c; break;
		}
		if (value) zero=0;

		if (!zero) {
			//fmt[0] = '%';
			if (flen) { //Build %04X / %06X / %02X
				fmt[1] = '0';
				fmt[2] = flen+'0';
				fmt[3] = 'X';
				fmt[4] = 0;
			}
			else {
				fmt[1] = 'c';
				fmt[2] = 0;
			}

			s += snprintf(result+s, size-s, fmt, value);
		}
		c++;
	}
	return s;
}

int32_t format_ecm(ECM_REQUEST *ecm, char *result, size_t size)
{
	return ecmfmt(ecm->caid, ecm->prid, ecm->chid, ecm->pid, ecm->srvid, ecm->l, ecm->checksum, result, size);
}

int32_t check_sct_len(const uchar *data, int32_t off)
{
	int32_t len = SCT_LEN(data);
	if (len + off > MAX_LEN) {
		cs_debug_mask(D_READER, "check_sct_len(): smartcard section too long %d > %d", len, MAX_LEN - off);
		len = -1;
	}
	return len;
}

int8_t cs_emmlen_is_blocked(struct s_reader *rdr, int16_t len)
{
	int i;
	for (i = 0; i < CS_MAXEMMBLOCKBYLEN; i++)
		if (rdr->blockemmbylen[i] == len)
			return 1;
	return 0;
}

struct s_cardsystem *get_cardsystem_by_caid(uint16_t caid) {
	int32_t i, j;
	for (i = 0; i < CS_MAX_MOD; i++) {
		if (cardsystems[i].caids) {
			for (j = 0; j < 2; j++) {
				uint16_t cs_caid = cardsystems[i].caids[j];
				if (cs_caid == caid || cs_caid == caid >> 8)
					return &cardsystems[i];
			}
		}
	}
	return NULL;
}
