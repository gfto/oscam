#include "globals.h"

#ifdef CS_CACHEEX

#include "oscam-chk.h"
#include "oscam-client.h"
#include "oscam-conf.h"
#include "module-cacheex.h"

#define cs_cacheex_matcher "oscam.cacheex"

extern uint8_t cc_node_id[8];
extern uint8_t camd35_node_id[8];
extern CS_MUTEX_LOCK ecmcache_lock;
extern struct ecm_request_t *ecmcwcache;

uint8_t cacheex_peer_id[8];
static LLIST *invalid_cws;

void cacheex_init(void) {
	// Init random node id
	int i;
	for (i = 0; i < 8; i++)
		cacheex_peer_id[i] = fast_rnd();
#ifdef MODULE_CCCAM
	memcpy(cacheex_peer_id, cc_node_id, 8);
#endif
#ifdef MODULE_CAMD35_TCP
	memcpy(camd35_node_id, cacheex_peer_id, 8);
#endif
}

void cacheex_clear_account_stats(struct s_auth *account) {
	account->cwcacheexgot = 0;
	account->cwcacheexpush = 0;
	account->cwcacheexhit = 0;
}

void cacheex_clear_client_stats(struct s_client *client) {
	client->cwcacheexgot = 0;
	client->cwcacheexpush = 0;
	client->cwcacheexhit = 0;
}

int32_t cacheex_add_stats(struct s_client *cl, uint16_t caid, uint16_t srvid, uint32_t prid, uint8_t direction)
{
	if (!cfg.cacheex_enable_stats)
		return -1;

	// create list if doesn't exist
	if (!cl->ll_cacheex_stats)
		cl->ll_cacheex_stats = ll_create("ll_cacheex_stats");

	time_t now = time((time_t*)0);
	LL_ITER itr = ll_iter_create(cl->ll_cacheex_stats);
	S_CACHEEX_STAT_ENTRY *cacheex_stats_entry;

	// check for existing entry
	while ((cacheex_stats_entry = ll_iter_next(&itr))) {
		if (cacheex_stats_entry->cache_srvid == srvid &&
				cacheex_stats_entry->cache_caid == caid &&
				cacheex_stats_entry->cache_prid == prid &&
				cacheex_stats_entry->cache_direction == direction) {
			// we already have this entry - just add count and time
			cacheex_stats_entry->cache_count++;
			cacheex_stats_entry->cache_last = now;
			return cacheex_stats_entry->cache_count;
		}
	}

	// if we land here we have to add a new entry
	if (cs_malloc(&cacheex_stats_entry, sizeof(S_CACHEEX_STAT_ENTRY), -1)){
		cacheex_stats_entry->cache_caid = caid;
		cacheex_stats_entry->cache_srvid = srvid;
		cacheex_stats_entry->cache_prid = prid;
		cacheex_stats_entry->cache_count = 1;
		cacheex_stats_entry->cache_last = now;
		cacheex_stats_entry->cache_direction = direction;
		ll_iter_insert(&itr, cacheex_stats_entry);
		return 1;
	}
	return 0;
}


int8_t cacheex_maxhop(struct s_client *cl)
{
	int maxhop = 10;
	if (cl->reader && cl->reader->cacheex_maxhop)
		maxhop = cl->reader->cacheex_maxhop;
	else if (cl->account && cl->account->cacheex_maxhop)
		maxhop = cl->account->cacheex_maxhop;
	return maxhop;
}

static void cacheex_cache_push_to_client(struct s_client *cl, ECM_REQUEST *er)
{
	add_job(cl, ACTION_CACHE_PUSH_OUT, er, 0);
}

/**
 * cacheex modes:
 *
 * cacheex=1 CACHE PULL:
 * Situation: oscam A reader1 has cacheex=1, oscam B account1 has cacheex=1
 *   oscam A gets a ECM request, reader1 send this request to oscam B, oscam B checks his cache
 *   a. not found in cache: return NOK
 *   a. found in cache: return OK+CW
 *   b. not found in cache, but found pending request: wait max cacheexwaittime and check again
 *   oscam B never requests new ECMs
 *
 *   CW-flow: B->A
 *
 * cacheex=2 CACHE PUSH:
 * Situation: oscam A reader1 has cacheex=2, oscam B account1 has cacheex=2
 *   if oscam B gets a CW, its pushed to oscam A
 *   reader has normal functionality and can request ECMs
 *
 *   Problem: oscam B can only push if oscam A is connected
 *   Problem or feature?: oscam A reader can request ecms from oscam B
 *
 *   CW-flow: B->A
 *
 * cacheex=3 REVERSE CACHE PUSH:
 * Situation: oscam A reader1 has cacheex=3, oscam B account1 has cacheex=3
 *   if oscam A gets a CW, its pushed to oscam B
 *
 *   oscam A never requests new ECMs
 *
 *   CW-flow: A->B
 */
void cacheex_cache_push(ECM_REQUEST *er)
{
	if (er->rc >= E_NOTFOUND && er->rc != E_UNHANDLED) //Maybe later we could support other rcs
		return; //NOT FOUND/Invalid

	if (er->cacheex_pushed || (er->ecmcacheptr && er->ecmcacheptr->cacheex_pushed))
		return;

	int64_t grp;
	if (er->selected_reader)
		grp = er->selected_reader->grp;
	else
		grp = er->grp;

	//cacheex=2 mode: push (server->remote)
	struct s_client *cl;
	cs_readlock(&clientlist_lock);
	for (cl=first_client->next; cl; cl=cl->next) {
		if (er->cacheex_src != cl) {
			if (cl->typ == 'c' && !cl->dup && cl->account && cl->account->cacheex == 2) { //send cache over user
				if (ph[cl->ctyp].c_cache_push // cache-push able
						&& (!grp || (cl->grp & grp)) //Group-check
						&& chk_srvid(cl, er) //Service-check
						&& (chk_caid(er->caid, &cl->ctab) > 0))  //Caid-check
				{
					cacheex_cache_push_to_client(cl, er);
				}
			}
		}
	}
	cs_readunlock(&clientlist_lock);

	//cacheex=3 mode: reverse push (reader->server)

	cs_readlock(&readerlist_lock);
	cs_readlock(&clientlist_lock);

	struct s_reader *rdr;
	for (rdr = first_active_reader; rdr; rdr = rdr->next) {
		struct s_client *cl = rdr->client;
		if (cl && er->cacheex_src != cl && rdr->cacheex == 3) { //send cache over reader
			if (rdr->ph.c_cache_push
				&& (!grp || (rdr->grp & grp)) //Group-check
				&& chk_srvid(cl, er) //Service-check
				&& chk_ctab(er->caid, &rdr->ctab))  //Caid-check
			{
				cacheex_cache_push_to_client(cl, er);
			}
		}
	}

	cs_readunlock(&clientlist_lock);
	cs_readunlock(&readerlist_lock);

	er->cacheex_pushed = 1;
	if (er->ecmcacheptr) er->ecmcacheptr->cacheex_pushed = 1;
}

static struct s_cacheex_matcher *is_cacheex_matcher_matching(ECM_REQUEST *from_er, ECM_REQUEST *to_er)
{
	struct s_cacheex_matcher *entry = cfg.cacheex_matcher;
	int8_t v_ok = (from_er && to_er)?2:1;
	while (entry) {
		int8_t ok = 0;
		if (from_er
				&& (!entry->caid || entry->caid == from_er->caid)
				&& (!entry->provid || entry->provid == from_er->prid)
				&& (!entry->srvid || entry->srvid == from_er->srvid)
				&& (!entry->chid || entry->chid == from_er->chid)
				&& (!entry->pid || entry->pid == from_er->pid)
				&& (!entry->ecmlen || entry->ecmlen == from_er->l))
			ok++;

		if (to_er
				&& (!entry->to_caid || entry->to_caid == to_er->caid)
				&& (!entry->to_provid || entry->to_provid == to_er->prid)
				&& (!entry->to_srvid || entry->to_srvid == to_er->srvid)
				&& (!entry->to_chid || entry->to_chid == to_er->chid)
				&& (!entry->to_pid || entry->to_pid == to_er->pid)
				&& (!entry->to_ecmlen || entry->to_ecmlen == to_er->l))
			ok++;

		if (ok == v_ok) {
			if (!from_er || !to_er || from_er->srvid == to_er->srvid)
				return entry;
		}
		entry = entry->next;
	}
	return NULL;
}

int8_t cacheex_is_match_alias(struct s_client *cl, ECM_REQUEST *er) {
	return cl && cl->account && cl->account->cacheex == 1 && is_cacheex_matcher_matching(NULL, er);
}

int8_t cacheex_match_alias(struct s_client *cl, ECM_REQUEST *er, ECM_REQUEST *ecm)
{
	if (cl && cl->account && cl->account->cacheex == 1) {
		struct s_cacheex_matcher *entry = is_cacheex_matcher_matching(ecm, er);
		if (entry) {
			int32_t diff = comp_timeb(&er->tps, &ecm->tps);
			if (diff > entry->valid_from && diff < entry->valid_to) {
#ifdef WITH_DEBUG
				char result[CXM_FMT_LEN] = { 0 };
				int32_t s, size = CXM_FMT_LEN;
				s = ecmfmt(entry->caid, entry->provid, entry->chid, entry->pid, entry->srvid, entry->ecmlen, 0, result, size);
				s += snprintf(result+s, size-s, " = ");
				s += ecmfmt(entry->to_caid, entry->to_provid, entry->to_chid, entry->to_pid, entry->to_srvid, entry->to_ecmlen, 0, result+s, size-s);
				s += snprintf(result+s, size-s, " valid %d/%d", entry->valid_from, entry->valid_to);
				cs_debug_mask(D_CACHEEX, "cacheex-matching for: %s", result);
#endif
				return 1;
			}
		}
	}
	return 0;
}

static void add_invalid_cw(uint8_t *cw) {
	if (!invalid_cws)
		invalid_cws = ll_create("invalid cws");
	uint8_t *cw2 = cs_malloc(&cw2, 16, 0);
	memcpy(cw2, cw, 16);
	ll_append(invalid_cws, cw2);
	while (ll_count(invalid_cws) > 32) {
		ll_remove_first_data(invalid_cws);
	}
}

static int32_t is_invalid_cw(uint8_t *cw) {
	if (!invalid_cws) return 0;

	LL_LOCKITER *li = ll_li_create(invalid_cws, 0);
	uint8_t *cw2;
	int32_t invalid = 0;
	while ((cw2 = ll_li_next(li)) && !invalid) {
		invalid = (memcmp(cw, cw2, 16) == 0);
	}
	ll_li_destroy(li);
	return invalid;
}

static int32_t cacheex_add_to_cache_int(struct s_client *cl, ECM_REQUEST *er, int8_t csp)
{
	if (!cl)
		return 0;
	if (!csp && cl->reader && cl->reader->cacheex!=2) { //from reader
		cs_debug_mask(D_CACHEEX, "CACHEX received, but disabled for %s", username(cl));
		return 0;
	}
	if (!csp && !cl->reader && cl->account && cl->account->cacheex!=3) { //from user
		cs_debug_mask(D_CACHEEX, "CACHEX received, but disabled for %s", username(cl));
		return 0;
	}
	if (!csp && !cl->reader && !cl->account) { //not active!
		cs_debug_mask(D_CACHEEX, "CACHEX received, but invalid client state %s", username(cl));
		return 0;
	}

	if (er->rc < E_NOTFOUND) { //=FOUND Check CW:
		uint8_t i, c;
		uint8_t null=0;
		for (i = 0; i < 16; i += 4) {
			c = ((er->cw[i] + er->cw[i + 1] + er->cw[i + 2]) & 0xff);
			null |= (er->cw[i] | er->cw[i + 1] | er->cw[i + 2]);
			if (er->cw[i + 3] != c) {
				cs_ddump_mask(D_CACHEEX, er->cw, 16, "push received cw with chksum error from %s", csp ? "csp" : username(cl));
				cl->cwcacheexerr++;
				if (cl->account)
					cl->account->cwcacheexerr++;
				return 0;
			}
		}

		if (null==0) {
			cs_ddump_mask(D_CACHEEX, er->cw, 16, "push received null cw from %s", csp ? "csp" : username(cl));
			cl->cwcacheexerr++;
			if (cl->account)
				cl->account->cwcacheexerr++;
			return 0;
		}

		if (is_invalid_cw(er->cw)) {
			cs_ddump_mask(D_TRACE, er->cw, 16, "push received invalid cw from %s", csp ? "csp" : username(cl));
			cl->cwcacheexerrcw++;
			if (cl->account)
				cl->account->cwcacheexerrcw++;
			return 0;
		}
	}

	er->grp = cl->grp;
//	er->ocaid = er->caid;
	if (er->rc < E_NOTFOUND) //map FOUND to CACHEEX
		er->rc = E_CACHEEX;
	er->cacheex_src = cl;
	er->client = NULL; //No Owner! So no fallback!

	if (er->l) {
		uint16_t *lp;
		for (lp=(uint16_t *)er->ecm+(er->l>>2), er->checksum=0; lp>=(uint16_t *)er->ecm; lp--)
			er->checksum^=*lp;

		int32_t offset = 3;
		if ((er->caid >> 8) == 0x17)
			offset = 13;
		unsigned char md5tmp[MD5_DIGEST_LENGTH];
		memcpy(er->ecmd5, MD5(er->ecm+offset, er->l-offset, md5tmp), CS_ECMSTORESIZE);
		cacheex_update_hash(er);
		//csp has already initialized these hashcode

		update_chid(er);
	} else {
		er->checksum = er->csp_hash;
	}

	struct ecm_request_t *ecm = check_cwcache(er, cl);

//	{
//		char h1[20];
//		char h2[10];
//		cs_hexdump(0, er->ecmd5, sizeof(er->ecmd5), h1, sizeof(h1));
//		cs_hexdump(0, (const uchar*)&er->csp_hash, sizeof(er->csp_hash), h2, sizeof(h2));
//		debug_ecm(D_TRACE, "cache push check %s: %s %s %s rc=%d found cache: %s", username(cl), buf, h1, h2, er->rc, ecm==NULL?"no":"yes");
//	}

	if (!ecm) {
		if (er->rc < E_NOTFOUND) { // Do NOT add cacheex - not founds!
			cs_writelock(&ecmcache_lock);
			er->next = ecmcwcache;
			ecmcwcache = er;
			cs_writeunlock(&ecmcache_lock);

			er->selected_reader = cl->reader;

			cacheex_cache_push(er);  //cascade push!

			if (er->rc < E_NOTFOUND)
				cacheex_add_stats(cl, er->caid, er->srvid, er->prid, 1);

			cl->cwcacheexgot++;
			if (cl->account)
				cl->account->cwcacheexgot++;
			first_client->cwcacheexgot++;
		}

		debug_ecm(D_CACHEEX, "got pushed ECM %s from %s", buf, csp ? "csp" : username(cl));

		return er->rc < E_NOTFOUND ? 1 : 0;
	} else {
		if (er->rc < ecm->rc) {
			if (ecm->csp_lastnodes == NULL) {
				ecm->csp_lastnodes = er->csp_lastnodes;
				er->csp_lastnodes = NULL;
			}
			ecm->cacheex_src = cl;
			ecm->cacheex_pushed = 0;

			write_ecm_answer(cl->reader, ecm, er->rc, er->rcEx, er->cw, ecm->msglog);

			if (er->rc < E_NOTFOUND)
				ecm->selected_reader = cl->reader;

			cacheex_cache_push(ecm);  //cascade push!

			if (er->rc < E_NOTFOUND)
				cacheex_add_stats(cl, er->caid, er->srvid, er->prid, 1);

			cl->cwcacheexgot++;
			if (cl->account)
				cl->account->cwcacheexgot++;
			first_client->cwcacheexgot++;

			debug_ecm(D_CACHEEX, "replaced pushed ECM %s from %s", buf, csp ? "csp" : username(cl));
		} else {
			if (er->rc < E_NOTFOUND && memcmp(er->cw, ecm->cw, sizeof(er->cw)) != 0) {
				add_invalid_cw(ecm->cw);
				add_invalid_cw(er->cw);

				cl->cwcacheexerrcw++;
				if (cl->account)
					cl->account->cwcacheexerrcw++;

				char cw1[16*3+2], cw2[16*3+2];
				cs_hexdump(0, er->cw, 16, cw1, sizeof(cw1));
				cs_hexdump(0, ecm->cw, 16, cw2, sizeof(cw2));

				char ip1[20]="", ip2[20]="";
				if (cl)
					cs_strncpy(ip1, cs_inet_ntoa(cl->ip), sizeof(ip1));
				if (ecm->cacheex_src)
					cs_strncpy(ip2, cs_inet_ntoa(ecm->cacheex_src->ip), sizeof(ip2));
				else if (ecm->selected_reader)
					cs_strncpy(ip2, cs_inet_ntoa(ecm->selected_reader->client->ip), sizeof(ip2));

				void *el = ll_has_elements(er->csp_lastnodes);
				uint64_t node1 = el?(*(uint64_t*)el):0;

				el = ll_has_elements(ecm->csp_lastnodes);
				uint64_t node2 = el?(*(uint64_t*)el):0;

				el = ll_last_element(er->csp_lastnodes);
				uint64_t node3 = el?(*(uint64_t*)el):0;

				el = ll_last_element(ecm->csp_lastnodes);
				uint64_t node4 = el?(*(uint64_t*)el):0;

				debug_ecm(D_TRACE, "WARNING: Different CWs %s from %s(%s)<>%s(%s): %s<>%s nodes %llX %llX %llX %llX", buf,
					csp ? "csp" : username(cl), ip1,
					ecm->cacheex_src?username(ecm->cacheex_src):(ecm->selected_reader?ecm->selected_reader->label:"unknown/csp"), ip2,
					cw1, cw2,
					(long long unsigned int)node1,
					(long long unsigned int)node2,
					(long long unsigned int)node3,
					(long long unsigned int)node4);

				//char ecmd51[17*3];
				//cs_hexdump(0, er->ecmd5, 16, ecmd51, sizeof(ecmd51));
				//char csphash1[5*3];
				//cs_hexdump(0, (void*)&er->csp_hash, 4, csphash1, sizeof(csphash1));
				//char ecmd52[17*3];
				//cs_hexdump(0, ecm->ecmd5, 16, ecmd52, sizeof(ecmd52));
				//char csphash2[5*3];
				//cs_hexdump(0, (void*)&ecm->csp_hash, 4, csphash2, sizeof(csphash2));
				//debug_ecm(D_TRACE, "WARNING: Different CWs %s from %s<>%s: %s<>%s %s<>%s %s<>%s", buf,
				//    csp ? "csp" : username(cl),
				//    ecm->cacheex_src?username(ecm->cacheex_src):"unknown/csp",
				//    cw1, cw2,
				//    ecmd51, ecmd52,
				//    csphash1, csphash2
				//    );
			} else {
				debug_ecm(D_CACHEEX, "ignored duplicate pushed ECM %s from %s", buf, csp ? "csp" : username(cl));
			}
		}
		return 0;
	}
}

void cacheex_add_to_cache(struct s_client *cl, ECM_REQUEST *er)
{
	if (!cacheex_add_to_cache_int(cl, er, 0))
		free_ecm(er);
}

void cacheex_add_to_cache_from_csp(struct s_client *cl, ECM_REQUEST *er)
{
	if (!cacheex_add_to_cache_int(cl, er, 1))
		free_ecm(er);
}

//Format:
//caid:prov:srvid:pid:chid:ecmlen=caid:prov:srvid:pid:chid:ecmlen[,validfrom,validto]
//validfrom: default=-2000
//validto: default=4000
//valid time if found in cache
static struct s_cacheex_matcher *cacheex_matcher_read_int(void) {
	FILE *fp = open_config_file(cs_cacheex_matcher);
	if (!fp)
		return NULL;

	char token[1024];
	unsigned char type;
	int32_t i, ret, count=0;
	struct s_cacheex_matcher *new_cacheex_matcher = NULL, *entry, *last=NULL;
	uint32_t line = 0;

	while (fgets(token, sizeof(token), fp)) {
		line++;
		if (strlen(token) <= 1) continue;
		if (token[0]=='#' || token[0]=='/') continue;
		if (strlen(token)>100) continue;

		for (i=0;i<(int)strlen(token);i++) {
			if ((token[i]==':' || token[i]==' ') && token[i+1]==':') {
				memmove(token+i+2, token+i+1, strlen(token)-i+1);
				token[i+1]='0';
			}
			if (token[i]=='#' || token[i]=='/') {
				token[i]='\0';
				break;
			}
		}

		type = 'm';
		uint32_t caid=0, provid=0, srvid=0, pid=0, chid=0, ecmlen=0;
		uint32_t to_caid=0, to_provid=0, to_srvid=0, to_pid=0, to_chid=0, to_ecmlen=0;
		int32_t valid_from=-2000, valid_to=4000;

		ret = sscanf(token, "%c:%4x:%6x:%4x:%4x:%4x:%4X=%4x:%6x:%4x:%4x:%4x:%4X,%4d,%4d",
				&type,
				&caid, &provid, &srvid, &pid, &chid, &ecmlen,
				&to_caid, &to_provid, &to_srvid, &to_pid, &to_chid, &to_ecmlen,
				&valid_from, &valid_to);

		type = tolower(type);

		if (ret<7 || type != 'm')
			continue;

		if(!cs_malloc(&entry,sizeof(struct s_cacheex_matcher), -1)){
			fclose(fp);
			return new_cacheex_matcher;
		}
		count++;
		entry->line=line;
		entry->type=type;
		entry->caid=caid;
		entry->provid=provid;
		entry->srvid=srvid;
		entry->pid=pid;
		entry->chid=chid;
		entry->ecmlen=ecmlen;
		entry->to_caid=to_caid;
		entry->to_provid=to_provid;
		entry->to_srvid=to_srvid;
		entry->to_pid=to_pid;
		entry->to_chid=to_chid;
		entry->to_ecmlen=to_ecmlen;
		entry->valid_from=valid_from;
		entry->valid_to=valid_to;

		cs_debug_mask(D_TRACE, "cacheex-matcher: %c: %04X:%06X:%04X:%04X:%04X:%02X = %04X:%06X:%04X:%04X:%04X:%02X valid %d/%d",
				entry->type, entry->caid, entry->provid, entry->srvid, entry->pid, entry->chid, entry->ecmlen,
				entry->to_caid, entry->to_provid, entry->to_srvid, entry->to_pid, entry->to_chid, entry->to_ecmlen,
				entry->valid_from, entry->valid_to);

		if (!new_cacheex_matcher) {
			new_cacheex_matcher=entry;
			last = new_cacheex_matcher;
		} else {
			last->next = entry;
			last = entry;
		}
	}

	cs_log("%d entries read from %s", count, cs_cacheex_matcher);

	fclose(fp);

	return new_cacheex_matcher;
}

void cacheex_load_config_file(void) {
	struct s_cacheex_matcher *entry, *old_list = cfg.cacheex_matcher;

	old_list = cfg.cacheex_matcher;
	cfg.cacheex_matcher = cacheex_matcher_read_int();

	while (old_list) {
		entry = old_list->next;
		free(old_list);
		old_list = entry;
	}
}

static int32_t cacheex_ecm_hash_calc(uchar *buf, int32_t n) {
	int32_t i, h = 0;
	for (i = 0; i < n; i++) {
		h = 31 * h + buf[i];
	}
	return h;
}

void cacheex_update_hash(ECM_REQUEST *er) {
	er->csp_hash = cacheex_ecm_hash_calc(er->ecm+3, er->l-3);
}

#endif
