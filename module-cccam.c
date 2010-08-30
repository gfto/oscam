
#include <string.h>
#include <stdlib.h>
#include "globals.h"
#include "module-cccam.h"
#include "module-obj-llist.h"
#include <time.h>
#include "reader-common.h"
#include <poll.h>

extern struct s_reader *reader;

int g_flag = 0;
int cc_use_rc4 = 0;

//Mode names for CMD_05 command:
char *cmd05_mode_name[] = { "UNKNOWN", "PLAIN", "AES", "CC_CRYPT", "RC4", "LEN=0" };

static unsigned int seed;
static uchar fast_rnd() {
	unsigned int offset = 12923;
	unsigned int multiplier = 4079;

	seed = seed * multiplier + offset;
	return (uchar)(seed % 0xFF);
}

static int cc_cli_init();
static int cc_get_nxt_ecm();
static int cc_send_pending_emms();
static void cc_rc4_crypt(struct cc_crypt_block *block, uint8 *data, int len,
		cc_crypt_mode_t mode);

char * prefix = NULL;

static char *getprefix() {
	if (prefix)
		return prefix;

	prefix = malloc(100);
	if (is_server)
		sprintf(prefix, "cccam(s) %s: ", client[cs_idx].usr);
	else
		sprintf(prefix, "cccam(r) %s: ", reader[ridx].label);
	while (strlen(prefix) < 22)
		strcat(prefix, " ");
	return prefix;
}

static int comp_timeb(struct timeb *tpa, struct timeb *tpb)
{
  if (tpa->time>tpb->time) return(1);
  if (tpa->time<tpb->time) return(-1);
  if (tpa->millitm>tpb->millitm) return(1);
  if (tpa->millitm<tpb->millitm) return(-1);
  return(0);
}
          
static void cc_init_crypt(struct cc_crypt_block *block, uint8 *key, int len) {
	int i = 0;
	uint8 j = 0;

	for (i = 0; i < 256; i++) {
		block->keytable[i] = i;
	}

	for (i = 0; i < 256; i++) {
		j += key[i % len] + block->keytable[i];
		SWAPC(&block->keytable[i], &block->keytable[j]);
	}

	block->state = *key;
	block->counter = 0;
	block->sum = 0;
}

static void cc_crypt(struct cc_crypt_block *block, uint8 *data, int len,
		cc_crypt_mode_t mode) {
	int i;
	uint8 z;

	for (i = 0; i < len; i++) {
		block->counter++;
		block->sum += block->keytable[block->counter];
		SWAPC(&block->keytable[block->counter], &block->keytable[block->sum]);
		z = data[i];
		data[i] = z ^ block->keytable[(block->keytable[block->counter]
				+ block->keytable[block->sum]) & 0xff];
		if (!cc_use_rc4)
			data[i] ^= block->state;
		if (!mode)
			z = data[i];
		block->state = block->state ^ z;
	}
}

static void cc_rc4_crypt(struct cc_crypt_block *block, uint8 *data, int len,
		cc_crypt_mode_t mode) {
	int i;
	uint8 z;

	for (i = 0; i < len; i++) {
		block->counter++;
		block->sum += block->keytable[block->counter];
		SWAPC(&block->keytable[block->counter], &block->keytable[block->sum]);
		z = data[i];
		data[i] = z ^ block->keytable[(block->keytable[block->counter]
				+ block->keytable[block->sum]) & 0xff];
		if (!mode)
			z = data[i];
		block->state = block->state ^ z;
	}
}


static void cc_xor(uint8 *buf) {
	const char cccam[] = "CCcam";
	uint8 i;

	for (i = 0; i < 8; i++) {
		buf[8 + i] = i * buf[i];
		if (i <= 5) {
			buf[i] ^= cccam[i];
		}
	}
}

static void cc_cw_crypt(uint8 *cws, uint32 cardid) {
	struct cc_data *cc;
	uint64 node_id;
	uint8 tmp;
	int i;

	if (!is_server) {
		cc = reader[ridx].cc;
		node_id = b2ll(8, cc->node_id);
	} else {
		cc = client[cs_idx].cc;
		node_id = b2ll(8, cc->peer_node_id);
	}

	for (i = 0; i < 16; i++) {
		tmp = cws[i] ^ (node_id >> (4 * i));
		if (i & 1)
			tmp = ~tmp;
		cws[i] = (cardid >> (2 * i)) ^ tmp;
	}
}

/**
 * reader
 * cleans autoblock list
 * list is not disposed
 */
static void cc_clear_auto_blocked(LLIST *cc_auto_blocked_list) {
	LLIST_ITR itr;
	struct cc_auto_blocked *auto_blocked = llist_itr_init(cc_auto_blocked_list,
			&itr);
	while (auto_blocked) {
		free(auto_blocked);
		auto_blocked = llist_itr_remove(&itr);
	}
}

static void cc_free_auto_blocked(LLIST *cc_auto_blocked_list) {
	if (cc_auto_blocked_list) {
		cc_clear_auto_blocked(cc_auto_blocked_list);
		llist_destroy(cc_auto_blocked_list);
	}
}
/**
 * reader
 * removed all caid:prov:xxx from the auto blocked list.
 * This function is called, when a new card arrives
 */
static int cc_remove_from_auto_blocked(LLIST *cc_auto_blocked_list,
		uint16 caid, uint32 prov) {
	int found = 0;
	LLIST_ITR itr;
	struct cc_auto_blocked *auto_blocked = llist_itr_init(cc_auto_blocked_list,
			&itr);
	while (auto_blocked) {
		if (auto_blocked->caid == caid && auto_blocked->prov == prov) {
			free(auto_blocked);
			auto_blocked = llist_itr_remove(&itr);
			found++;
		} else
			auto_blocked = llist_itr_next(&itr);
	}
	return found;
}

static int sid_eq(struct cc_srvid *srvid1, struct cc_srvid *srvid2) {
	return (srvid1->sid == srvid2->sid && srvid1->ecmlen == srvid2->ecmlen);
}


/**
 * reader
 * add caid:prov:sid to the autoblock list
 */
static int cc_add_auto_blocked(LLIST *cc_auto_blocked_list, uint16 caid,
		uint32 prov, struct cc_srvid *srvid) {
	LLIST_ITR itr;
	struct cc_auto_blocked *auto_blocked = llist_itr_init(cc_auto_blocked_list,
			&itr);
	while (auto_blocked) {
		if (auto_blocked->caid == caid && auto_blocked->prov == prov
				&& sid_eq(&auto_blocked->srvid, srvid)) {
			auto_blocked->time = time((time_t*) 0);
			return 0; //Already blocked
		}
		auto_blocked = llist_itr_next(&itr);
	}
	//Add auto-block:
	auto_blocked = malloc(sizeof(struct cc_auto_blocked));
	auto_blocked->caid = caid;
	auto_blocked->prov = prov;
	auto_blocked->srvid = *srvid;
	auto_blocked->time = time((time_t*) 0);
	llist_append(cc_auto_blocked_list, auto_blocked);
	cs_debug_mask(D_TRACE, "%s adding %04X:%04X:%04X(%d) to auto block list", getprefix(), caid,
			prov, srvid->sid, srvid->ecmlen);
	return 1;
}

/**
 * reader
 * checks if caid:prov:sid is on the autoblock list
 */
static int cc_is_auto_blocked(LLIST *cc_auto_blocked_list, uint16 caid,
		uint32 prov, struct cc_srvid *srvid, int timeout) {
	LLIST_ITR itr;
	struct cc_auto_blocked *auto_blocked = llist_itr_init(cc_auto_blocked_list,
			&itr);
	while (auto_blocked) {
		if (auto_blocked->caid == caid && auto_blocked->prov == prov
				&& sid_eq(&auto_blocked->srvid, srvid)) {
			if (auto_blocked->time < time((time_t*) 0) - timeout) {
				free(auto_blocked);
				llist_itr_remove(&itr);
			} else {
				auto_blocked->time = time((time_t*) 0);
				return 1; //Already blocked
			}
		}
		auto_blocked = llist_itr_next(&itr);
	}
	return 0;
}

static int is_sid_blocked(struct cc_card *card, struct cc_srvid *srvid_blocked) {
	LLIST_ITR sitr;
	struct cc_srvid *srvid = llist_itr_init(card->badsids, &sitr);
	while (srvid) {
		if (sid_eq(srvid, srvid_blocked)) {
			return 1;
		}
		srvid = llist_itr_next(&sitr);
	}
	return 0;
}

static int is_good_sid(struct cc_card *card, struct cc_srvid *srvid_good) {
	LLIST_ITR sitr;
	struct cc_srvid *srvid = llist_itr_init(card->goodsids, &sitr);
	while (srvid) {
		if (sid_eq(srvid, srvid_good)) {
			return 1;
		}
		srvid = llist_itr_next(&sitr);
	}
	return 0;
}

static void add_sid_block(struct cc_card *card, struct cc_srvid *srvid_blocked) {
	if (is_sid_blocked(card, srvid_blocked))
		return;
		
	struct cc_srvid *srvid = malloc(sizeof(struct cc_srvid));
	if (srvid) {
		*srvid = *srvid_blocked;
		llist_append(card->badsids, srvid);
		cs_debug_mask(D_TRACE, "%s added sid block %04X(%d) for card %08x",
			getprefix(), srvid_blocked->sid, srvid_blocked->ecmlen, card->id);
	}
}

static void remove_sid_block(struct cc_card *card, struct cc_srvid *srvid_blocked) {
	LLIST_ITR sitr;
	struct cc_srvid *srvid = llist_itr_init(card->badsids, &sitr);
	while (srvid) {
		if (sid_eq(srvid, srvid_blocked)) {
			free(srvid);
			srvid = llist_itr_remove(&sitr);
		}
		else
			srvid = llist_itr_next(&sitr);
	}
}

static void remove_good_sid(struct cc_card *card, struct cc_srvid *srvid_good) {
	LLIST_ITR sitr;
	struct cc_srvid *srvid = llist_itr_init(card->goodsids, &sitr);
	while (srvid) {
		if (sid_eq(srvid, srvid_good)) {
			free(srvid);
			srvid = llist_itr_remove(&sitr);
		}
		else
			srvid = llist_itr_next(&sitr);
	}
}

static void add_good_sid(struct cc_card *card, struct cc_srvid *srvid_good) {
	if (is_good_sid(card, srvid_good))
		return;

	remove_sid_block(card, srvid_good);		
	struct cc_srvid *srvid = malloc(sizeof(struct cc_srvid));
	if (srvid) {
		*srvid = *srvid_good;
		llist_append(card->goodsids, srvid);
		cs_debug_mask(D_TRACE, "%s added good sid %04X(%d) for card %08x",
			getprefix(), srvid_good->sid, srvid_good->ecmlen, card->id);
	}
}


/**
 * reader
 * clears and frees values for reinit
 */
static void cc_cli_close() {
	reader[ridx].tcp_connected = 0;
	reader[ridx].card_status = CARD_FAILURE;
	reader[ridx].available = 0;
	reader[ridx].card_system = 0;

	//cs_sleepms(100);
	if (pfd) {
		close(pfd); 
		pfd = 0;
		client[cs_idx].udp_fd = 0;
	}
	else if (client[cs_idx].udp_fd) {
		close(client[cs_idx].udp_fd);
		client[cs_idx].udp_fd = 0;
		pfd = 0;
	}
	//cs_sleepms(100);
	struct cc_data *cc = reader[ridx].cc;
	if (cc) {
		pthread_mutex_unlock(&cc->lock);
		pthread_mutex_unlock(&cc->ecm_busy);
		pthread_mutex_destroy(&cc->lock);
		pthread_mutex_destroy(&cc->ecm_busy);
		cc_clear_auto_blocked(cc->auto_blocked);
		cc->just_logged_in = 0;
	}
}

/**
 * reader
 * closes the connection and reopens it.
 */
static void cc_cycle_connection() {
	cc_cli_close();
	cc_cli_init();
}

/**
 * reader+server:
 * receive a message
 */
static int cc_msg_recv(uint8 *buf) {
	int len;
	uint8 netbuf[CC_MAXMSGSIZE + 4];
	struct cc_data *cc;

	if (!is_server)
		cc = reader[ridx].cc;
	else
		cc = client[cs_idx].cc;

	int handle = client[cs_idx].udp_fd;

	if (handle < 0)
		return -1;

	len = recv(handle, netbuf, 4, MSG_WAITALL);
	if (!is_server)
		reader[ridx].last_g = time(NULL);
	
	if (!len)
		return 0;

	if (len != 4) { // invalid header length read
		cs_log("%s invalid header length (expected 4, read %d)", getprefix(), len);
		return -1;
	}

	cc_crypt(&cc->block[DECRYPT], netbuf, 4, DECRYPT);
	cs_ddump(netbuf, 4, "cccam: decrypted header:");

	g_flag = netbuf[0];

	int size = (netbuf[2] << 8) | netbuf[3];
	if (size) { // check if any data is expected in msg
		if (size > CC_MAXMSGSIZE - 2) {
			cs_log("%s message too big (size=%d)", getprefix(), size);
			return 0;
		}

		len = recv(handle, netbuf + 4, size, MSG_WAITALL); // read rest of msg
		if (!is_server)
			reader[ridx].last_g = time(NULL);

		if (len != size) {
			cs_log("%s invalid message length read (expected %d, read %d)", getprefix(), size, len);
			return -1;
		}

		cc_crypt(&cc->block[DECRYPT], netbuf + 4, len, DECRYPT);
		len += 4;
	}

	cs_ddump(netbuf, len, "cccam: full decrypted msg, len=%d:", len);

	memcpy(buf, netbuf, len);
	return len;
}

/**
 * reader+server
 * send a message
 */
static int cc_cmd_send(uint8 *buf, int len, cc_msg_type_t cmd) {
	int n;
	uint8 netbuf[len + 4];
	struct cc_data *cc;

	if (!is_server)
		cc = reader[ridx].cc;
	else
		cc = client[cs_idx].cc;

	memset(netbuf, 0, len + 4);

	if (cmd == MSG_NO_HEADER) {
		memcpy(netbuf, buf, len);
	} else {
		// build command message
		netbuf[0] = g_flag; // flags??
		netbuf[1] = cmd & 0xff;
		netbuf[2] = len >> 8;
		netbuf[3] = len & 0xff;
		if (buf)
			memcpy(netbuf + 4, buf, len);
		len += 4;
	}

	cs_ddump(netbuf, len, "cccam: send:");
	cc_crypt(&cc->block[ENCRYPT], netbuf, len, ENCRYPT);

	n = send(client[cs_idx].udp_fd, netbuf, len, 0);
	if (!is_server)
		reader[ridx].last_s = time(NULL);

	if (n < 0 && is_server) {
		cs_disconnect_client();
	}		

	return n;
}

#define CC_DEFAULT_VERSION 1
char *version[] = { "2.0.11", "2.1.1", "2.1.2", "2.1.3", "2.1.4", "" };
char *build[] = { "2892", "2971", "3094", "3165", "3191", "" };

/**
 * reader+server
 * checks the cccam-version in the configuration
 */
static void cc_check_version(char *cc_version, char *cc_build) {
	int i;
	for (i = 0; strlen(version[i]); i++) {
		if (!memcmp(cc_version, version[i], strlen(version[i]))) {
			memcpy(cc_build, build[i], strlen(build[i]));
			cs_debug("cccam: auto build set for version: %s build: %s",
					cc_version, cc_build);
			return;
		}
	}
	memcpy(cc_version, version[CC_DEFAULT_VERSION], strlen(
			version[CC_DEFAULT_VERSION]));
	memcpy(cc_build, build[CC_DEFAULT_VERSION], strlen(
			build[CC_DEFAULT_VERSION]));

	cs_debug("cccam: auto version set: %s build: %s", cc_version, cc_build);
}

/**
 * reader
 * sends own version information to the CCCam server
 */
static int cc_send_cli_data() {
	int i;
	struct cc_data *cc = reader[ridx].cc;

	cs_debug("cccam: send client data");

	seed = (unsigned int) time((time_t*) 0);
	for (i = 0; i < 8; i++)
		cc->node_id[i] = fast_rnd();

	uint8 buf[CC_MAXMSGSIZE];
	memset(buf, 0, CC_MAXMSGSIZE);

	memcpy(buf, reader[ridx].r_usr, sizeof(reader[ridx].r_usr));
	memcpy(buf + 20, cc->node_id, 8);
	buf[28] =  reader[ridx].cc_want_emu; // <-- Client want to have EMUs, 0 - NO; 1 - YES
	memcpy(buf + 29, reader[ridx].cc_version, sizeof(reader[ridx].cc_version)); // cccam version (ascii)
	memcpy(buf + 61, reader[ridx].cc_build, sizeof(reader[ridx].cc_build)); // build number (ascii)

	cs_log("%s sending own version: %s, build: %s", getprefix(),
			reader[ridx].cc_version, reader[ridx].cc_build);

	i = cc_cmd_send(buf, 20 + 8 + 6 + 26 + 4 + 28 + 1, MSG_CLI_DATA);

	return i;
}

/**
 * server
 * sends version information to the client
 */
static int cc_send_srv_data() {
	int i;
	struct cc_data *cc = client[cs_idx].cc;

	cs_debug("cccam: send server data");

	seed = (unsigned int) time((time_t*) 0);
	for (i = 0; i < 8; i++)
		cc->node_id[i] = fast_rnd();

	uint8 buf[CC_MAXMSGSIZE];
	memset(buf, 0, CC_MAXMSGSIZE);

	memcpy(buf, cc->node_id, 8);
	cc_check_version((char *) cfg->cc_version, reader[ridx].cc_build);
	memcpy(buf + 8, cfg->cc_version, sizeof(reader[ridx].cc_version)); // cccam version (ascii)
	memcpy(buf + 40, reader[ridx].cc_build, sizeof(reader[ridx].cc_build)); // build number (ascii)

	cs_log("%s version: %s, build: %s nodeid: %s", getprefix(),
			cfg->cc_version, reader[ridx].cc_build, cs_hexdump(0, cc->peer_node_id, 8));

	return cc_cmd_send(buf, 0x48, MSG_SRV_DATA);
}

/**
 * reader
 * retrieves the next waiting ecm request
 */
static int cc_get_nxt_ecm() {
	int n, i;
	time_t t;
	// struct cc_data *cc = reader[ridx].cc;

	t = time(NULL);
	n = -1;
	for (i = 0; i < CS_MAXPENDING; i++) {
		if ((t - (ulong) ecmtask[i].tps.time > ((cfg->ctimeout + 500) / 1000)
				+ 1) && (ecmtask[i].rc >= 10)) // drop timeouts
		{
			ecmtask[i].rc = 0;
		}

		if (ecmtask[i].rc >= 10 && ecmtask[i].rc != 99) { // stil active and waiting
			// search for the ecm with the lowest time, this should be the next to go
			if ((n < 0 || ecmtask[n].tps.time - ecmtask[i].tps.time < 0)
					&& &ecmtask[n])
				n = i;
		}
	}
	return n;
}

/**
 * sends the secret cmd05 answer to the server 
 */
static int send_cmd05_answer()
{
	struct cc_data *cc = reader[ridx].cc;
	if (!cc->cmd05_active || !reader[ridx].available) //exit if not in cmd05 or waiting for ECM answer
		return 0;
		
	cc->cmd05_active--;
	if (cc->cmd05_active)
		return 0;
		
	uint8 *data = cc->cmd05_data;
	cc_cmd05_mode cmd05_mode = MODE_UNKNOWN;
	
	// by Project:Keynation
	switch (cc->cmd05_data_len) {
		case 0: { //payload 0, return with payload 0!
			cc_cmd_send(NULL, 0, MSG_CMD_05);
			cmd05_mode = MODE_LEN0;
			break;
		}
		case 256: {
			cmd05_mode = cc->cmd05_mode;
			switch (cmd05_mode) {
			case MODE_PLAIN: { //Send plain unencrypted back
				cc_cmd_send(data, 256, MSG_CMD_05);
				break;
			}
			case MODE_AES: { //encrypt with received aes128 key:
				AES_KEY key;
				uint8 aeskey[16];
				uint8 out[256];

				memcpy(aeskey, cc->cmd05_aeskey, 16);
				memset(&key, 0, sizeof(key));

				AES_set_encrypt_key((unsigned char *) &aeskey, 128, &key);
				int i;
				for (i = 0; i < 256; i+=16)
					AES_encrypt((unsigned char *) data+i, (unsigned char *) &out+i, &key);

				cc_cmd_send(out, 256, MSG_CMD_05);
				break;
			}
			case MODE_CC_CRYPT: { //encrypt with cc_crypt:
				cc_crypt(&cc->cmd05_cryptkey, data, 256, ENCRYPT);
				cc_cmd_send(data, 256, MSG_CMD_05);
				break;
			}
			case MODE_RC4_CRYPT: {//special xor crypt:
				cc_rc4_crypt(&cc->cmd05_cryptkey, data, 256, DECRYPT);
				cc_cmd_send(data, 256, MSG_CMD_05);
				break;
			}
			default:
				cmd05_mode = MODE_UNKNOWN;
			}
			break;
		}
		default:
			cmd05_mode = MODE_UNKNOWN;
	}

	//unhandled types always needs cycle connection after 50 ECMs!!
	if (cmd05_mode == MODE_UNKNOWN) {
		cc_cmd_send(NULL, 0, MSG_CMD_05);
		if (!cc->max_ecms) { //max_ecms already set?
			cc->max_ecms = 50;
			cc->ecm_counter = 0;
		}
	}
	cs_debug_mask(D_TRACE, "%s sending CMD_05 back! MODE: %s len=%d", getprefix(), cmd05_mode_name[cmd05_mode], cc->cmd05_data_len);
	
	return 1;
}


/**
 * reader
 * sends a ecm request to the connected CCCam Server
 */
static int cc_send_ecm(ECM_REQUEST *er, uchar *buf) {
	int n, h = -1;
	struct cc_data *cc = reader[ridx].cc;
	struct cc_card *card;
	struct cc_current_card *current_card;
	LLIST_ITR itr;
	ECM_REQUEST *cur_er;
	struct timeb cur_time;
	cs_ftime(&cur_time);

	if (!cc || (pfd < 1) || !reader[ridx].tcp_connected) {
		if (er) {
			er->rc = 0;
			er->rcEx = 0x27;
			cs_debug_mask(D_TRACE, "%s server not init! ccinit=%d pfd=%d", getprefix(), cc ? 1
					: 0, pfd);
			write_ecm_answer(&reader[ridx], fd_c2m, er);
		}
		return -1;
	}

	if (!llist_count(cc->cards))
		return 0;
		
	cc->just_logged_in = 0;

	if (pthread_mutex_trylock(&cc->ecm_busy) == EBUSY) { //Unlock by NOK or ECM ACK
		cs_debug_mask(D_TRACE, "%s ecm trylock: ecm busy, retrying later after msg-receive",
			getprefix());
		
		struct timeb timeout;	
		timeout = cc->ecm_time;
		timeout.millitm += cfg->ctimeout*4;
		timeout.time += timeout.millitm / 1000;
		timeout.millitm = timeout.millitm % 1000;
			
		if (comp_timeb(&cur_time, &timeout) < 0) { //TODO: Configuration?
			return 0; //pending send...
		}
		else
		{
			cs_debug_mask(D_TRACE, "%s unlocked-cycleconnection! timeout %ds", getprefix(),
				cfg->ctimeout*4/1000);
			cc_cycle_connection();
		}
	}
	cs_debug("cccam: ecm trylock: got lock");
	cc->ecm_time = cur_time;
	reader[ridx].available = 0;

	//Search next ECM to send:
	int found = 0;
	while (!found) {
		if ((n = cc_get_nxt_ecm()) < 0) {
			reader[ridx].available = 1;
			pthread_mutex_unlock(&cc->ecm_busy);
			cs_debug("%s no ecm pending!", getprefix());
			if (!cc_send_pending_emms())
				send_cmd05_answer();
			return 0; // no queued ecms
		}
		//cs_debug("cccam: ecm-task-idx = %d", n);
		cur_er = &ecmtask[n];
		
		if (crc32(0, cur_er->ecm, cur_er->l) == cc->crc) {
			//cs_log("%s cur_er->rc=%d", getprefix(), cur_er->rc);
			cur_er->rc = 99; //ECM already send
		}
		cc->crc = crc32(0, cur_er->ecm, cur_er->l);
		
		//cs_debug("cccam: ecm crc = 0x%lx", cc->crc);
		
		if (cur_er->rc != 99)
			found = 1;
	}

	if (buf)
		memcpy(buf, cur_er->ecm, cur_er->l);
		
	struct cc_srvid cur_srvid;
	cur_srvid.sid = cur_er->srvid;
	cur_srvid.ecmlen = cur_er->l;

	//First check last used card:
	cc->current_ecm_cidx = cur_er->cidx;
	current_card = &cc->current_card[cur_er->cidx];
	if (current_card->card && current_card->prov == cur_er->prid && 
	  sid_eq(&current_card->srvid, &cur_srvid)) {
		card = current_card->card;
	}
	else
	{
		card = NULL;
		current_card->prov = cur_er->prid;
		current_card->srvid = cur_srvid;
	}

	//then check all other cards
	int is_auto_blocked = 0;
	if (!card) {
		//check if auto blocked:
		if (!reader[ridx].cc_disable_auto_block && 
	  	    cc_is_auto_blocked(
		    cc->auto_blocked, cur_er->caid, cur_er->prid, &cur_srvid, 60*60*1)) { //TODO: Timeout 60*60*1 = 1h, Config?
		        is_auto_blocked = 1;
			current_card->card = NULL;
		}
		else
		{
			card = llist_itr_init(cc->cards, &itr);
			while (card) {
				if (card->caid == cur_er->caid) { // caid matches
					int s = is_sid_blocked(card, &cur_srvid);
						
					LLIST_ITR pitr;
					uint8 *prov = llist_itr_init(card->provs, &pitr);
					while (prov && !s) {
						ulong card_prov = b2i(3, prov);
						if (!cur_er->prid || !card_prov || card_prov == cur_er->prid) { // provid matches
							if (((h < 0) || (card->hop < h)) && (card->hop
									<= reader[ridx].cc_maxhop)) { // card is closer and doesn't exceed max hop
								//cc->cur_card = card;
								current_card->card = card;
								h = card->hop; // card has been matched
							}
						}
						prov = llist_itr_next(&pitr);
					}
				}
				card = llist_itr_next(&itr);
			}
		}
	}
	
	if (current_card->card) {
		card = current_card->card;
		current_card->prov = cur_er->prid;
		current_card->srvid = cur_srvid;

		card->time = time((time_t) 0);
		uint8 ecmbuf[CC_MAXMSGSIZE];
		memset(ecmbuf, 0, CC_MAXMSGSIZE);

		// build ecm message
		ecmbuf[0] = card->caid >> 8;
		ecmbuf[1] = card->caid & 0xff;
		ecmbuf[2] = cur_er->prid >> 24;
		ecmbuf[3] = cur_er->prid >> 16;
		ecmbuf[4] = cur_er->prid >> 8;
		ecmbuf[5] = cur_er->prid & 0xff;
		ecmbuf[6] = card->id >> 24;
		ecmbuf[7] = card->id >> 16;
		ecmbuf[8] = card->id >> 8;
		ecmbuf[9] = card->id & 0xff;
		ecmbuf[10] = cur_er->srvid >> 8;
		ecmbuf[11] = cur_er->srvid & 0xff;
		ecmbuf[12] = cur_er->l & 0xff;
		memcpy(ecmbuf + 13, cur_er->ecm, cur_er->l);

		cc->send_ecmtask = cur_er->idx;
		reader[ridx].cc_currenthops = card->hop + 1;

		cs_log("%s sending ecm for sid %04X(%d) to card %08x, hop %d, ecmtask %d",
				getprefix(), cur_er->srvid, cur_er->l, card->id, card->hop
						+ 1, cc->send_ecmtask);
		cc_cmd_send(ecmbuf, cur_er->l + 13, MSG_CW_ECM); // send ecm

		//For EMM
		if (!reader[ridx].audisabled) {
			reader[ridx].card_system = get_cardsystem(card->caid);
			memcpy(reader[ridx].hexserial, card->hexserial, sizeof(card->hexserial));
			cs_debug_mask(D_EMM, "%s au info: caid %04X card system: %d serial: %s", 
				getprefix(), card->caid, reader[ridx].card_system, cs_hexdump(0, card->hexserial, 8));
		}

		return 0;
	} else {
		if (is_auto_blocked)
			cs_log("%s no suitable card on server (auto blocked)", getprefix());
		else
			cs_log("%s no suitable card on server", getprefix());
		cur_er->rc = 0;
		cur_er->rcEx = 0x27;
		write_ecm_answer(&reader[ridx], fd_c2m, cur_er);
		//cur_er->rc = 1;
		//cur_er->rcEx = 0;
		//cs_sleepms(300);
		reader[ridx].last_s = reader[ridx].last_g;

		card = llist_itr_init(cc->cards, &itr);
		while (card) {
			if (card->caid == cur_er->caid) { // caid matches
				LLIST_ITR sitr;
				struct cc_srvid *srvid = llist_itr_init(card->badsids, &sitr);
				while (srvid) {
					if (sid_eq(srvid, &cur_srvid)) {
						free(srvid);
						srvid = llist_itr_remove(&sitr);
					}
					else
						srvid = llist_itr_next(&sitr);
				}
			}
			card = llist_itr_next(&itr);
		}

		if (!reader[ridx].cc_disable_auto_block) {
			cc_add_auto_blocked(cc->auto_blocked, cur_er->caid, cur_er->prid,
					&cur_srvid);
		}
		reader[ridx].available = 1;
		pthread_mutex_unlock(&cc->ecm_busy);
		
		return -1;
	}
}

/*
 static int cc_abort_user_ecms(){
 int n, i;
 time_t t;//, tls;
 struct cc_data *cc = reader[ridx].cc;

 t=time((time_t *)0);
 for (i=1,n=1; i<CS_MAXPENDING; i++)
 {
 if ((t-ecmtask[i].tps.time > ((cfg->ctimeout + 500) / 1000) + 1) &&
 (ecmtask[i].rc>=10))      // drop timeouts
 {
 ecmtask[i].rc=0;
 }
 int td=abs(1000*(ecmtask[i].tps.time-cc->found->tps.time)+ecmtask[i].tps.millitm-cc->found->tps.millitm);
 if (ecmtask[i].rc>=10 && ecmtask[i].cidx==cc->found->cidx && &ecmtask[i]!=cc->found){
 cs_log("aborting idx:%d caid:%04x client:%d timedelta:%d",ecmtask[i].idx,ecmtask[i].caid,ecmtask[i].cidx,td);
 ecmtask[i].rc=0;
 ecmtask[i].rcEx=7;
 write_ecm_answer(&reader[ridx], fd_c2m, &ecmtask[i]);
 }
 }
 return n;

 }
 */

static int cc_send_pending_emms() {
	struct cc_data *cc = reader[ridx].cc;

	LLIST_ITR itr;
	uint8 *emmbuf = llist_itr_init(cc->pending_emms, &itr);
	if (emmbuf) {
		if (pthread_mutex_trylock(&cc->ecm_busy) == EBUSY) { //Unlock by NOK or ECM ACK
			return 0; //send later with cc_send_ecm
		}
		int size = emmbuf[11]+12;
	
		reader[ridx].available = 0;
		cc->current_ecm_cidx = 0;
		cc->just_logged_in = 0;
		cs_ftime(&cc->ecm_time);
		
		cs_debug_mask(D_EMM, "%s emm send for card %08X", getprefix(), b2i(4, emmbuf+7));
		
		cc_cmd_send(emmbuf, size, MSG_EMM_ACK); // send emm
 		free(emmbuf);
 		llist_itr_remove(&itr);
 		return size;
	}
	return 0;
}

/**
 * READER only:
 * find card by hexserial
 * */
struct cc_card *get_card_by_hexserial(uint8 *hexserial, uint16 caid) {
	struct cc_data *cc = reader[ridx].cc;
	LLIST_ITR itr;
	struct cc_card *card = llist_itr_init(cc->cards, &itr);
	while (card) {
		if (memcmp(card->hexserial, hexserial, 8) == 0 && card->caid == caid) { //found it!
			return card;
		}
		card = llist_itr_next(&itr);
	}
	return NULL;
}

/**
 * EMM Procession
 * Copied from http://85.17.209.13:6100/file/8ec3c0c5d257/systems/cardclient/cccam2.c
 * ProcessEmm
 * */
static int cc_send_emm(EMM_PACKET *ep) {
	struct cc_data *cc = reader[ridx].cc;
	if (!cc || (pfd < 1) || !reader[ridx].tcp_connected) {
		cs_log("%s server not init! ccinit=%d pfd=%d", getprefix(), cc ? 1 : 0,
				pfd);
		return 0;
	}
	if (reader[ridx].audisabled) {
		cs_log("%s au is disabled", getprefix());
		return 0;
	}
	


	struct cc_card *emm_card = cc->current_card[ep->cidx].card;

	if (!emm_card || emm_card->caid != b2i(2, ep->caid)) {
		emm_card = get_card_by_hexserial(ep->hexserial, b2i(2, ep->caid));
	}

	if (!emm_card) { //Card for emm not found!
		cs_log("%s emm for client %d not possible, no card found!", getprefix(), ep->cidx);
		return 0;
	}

	cs_debug_mask(D_EMM, "%s emm received for client %d caid %04X for card %08X", getprefix(), ep->cidx,
			b2i(2, ep->caid), emm_card->id);

	int size = ep->l+12;
	uint8 *emmbuf = malloc(size);
	memset(emmbuf, 0, size);

	// build ecm message
	emmbuf[0] = ep->caid[0];
	emmbuf[1] = ep->caid[1];
	emmbuf[2] = 0;
	emmbuf[3] = ep->provid[0];
	emmbuf[4] = ep->provid[1];
	emmbuf[5] = ep->provid[2];
	emmbuf[6] = ep->provid[3];
	emmbuf[7] = emm_card->id >> 24;
	emmbuf[8] = emm_card->id >> 16;
	emmbuf[9] = emm_card->id >> 8;
	emmbuf[10] = emm_card->id & 0xff;
	emmbuf[11] = ep->l;
	memcpy(emmbuf + 12, ep->emm, ep->l);

	llist_append(cc->pending_emms, emmbuf);
	cc_send_pending_emms();
	return 1;
}

//SS: Hack
static void cc_free_card(struct cc_card *card) {
	if (!card)
		return;

	if (card->provs)
		llist_destroy(card->provs);
	if (card->badsids)
		llist_destroy(card->badsids);
	if (card->goodsids)
		llist_destroy(card->goodsids);
	free(card);
}

static void freeCaidInfos(LLIST *caid_infos) {
	if (caid_infos) {
		LLIST_ITR itr;
		struct cc_caid_info *caid_info = llist_itr_init(caid_infos, &itr);
		while (caid_info) {
			llist_destroy(caid_info->provs);
			free(caid_info);
			caid_info = llist_itr_remove(&itr);
		}
		llist_destroy(caid_infos);
	}
}

/**
 * Server:
 * Adds a cccam-carddata buffer to the list of reported carddatas
 */
static void cc_add_reported_carddata(LLIST *reported_carddatas, uint8 *buf,
		int len) {
	struct cc_reported_carddata *carddata = malloc(
			sizeof(struct cc_reported_carddata));
	uint8 *buf_copy = malloc(len);
	memcpy(buf_copy, buf, len);
	carddata->buf = buf_copy;
	carddata->len = len;
	llist_append(reported_carddatas, carddata);
}

static void cc_clear_reported_carddata(LLIST *reported_carddatas,
		int send_removed) {
	LLIST_ITR itr;
	struct cc_reported_carddata *carddata = llist_itr_init(reported_carddatas,
			&itr);
	while (carddata) {
		if (send_removed)
			cc_cmd_send(carddata->buf, carddata->len, MSG_CARD_REMOVED);
		free(carddata->buf);
		free(carddata);
		carddata = llist_itr_remove(&itr);
	}

}

static void cc_free_reported_carddata(LLIST *reported_carddatas,
		int send_removed) {
	if (reported_carddatas) {
		cc_clear_reported_carddata(reported_carddatas, send_removed);
		llist_destroy(reported_carddatas);
	}
}

/**
 * Clears and free the cc datas
 */
static void cc_free(struct cc_data *cc) {
	if (!cc)
		return;
	freeCaidInfos(cc->caid_infos);

	if (cc->cards) {
		LLIST_ITR itr;
		struct cc_card *card = llist_itr_init(cc->cards, &itr);
		while (card) {
			cc_free_card(card);
			card = llist_itr_remove(&itr);
		}
		llist_destroy(cc->cards);
		cc->cards = NULL;
	}
	cc_free_reported_carddata(cc->reported_carddatas, 0);
	cc_free_auto_blocked(cc->auto_blocked);
	if (cc->current_card)
		free(cc->current_card);
	if (cc->server_card)
		free(cc->server_card);
	if (cc->pending_emms) {
		LLIST_ITR itr;
		uint8 *ep = llist_itr_init(cc->pending_emms, &itr);
		while (ep) {
			free(ep);
			ep = llist_itr_remove(&itr);
		}
		llist_destroy(cc->pending_emms);
		cc->pending_emms = NULL;
	}
	free(cc);
}

static void fname_caidinfos(char *fname, int index) {
	sprintf(fname, "%s/caidinfos.%d", get_tmp_dir(), index);
}

static int checkCaidInfos(int index, long *lastSize) {
	char fname[40];
	fname_caidinfos(fname, index);
	struct stat st;
	stat(fname, &st);
	long current_size = st.st_size;
	int result = (current_size != *lastSize);
	cs_debug("checkCaidInfos %d: cur=%ld last=%ld", index, current_size,
			*lastSize);
	*lastSize = current_size;
	return result;
}

/**
 * Saves caidinfos to /tmp/caidinfos.<readerindex>
 */
static void saveCaidInfos(int index, LLIST *caid_infos) {
	char fname[40];
	fname_caidinfos(fname, index);
	FILE *file = fopen(fname, "w");
	LLIST_ITR itr;
	LLIST_ITR itr_prov;
	int caid_count = 0;
	int prov_count = 0;
	struct cc_caid_info *caid_info = llist_itr_init(caid_infos, &itr);
	while (caid_info) {
		fwrite(&caid_info->caid, 1, sizeof(uint16), file);
		fwrite(&caid_info->hop, 1, sizeof(uint8), file);

		caid_count++;
		uint8 count = 0;
		uint8 *prov = llist_itr_init(caid_info->provs, &itr_prov);
		while (prov) {
			count++;
			prov = llist_itr_next(&itr_prov);
		}
		fwrite(&count, 1, sizeof(uint8), file);
		prov = llist_itr_init(caid_info->provs, &itr_prov);
		while (prov) {
			fwrite(prov, 1, 3, file);
			prov = llist_itr_next(&itr_prov);
		}
		prov_count += count;

		caid_info = llist_itr_next(&itr);
	}
	fclose(file);
	cs_debug("saveCaidInfos %d: CAIDS: %d PROVIDERS: %d", index, caid_count,
			prov_count);
}

/**
 * Loads caidinfos from /tmp/caidinfos.<readerindex>
 */
static LLIST *loadCaidInfos(int index) {
	char fname[40];
	fname_caidinfos(fname, index);
	FILE *file = fopen(fname, "r");
	if (!file)
		return NULL;

	int caid_count = 0;
	int prov_count = 0;

	uint16 caid = 0;
	uint8 hop = 0;
	LLIST *caid_infos = llist_create();
	do {
		if (fread(&caid, 1, sizeof(uint16), file) <= 0)
			break;
		if (fread(&hop, 1, sizeof(uint8), file) <= 0)
			break;
		caid_count++;
		uint8 count = 0;
		if (fread(&count, 1, sizeof(uint8), file) <= 0)
			break;
		struct cc_caid_info *caid_info = malloc(sizeof(struct cc_caid_info));
		caid_info->caid = caid;
		caid_info->hop = hop;
		caid_info->provs = llist_create();
		uint8 *prov;
		while (count > 0) {
			prov = malloc(3);
			if (fread(prov, 1, 3, file) <= 0)
				break;
			llist_append(caid_info->provs, prov);
			count--;
			prov_count++;
		}
		llist_append(caid_infos, caid_info);
	} while (1);
	fclose(file);
	cs_debug("loadCaidInfos %d: CAIDS: %d PROVIDERS: %d", index, caid_count,
			prov_count);
	return caid_infos;
}

/**
 * Adds a new card to the caid_infos. Only caid/provs are used
 * Return 0 if caid already exists, 1 ist this is a new card or provider
 */
static int add_card_to_caidinfo(struct cc_data *cc, struct cc_card *card) {
	int doSaveCaidInfos = 0;
	LLIST_ITR itr;
	struct cc_caid_info *caid_info = llist_itr_init(cc->caid_infos, &itr);
	while (caid_info) {
		if (caid_info->caid == card->caid && caid_info->hop == card->hop)
			if (llist_count(caid_info->provs) < CS_MAXPROV)
				break;
		caid_info = llist_itr_next(&itr);
	}
	if (!caid_info) {
		caid_info = malloc(sizeof(struct cc_caid_info));
		caid_info->caid = card->caid;
		caid_info->provs = llist_create();
		caid_info->hop = card->hop;
		llist_append(cc->caid_infos, caid_info);
		doSaveCaidInfos = 1;
	}

	uint8 *prov_info;
	uint8 *prov_card;
	LLIST_ITR itr_info;
	LLIST_ITR itr_card;
	prov_card = llist_itr_init(card->provs, &itr_card);
	while (prov_card) {
		prov_info = llist_itr_init(caid_info->provs, &itr_info);
		while (prov_info) {
			if (b2i(3, prov_info) == b2i(3, prov_card))
				break;
			prov_info = llist_itr_next(&itr_info);
		}
		if (!prov_info) {
			uint8 *prov_new = malloc(3);
			memcpy(prov_new, prov_card, 3);
			llist_append(caid_info->provs, prov_new);
			doSaveCaidInfos = 1;
		}
		prov_card = llist_itr_next(&itr_card);
	}
	return doSaveCaidInfos;
}

//static void cc_clear_current_card(struct cc_data *cc, int cidx) {
//	memset(&cc->current_card[cidx], 0, sizeof(struct cc_current_card));
//}

//static int cc_remove_current_card(struct cc_data *cc, struct cc_card *card) {
//	int i, c = 0;
//	for (i = 0; i<CS_MAXPID; i++) {
//		if (cc->current_card[i].card == card) {
//			cc_clear_current_card(cc, i);
//			c++;
//		}
//	}
//	return c;
//}

static struct cc_current_card *cc_find_current_card(struct cc_data *cc, struct cc_card *card) {
	int i;
	for (i = 0; i<CS_MAXPID; i++) {
		if (cc->current_card[i].card == card) {
			return &cc->current_card[i];
		}
	}
	return NULL;
}

static void rebuild_caidinfos(struct cc_data *cc) {
	freeCaidInfos(cc->caid_infos);
	cc->caid_infos = llist_create();
	LLIST_ITR itr;
	struct cc_card *card = llist_itr_init(cc->cards, &itr);
	while (card) {
		add_card_to_caidinfo(cc, card);
		card = llist_itr_next(&itr);
	}
	cc->needs_rebuild_caidinfo = 0;
}

//static void cleanup_old_cards(struct cc_data *cc) {
//	time_t clean_time = time((time_t) 0) - 60 * 60 * 48; //TODO: Timeout old cards 60*60*48=48h Config
//	LLIST_ITR itr;
//	struct cc_card *card = llist_itr_init(cc->cards, &itr);
//	while (card) {
//		if (card->time < clean_time) {
//			//cs_log("cccam: old card removed %08x, count %d", card->id,
//			//		llist_count(cc->cards));
//			cc_remove_current_card(cc, card);
//			cc_free_card(card);
//			card = llist_itr_remove(&itr);
//		} else
//			card = llist_itr_next(&itr);
//	}
//}

static int caid_filtered(int ridx, int caid) {
	int defined = 0;
	int i;
	for (i = 0; i < CS_MAXREADERCAID; i++) {
		if (reader[ridx].caid[i]) {
			if (reader[ridx].caid[i] == caid)
				return 0;
			defined = 1;
		}
	}
	return defined;
}

static int is_null_dcw(uint8 *dcw)
{
	int i;
	for (i = 0; i < 15; i++)
		if (dcw[i])
			return 0;
	return 1;
}

/*static int is_dcw_corrupted(uchar *dcw)
{
    int i;
    int c, cs;

    for (i=0; i<16; i+=4)
    {
       c = (dcw[i] + dcw[i+1] + dcw[i+2]) & 0xFF;
       cs = dcw[i+3];
       if (cs!=c) return (1);
    }
    return 0;
}

static void fix_dcw(uchar *dcw)
{
    int i;
    for (i=0; i<16; i+=4)
    {
       dcw[i+3] = (dcw[i] + dcw[i+1] + dcw[i+2]) & 0xFF;
    }
}*/

static void cc_idle() {
	struct cc_data *cc = reader[ridx].cc;
	if (!reader[ridx].tcp_connected)
		return;
		
	cs_debug("%s IDLE", getprefix());
	if (cc->answer_on_keepalive + 55 < time(NULL)) {
		cc_cmd_send(NULL, 0, MSG_KEEPALIVE);
		cs_debug("cccam: keepalive");
		cc->answer_on_keepalive = time(NULL);
	}
}

static int cc_parse_msg(uint8 *buf, int l) {
	int ret = buf[1];
	struct cc_data *cc;

	if (!is_server)
		cc = reader[ridx].cc;
	else
		cc = client[cs_idx].cc;

	cs_debug("%s parse_msg=%d", getprefix(), buf[1]);

	uint8 *data = buf+4;
	memcpy(&cc->receive_buffer, data, l-4);

	switch (buf[1]) {
	case MSG_CLI_DATA:
		cs_debug("cccam: client data ack");
		break;
	case MSG_SRV_DATA:
		l -= 4;
		cs_log("%s MSG_SRV_DATA (payload=%d, hex=%02X)", getprefix(), l, l);
		data = (uint8*)&cc->receive_buffer;

		if (l == 0x48) { //72 bytes: normal server data
			memcpy(cc->peer_node_id, data, 8);
			memcpy(cc->peer_version, data+8, 8);

			memcpy(cc->cmd0b_aeskey, cc->peer_node_id, 8);
			memcpy(cc->cmd0b_aeskey + 8, cc->peer_version, 8);
			cs_log("%s srv %s running v%s (%s)", getprefix(),
					cs_hexdump(0, cc->peer_node_id, 8), data + 8, data + 40);
			cc->cmd05_mode = MODE_PLAIN;
			//
			//Keyoffset is payload-size:
			//
		} else if (l >= 0x00 && l <= 0x0F) {
			cc->cmd05_offset = l;
			//
			//16..43 bytes: RC4 encryption:
			//
		} else if ((l >= 0x10 && l <= 0x1f) || (l >= 0x24 && l <= 0x2b)) {
			cc_init_crypt(&cc->cmd05_cryptkey, data, l);
			cc->cmd05_mode = MODE_RC4_CRYPT;
			//
			//32 bytes: set AES128 key for CMD_05, Key=16 bytes offset keyoffset
			//
		} else if (l == 0x20) {
			memcpy(cc->cmd05_aeskey, data+cc->cmd05_offset, 16);
			cc->cmd05_mode = MODE_AES;
			//
			//33 bytes: xor-algo mit payload-bytes, offset keyoffset
			//
		} else if (l == 0x21) {
			cc_init_crypt(&cc->cmd05_cryptkey, data+cc->cmd05_offset, l);
			cc->cmd05_mode = MODE_CC_CRYPT;
			//
			//34 bytes: cmd_05 plain back
			//
		} else if (l == 0x22) {
			cc->cmd05_mode = MODE_PLAIN;
			//
			//35 bytes: Unknown!! 2 256 byte keys exchange
			//
		} else if (l == 0x23) {
			cc->cmd05_mode = MODE_UNKNOWN;
			cc_cycle_connection(); //Absolute unknown handling!
			//
			//44 bytes: set aes128 key, Key=16 bytes [Offset=len(password)]
			//
		} else if (l == 0x2c) {
			memcpy(cc->cmd05_aeskey, data+strlen(reader[ridx].r_pwd), 16);
			cc->cmd05_mode = MODE_AES;
			//
			//45 bytes: set aes128 key, Key=16 bytes [Offset=len(username)]
			//
		} else if (l == 0x2d) {
			memcpy(cc->cmd05_aeskey, data+strlen(reader[ridx].r_usr), 16);
			cc->cmd05_mode = MODE_AES;
			//
			//Unknown!!
			//
		} else {
			cs_log("%s received improper MSG_SRV_DATA! No change to current mode, mode=%d", getprefix(), cc->cmd05_mode);
			break;
			}
		cs_debug_mask(D_TRACE, "%s MSG_SRV_DATA MODE=%s, len=%d", getprefix(), cmd05_mode_name[cc->cmd05_mode], l);
		
		break;
	case MSG_NEW_CARD: {
		int i = 0;
		if (buf[14] > reader[ridx].cc_maxhop)
			break;

		if (caid_filtered(ridx, b2i(2, buf + 12)))
			break;

		struct cc_card *card = malloc(sizeof(struct cc_card));
		if (!card)
			break;

		reader[ridx].tcp_connected = 2; //we have card
		reader[ridx].card_status = CARD_INSERTED;
		memset(card, 0, sizeof(struct cc_card));

		card->provs = llist_create();
		card->badsids = llist_create();
		card->goodsids = llist_create();
		card->id = b2i(4, buf + 4);
		card->sub_id = b2i(3, buf + 9);
		card->caid = b2i(2, buf + 12);
		card->hop = buf[14];
		card->maxdown = buf[15];
		memcpy(card->hexserial, buf + 16, 8); //HEXSERIAL!!

		//cs_debug("cccam: card %08x added, caid %04X, hop %d, key %s, count %d",
		//		card->id, card->caid, card->hop, cs_hexdump(0, card->hexserial, 8),
		//		llist_count(cc->cards));

		for (i = 0; i < buf[24]; i++) { // providers
			uint8 *prov = malloc(3);
			if (prov) {
				memcpy(prov, buf + 25 + (7 * i), 3);
				cs_debug("      prov %d, %06x", i + 1, b2i(3, prov));

				llist_append(card->provs, prov);
			}
		}

		//SS: Hack:
		//Check if we already have this card:
		LLIST_ITR itr;
		struct cc_card *old_card = llist_itr_init(cc->cards, &itr);
		while (old_card) {
			if (old_card->id == card->id) { //we aready have this card, delete it
				cc_free_card(card);
				old_card->time = time((time_t) 0);
				return 0;
			}
			old_card = llist_itr_next(&itr);
		}

		card->time = time((time_t) 0);
		llist_append(cc->cards, card);

		//build own card/provs list:
		cc->needs_rebuild_caidinfo++;
		if (cc->needs_rebuild_caidinfo > CC_CAIDINFO_REBUILD) {
			//cleanup_old_cards(cc);
			rebuild_caidinfos(cc);
			saveCaidInfos(ridx, cc->caid_infos);
		} else {
			if (cc->caid_infos && checkCaidInfos(ridx, &cc->caid_size)) {
				freeCaidInfos(cc->caid_infos);
				cc->caid_infos = NULL;
			}
			if (!cc->caid_infos)
				cc->caid_infos = loadCaidInfos(ridx);
			if (!cc->caid_infos)
				cc->caid_infos = llist_create();

			if (add_card_to_caidinfo(cc, card))
				saveCaidInfos(ridx, cc->caid_infos);
		}
		uint8 *prov = llist_itr_init(card->provs, &itr);
		while (prov) {
			cc_remove_from_auto_blocked(cc->auto_blocked, card->caid, b2i(3,
					prov));
			prov = llist_itr_next(&itr);
		}
		//SS: Hack end
	}
		break;
	case MSG_CARD_REMOVED: {
		struct cc_card *card;
		LLIST_ITR itr;

		card = llist_itr_init(cc->cards, &itr);
		while (card) {
			if (card->id == b2i(4, buf + 4)) {// && card->sub_id == b2i (3, buf + 9)) {
				//cs_debug("cccam: card %08x removed, caid %04X, count %d",
				//		card->id, card->caid, llist_count(cc->cards));
				struct cc_card *next_card = llist_itr_remove(&itr);
				struct cc_current_card *current_card;
				while ((current_card = cc_find_current_card(cc, card))) {
					cs_debug_mask(D_TRACE, "%s current card %08x removed!", getprefix(), card->id);

					current_card->card = NULL;
					
				}
				cc_free_card(card);

				card = next_card;
				//break;
			} else {
				card = llist_itr_next(&itr);
			}
		}
		cc->needs_rebuild_caidinfo++;

		ret = 0;
	}
	break;
	
	case MSG_CW_NOK1:
	case MSG_CW_NOK2:
		if (l > 4) {
			//Received NOK with payload:
			cs_log("%s %s", getprefix(), (char*) buf+4);

			//Check for PARTNER connection:
			if (!cc->is_oscam_cccam && strncmp((char*)buf+4, "PARTNER:",8) == 0) {
				//When Data starts with "PARTNER:" we have an Oscam-cccam-compatible client/server!
				cc->is_oscam_cccam = 1;
				sprintf((char*)buf, "PARTNER: OSCam v%s, build #%s (%s)", CS_VERSION, CS_SVN_VERSION, CS_OSTYPE);
				cc_cmd_send(buf, strlen((char*)buf)+1, MSG_CW_NOK1);
			}
			return 0;
		}

		if (is_server) //for reader only
			return 0;

		if (cc->just_logged_in)
			return -1; // reader restart needed

		if (cc->current_ecm_cidx) {
			struct cc_current_card *current_card = &cc->current_card[cc->current_ecm_cidx];

			cs_debug_mask(D_TRACE, "%s cw nok (%d), sid = %04X(%d)", getprefix(), buf[1], 
				current_card->srvid.sid, current_card->srvid.ecmlen);
			struct cc_card *card = current_card->card;
			if (card) {
				if (!is_good_sid(card, &current_card->srvid)) {
					add_sid_block(card, &current_card->srvid);
					current_card->card = NULL;
				}
				else
					remove_good_sid(card, &current_card->srvid);
			}
			else
				current_card = NULL;
		}
		reader[ridx].available = 1;
		pthread_mutex_unlock(&cc->ecm_busy);
		
		if (!reader[ridx].cc_disable_retry_ecm)	{
			cc->crc++;
		}
		cc_send_ecm(NULL, NULL);

		ret = 0;
		
		break;
	case MSG_CW_ECM:
		cc->just_logged_in = 0;
		if (is_server) { //SERVER:
			ECM_REQUEST *er;

			memset(cc->server_card, 0, sizeof(struct cc_card));
			cc->server_card->id = buf[10] << 24 | buf[11] << 16 | buf[12] << 8 | buf[13];
			cc->server_card->caid = b2i(2, data);

			if ((er = get_ecmtask())) {
				er->caid = b2i(2, buf + 4);
				er->srvid = b2i(2, buf + 14);
				er->l = buf[16];
				memcpy(er->ecm, buf + 17, er->l);
				er->prid = b2i(4, buf + 6);
				cc->server_ecm_pending++;
				get_cw(er);
				cs_debug_mask(
						D_TRACE,
						"%s ECM request from client: caid %04x srvid %04x(%d) prid %06x",
						getprefix(), er->caid, er->srvid, er->l, er->prid);
			} else
				cs_debug_mask(D_TRACE, "%s NO ECMTASK!!!!", getprefix());

		} else { //READER:
			struct cc_current_card *current_card = &cc->current_card[cc->current_ecm_cidx];
			struct cc_card *card = current_card->card;
			if (card) {
				cc_cw_crypt(buf + 4, card->id);
				memcpy(cc->dcw, buf + 4, 16);
				cc_crypt(&cc->block[DECRYPT], buf + 4, l - 4, ENCRYPT); // additional crypto step

				if (is_null_dcw(cc->dcw)) {
					cs_log("%s null dcw received! sid=%04X(%d)", getprefix(), 
					  current_card->srvid.sid, current_card->srvid.ecmlen);
					add_sid_block(card, &current_card->srvid);
					current_card->card = NULL;
					cc->crc++; //So ecm could retryied
					buf[1] = MSG_CW_NOK1; //So it's really handled like a nok!
				}
				else {
					cc->recv_ecmtask = cc->send_ecmtask;
					int i = 0;
					for (i = 0; i < CS_MAXPENDING; i++) {
						if (ecmtask[i].idx == cc->send_ecmtask)
							ecmtask[i].rc = 99; //Mark as received
					}
					cs_debug_mask(D_TRACE, "%s cws: %d %s", getprefix(),
						cc->send_ecmtask, cs_hexdump(0, cc->dcw, 16));
					add_good_sid(card, &current_card->srvid);
				}
			}
			else {
				cs_log("%s warning: ECM-CWS respond by CCCam server without current card!", getprefix());
				current_card = NULL;
			}

			reader[ridx].available = 1;
			pthread_mutex_unlock(&cc->ecm_busy);
			
			//cc_abort_user_ecms();

			cc_send_ecm(NULL, NULL);

			if (cc->max_ecms)
				cc->ecm_counter++;
		}
		ret = 0;
		break;
	case MSG_KEEPALIVE:
		cc->just_logged_in = 0;
		if (!is_server) {
			cs_debug("cccam: keepalive ack");
		} else {
			//Checking if last answer is one minute ago:
			if (cc->answer_on_keepalive+55 < time(NULL)) {
				cc_cmd_send(NULL, 0, MSG_KEEPALIVE);
				cs_debug("cccam: keepalive");
				cc->answer_on_keepalive = time(NULL);
			}
		}
		break;
	case MSG_CMD_05:
		if (!is_server) {
			cc->just_logged_in = 0;
			l = l - 4;//Header Length=4 Byte

			cs_log("%s MSG_CMD_05 recvd, payload length=%d mode=%d", getprefix(), l, cc->cmd05_mode);
			cc->cmd05_active = 1;
			cc->cmd05_data_len = l;
			memcpy(&cc->cmd05_data, buf+4, l);
			if (reader[ridx].available)
				send_cmd05_answer();
			cc->current_ecm_cidx = 0; //After CMD_05 is always a NOK! So retry ECM
		}
		ret = 0;
		break;
	case MSG_CMD_0B: {
		// by Project:Keynation
		/*cs_log("%s MSG_CMD_0B received, cycle connection (payload=%d)!", getprefix(), l-4);*/
		cs_debug_mask(D_TRACE, "%s MSG_CMD_0B received (payload=%d)!", getprefix(), l-4);
		cs_ddump(buf, l, "%s content: len=%d", getprefix(), l);

		AES_KEY key;
		uint8 aeskey[16];
		uint8 out[16];

		memcpy(aeskey, cc->cmd0b_aeskey, 16);
		memset(&key, 0, sizeof(key));

		cs_ddump(aeskey, 16, "%s CMD_0B AES key:", getprefix());
		cs_ddump(buf + 4, 16, "%s CMD_0B received data:", getprefix());

		AES_set_encrypt_key((unsigned char *) &aeskey, 128, &key);
		AES_encrypt((unsigned char *) buf + 4, (unsigned char *) &out, &key);

		cs_debug_mask(D_TRACE, "%s sending CMD_0B! ", getprefix());
		cs_ddump(out, 16, "%s CMD_0B out:", getprefix());
		cc_cmd_send(out, 16, MSG_CMD_0B);

		ret = 0;
		break;
	}
	case MSG_EMM_ACK: {
		cc->just_logged_in = 0;
		if (is_server) { //EMM Request received
			cc_cmd_send(NULL, 0, MSG_EMM_ACK); //Send back ACK
			if (l > 4) {
				cs_debug_mask(D_EMM, "%s EMM Request received!", getprefix());

				int au = client[cs_idx].au;
				if ((au < 0) || (au > CS_MAXREADER)) {
					cs_debug_mask(D_EMM, "%s EMM Request discarded because au is not assigned to an reader!", getprefix());
					return 0;
				}

				EMM_PACKET *emm = malloc(sizeof(EMM_PACKET));
				memset(emm, 0, sizeof(EMM_PACKET));
				emm->caid[0] = buf[4];
				emm->caid[1] = buf[5];
				emm->provid[0] = buf[7];
				emm->provid[1] = buf[8];
				emm->provid[2] = buf[9];
				emm->provid[3] = buf[10];
				//emm->hexserial[0] = buf[11];
				//emm->hexserial[1] = buf[12];
				//emm->hexserial[2] = buf[13];
				//emm->hexserial[3] = buf[14];
				emm->l = buf[15];
				memcpy(emm->emm, buf + 16, emm->l);
				//emm->type = UNKNOWN;
				//emm->cidx = cs_idx;
				do_emm(emm);
				free(emm);
			}
		} else { //Our EMM Request Ack!
			cs_debug_mask(D_EMM, "%s EMM ACK!", getprefix());
			reader[ridx].available = 1;
			pthread_mutex_unlock(&cc->ecm_busy);
			cc->current_ecm_cidx = 0;
			cc_send_ecm(NULL, NULL);
		}
		ret = 0;
		break;
	}
	default:
		cs_ddump(buf, l, "%s unhandled msg: %d len=%d", getprefix(), buf[1], l);
		break;
	}

	if (cc->max_ecms && (cc->ecm_counter > cc->max_ecms)) {
		cs_log("%s max ecms (%d) reached, cycle connection!", getprefix(),
				cc->max_ecms);
		cc_cycle_connection();
		cc_send_ecm(NULL, NULL);
		ret = 0;
	}
	return ret;
}

static int cc_recv_chk(uchar *dcw, int *rc, uchar *buf) {
	struct cc_data *cc = reader[ridx].cc;

	if (buf[1] == MSG_CW_ECM) {
		memcpy(dcw, cc->dcw, 16);
		cs_debug("cccam: recv chk - MSG_CW %d - %s", cc->recv_ecmtask,
				cs_hexdump(0, dcw, 16));
		*rc = 1;
		return (cc->recv_ecmtask);
	} else if ((buf[1] == (MSG_CW_NOK1)) || (buf[1] == (MSG_CW_NOK2))) {
		//memset(dcw, 0, 16);
		//return *rc = 0;
		return -1;
	}

	return (-1);
}

static void cc_send_dcw(ECM_REQUEST *er) {
	uchar buf[16];
	struct cc_data *cc;

	memset(buf, 0, sizeof(buf));

	if (er->rc <= 3) {
		cc = client[cs_idx].cc;
		memcpy(buf, er->cw, sizeof(buf));
		cs_debug_mask(D_TRACE, "%s send cw: %s cpti: %d", getprefix(),
			cs_hexdump(0, buf, 16), er->cpti);
		cc_cw_crypt(buf, cc->server_card->id);
		cc_cmd_send(buf, 16, MSG_CW_ECM);
		cc_crypt(&cc->block[ENCRYPT], buf, 16, ENCRYPT); // additional crypto step
	} else {
		cs_debug_mask(D_TRACE, "%s send cw: NOK cpti: %d", getprefix(),
			er->cpti);
		cc_cmd_send(NULL, 0, MSG_CW_NOK1);
	}
	cc->server_ecm_pending--;
}

int cc_recv(uchar *buf, int l) {
	int n;
	uchar *cbuf;
	struct cc_data *cc;

	if (!is_server)
		cc = reader[ridx].cc;
	else
		cc = client[cs_idx].cc;

	if (buf == NULL || l <= 0)
		return -1;
	cbuf = malloc(l);
	memcpy(cbuf, buf, l); // make a copy of buf

	pthread_mutex_lock(&cc->lock);

	n = cc_msg_recv(cbuf); // recv and decrypt msg

	cs_ddump(cbuf, n, "cccam: received %d bytes from %s", n, remote_txt());
	client[cs_idx].last = time((time_t *) 0);

	if (n <= 0) {
		cs_log("%s connection closed to %s", getprefix(), remote_txt());
		n = -1;
	} else if (n < 4) {
		cs_log("%s packet to small (%d bytes)", getprefix(), n);
		n = -1;
	} else {
		// parse it and write it back, if we have received something of value
		if (cc_parse_msg(cbuf, n) == -1) //aston
			n = -2; 
		memcpy(buf, cbuf, l);
	}

	pthread_mutex_unlock(&cc->lock);

	NULLFREE(cbuf);
		
	if (!is_server && (n == -1)) {
		cs_debug_mask(D_TRACE, "%s cc_recv: cycle connection", getprefix());
		cc_cycle_connection();
	}

	return n;
}

static int cc_cli_connect(void) {
	int handle, n;
	uint8 data[20];
	uint8 hash[SHA_DIGEST_LENGTH];
	uint8 buf[CC_MAXMSGSIZE];
	char pwd[64];

	// check cred config
	if (reader[ridx].device[0] == 0 || reader[ridx].r_pwd[0] == 0
			|| reader[ridx].r_usr[0] == 0 || reader[ridx].r_port == 0) {
		cs_log("%s configuration error!", getprefix());
		return -5;
	}

	// connect
	handle = network_tcp_connection_open();
	if (handle <= 0) {
		cs_log("%s network connect error!", getprefix());
		return -1;
	}

	// get init seed
	//if ((n = recv(handle, data, 16, MSG_WAITALL)) != 16) {
	if ((n = read(handle, data, 16)) != 16) {
		int err = errno;
		cs_log("%s server does not return 16 bytes (n=%d, handle=%d, udp_fd=%d, cs_idx=%d, errno=%d)", 
			getprefix(), n, handle, client[cs_idx].udp_fd, cs_idx, err);
		return -2;
	}
	struct cc_data *cc = reader[ridx].cc;

	if (!cc) {
		// init internals data struct
		cc = malloc(sizeof(struct cc_data));
		if (cc == NULL) {
			cs_log("%s cannot allocate memory", getprefix());
			return -1;
		}
		memset(cc, 0, sizeof(struct cc_data));
		cc->cards = llist_create();
		reader[ridx].cc = cc;
		cc->auto_blocked = llist_create();
		cc->current_card = malloc(sizeof(struct cc_current_card)*CS_MAXPID);
		memset(cc->current_card, 0, sizeof(struct cc_current_card)*CS_MAXPID);
		cc->pending_emms = llist_create();
	}
	cc->ecm_counter = 0;
	cc->max_ecms = 0;
	cc->cmd05_mode = MODE_UNKNOWN;
	cc->cmd05_offset = 0;
	cc->cmd05_active = 0;
	cc->cmd05_data_len = 0;
	cc->answer_on_keepalive = time(NULL);
	memset(&cc->cmd05_data, 0, sizeof(cc->cmd05_data));

	pthread_mutex_init(&cc->lock, NULL);
	pthread_mutex_init(&cc->ecm_busy, NULL);

	cs_ddump(data, 16, "cccam: server init seed:");

	uint16 sum = 0x1234;
	uint16 recv_sum = (data[14] << 8) | data[15];
	int i;
	for (i = 0; i < 14; i++) {
		sum += data[i];
	}
	//Create special data to detect oscam-cccam:
	cc->is_oscam_cccam = sum==recv_sum;

	cc_xor(data); // XOR init bytes with 'CCcam'

	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, data, 16);
	SHA1_Final(hash, &ctx);

	cs_ddump(hash, sizeof(hash), "cccam: sha1 hash:");

	//initialisate crypto states
	cc_init_crypt(&cc->block[DECRYPT], hash, 20);
	cc_crypt(&cc->block[DECRYPT], data, 16, DECRYPT);
	cc_init_crypt(&cc->block[ENCRYPT], data, 16);
	cc_crypt(&cc->block[ENCRYPT], hash, 20, DECRYPT);

	cc_cmd_send(hash, 20, MSG_NO_HEADER); // send crypted hash to server

	memset(buf, 0, sizeof(buf));
	memcpy(buf, reader[ridx].r_usr, strlen(reader[ridx].r_usr));
	cs_ddump(buf, 20, "cccam: username '%s':", buf);
	cc_cmd_send(buf, 20, MSG_NO_HEADER); // send usr '0' padded -> 20 bytes

	memset(buf, 0, sizeof(buf));
	memset(pwd, 0, sizeof(pwd));

	cs_debug("cccam: 'CCcam' xor");
	memcpy(buf, "CCcam", 5);
	strncpy(pwd, reader[ridx].r_pwd, sizeof(pwd) - 1);
	cc_crypt(&cc->block[ENCRYPT], (uint8 *) pwd, strlen(pwd), ENCRYPT);
	cc_cmd_send(buf, 6, MSG_NO_HEADER); // send 'CCcam' xor w/ pwd

	//if ((n = recv(handle, data, 20, MSG_WAITALL)) != 20) {
	if ((n = read(handle, data, 20)) != 20) {
		cs_log("%s login failed, pwd ack not received (n = %d)", getprefix(), n);
		return -2;
	}
	cc_crypt(&cc->block[DECRYPT], data, 20, DECRYPT);
	cs_ddump(data, 20, "cccam: pwd ack received:");

	if (memcmp(data, buf, 5)) { // check server response
		cs_log("%s login failed, usr/pwd invalid", getprefix());
		return -2;
	} else {
		cs_debug_mask(D_TRACE, "%s login succeeded", getprefix());
	}

	cs_debug("cccam: last_s=%d, last_g=%d", reader[ridx].last_s,
			reader[ridx].last_g);

	pfd = client[cs_idx].udp_fd;
	cs_debug("cccam: pfd=%d", pfd);

	if (cc_send_cli_data() <= 0) {
		cs_log("%s login failed, could not send client data", getprefix());
		return -3;
	}

	//Trick: when discovered partner is an Oscam Client, then we send him our version string:
	if (cc->is_oscam_cccam) {
		sprintf((char*)buf, "PARTNER: OSCam v%s, build #%s (%s)", CS_VERSION, CS_SVN_VERSION, CS_OSTYPE);
		cc_cmd_send(buf, strlen((char*)buf)+1, MSG_CW_NOK1);
	}

	reader[ridx].caid[0] = reader[ridx].ftab.filts[0].caid;
	reader[ridx].nprov = reader[ridx].ftab.filts[0].nprids;
	for (n = 0; n < reader[ridx].nprov; n++) {
		reader[ridx].availkeys[n][0] = 1;
		reader[ridx].prid[n][0] = reader[ridx].ftab.filts[0].prids[n] >> 24;
		reader[ridx].prid[n][1] = reader[ridx].ftab.filts[0].prids[n] >> 16;
		reader[ridx].prid[n][2] = reader[ridx].ftab.filts[0].prids[n] >> 8;
		reader[ridx].prid[n][3] = reader[ridx].ftab.filts[0].prids[n] & 0xff;
	}

	reader[ridx].card_status = CARD_NEED_INIT;
	reader[ridx].last_g = reader[ridx].last_s = time((time_t *) 0);
	reader[ridx].tcp_connected = 1;
	reader[ridx].available = 1;

	cc->just_logged_in = 1;

	return 0;
}

struct s_auth *get_account(char *usr) {
	struct s_auth *account;
	for (account = cfg->account; account; account = account->next) {
		if (strcmp(usr, account->usr) == 0) {
			return account;
		}
	}
	return NULL;
}

/**
 * This function checks for hexserial changes on cards.
 * We update the share-list if a card has changed
 */
static ulong get_reader_hexserial_crc()
{
	if (!client[cs_idx].au)
		return 0;
		
	ulong crc = 0;
	int r;
	for (r = 0; r < CS_MAXREADER; r++) {
		 if (reader[r].enable && !reader[r].deleted && reader[r].cs_idx && 
		     		!reader[r].audisabled)
			crc += crc32(0, reader[r].hexserial, 8);
	}
	return crc;
}

/**
 * Server:
 * Reports all caid/providers to the connected clients
 * returns total count of reported cards
 */
static int cc_srv_report_cards() {
	int j;
	uint32 id;
	uint r, k;
	uint8 hop = 0;
	int reshare, usr_reshare, reader_reshare, maxhops, flt = 0;
	uint8 buf[CC_MAXMSGSIZE];
	struct cc_data *cc = client[cs_idx].cc;

	struct s_auth *account = get_account(client[cs_idx].usr);
	if (account) {
		maxhops = account->cccmaxhops;
		usr_reshare = account->cccreshare;
	} else {
		maxhops = 10;
		usr_reshare = cfg->cc_reshare;
	}
	
	if (!cc->report_carddata_id)
		id = 0x64;
	else
		id = cc->report_carddata_id;

	LLIST *reported_carddatas = llist_create();

	for (r = 0; r < CS_MAXREADER; r++) {
		if (!reader[r].fd || !reader[r].enable || reader[r].deleted) continue;
		if (!(reader[r].grp & client[cs_idx].grp)) continue;
		reader_reshare = reader[r].cc_reshare;

		reshare = (reader_reshare < usr_reshare) ? reader_reshare : usr_reshare;
		if (reshare < 0)
			continue;
			
		flt = 0;
		if (/*!reader[r].caid[0] && */reader[r].ftab.filts) {
			for (j = 0; j < CS_MAXFILTERS; j++) {
				if (reader[r].ftab.filts[j].caid) {
					memset(buf, 0, sizeof(buf));
					buf[0] = id >> 24;
					buf[1] = id >> 16;
					buf[2] = id >> 8;
					buf[3] = id & 0xff;
					//if (!reader[r].cc_id)
					{
						buf[6] = 0x49 + r;
						buf[7] = 0x10 + j;
						reader[r].cc_id = b2i(3, buf + 5);
					}
					//else
					//reader[r].cc_id++;
					buf[5] = reader[r].cc_id >> 16;
					buf[6] = reader[r].cc_id >> 8;
					buf[7] = reader[r].cc_id & 0xFF;
					buf[8] = reader[r].ftab.filts[j].caid >> 8;
					buf[9] = reader[r].ftab.filts[j].caid & 0xff;
					buf[10] = hop;
					buf[11] = reshare;
					if (!reader[r].audisabled && client[cs_idx].au)
						memcpy(buf + 12, reader[r].hexserial, 8);
					buf[20] = reader[r].ftab.filts[j].nprids;
					//cs_log("Ident CCcam card report caid: %04X readr %s subid: %06X", reader[r].ftab.filts[j].caid, reader[r].label, reader[r].cc_id);
					for (k = 0; k < reader[r].ftab.filts[j].nprids; k++) {
						buf[21 + (k * 7)] = reader[r].ftab.filts[j].prids[k]
								>> 16;
						buf[22 + (k * 7)] = reader[r].ftab.filts[j].prids[k]
								>> 8;
						buf[23 + (k * 7)] = reader[r].ftab.filts[j].prids[k]
								& 0xFF;
						//cs_log("Ident CCcam card report provider: %02X%02X%02X", buf[21 + (k*7)]<<16, buf[22 + (k*7)], buf[23 + (k*7)]);
					}
					buf[21 + (k * 7)] = 1;
					memcpy(buf + 22 + (k * 7), cc->node_id, 8);
					/*
					 buf[21 + (k*7)+8] = 1;
					 memcpy(buf + 22 + (k*7)+8, cc->node_id, 7);//8);
					 cc_cmd_send(buf, 30 + (k*7) + 9, MSG_NEW_CARD);
					 */
					int len = 30 + (k * 7);
					cc_cmd_send(buf, len, MSG_NEW_CARD);
					cc_add_reported_carddata(reported_carddatas, buf, len);

					id++;
					flt = 1;
				}
			}
		}

		if (!reader[r].caid[0] && !flt) {
			flt = 0;
			for (j = 0; j < CS_MAXCAIDTAB; j++) {
				//cs_log("CAID map CCcam card report caid: %04X cmap: %04X", reader[r].ctab.caid[j], reader[r].ctab.cmap[j]);
				ushort lcaid = reader[r].ctab.caid[j];

				if (!lcaid || (lcaid == 0xFFFF))
					lcaid = reader[r].ctab.cmap[j];

				if (lcaid && (lcaid != 0xFFFF)) {
					memset(buf, 0, sizeof(buf));
					buf[0] = id >> 24;
					buf[1] = id >> 16;
					buf[2] = id >> 8;
					buf[3] = id & 0xff;
					//if (!reader[r].cc_id)
					{
						buf[6] = 0x48 + r;
						buf[7] = 0x63 + j;
						reader[r].cc_id = b2i(3, buf + 5);
					}
					//else
					//reader[r].cc_id++;
					buf[5] = reader[r].cc_id >> 16;
					buf[6] = reader[r].cc_id >> 8;
					buf[7] = reader[r].cc_id & 0xFF;
					buf[8] = lcaid >> 8;
					buf[9] = lcaid & 0xff;
					buf[10] = hop;
					buf[11] = reshare;
					if (!reader[r].audisabled && client[cs_idx].au)
						memcpy(buf + 12, reader[r].hexserial, 8);
					buf[20] = 1;
					//cs_log("CAID map CCcam card report caid: %04X nodeid: %s subid: %06X", lcaid, cs_hexdump(0, cc->peer_node_id, 8), reader[r].cc_id);
					//buf[21] = 0;
					//buf[22] = 0;
					//buf[23] = 0;
					buf[21 + 7] = 1;
					memcpy(buf + 22 + 7, cc->node_id, 8);
					int len = 30 + 7;
					cc_cmd_send(buf, len, MSG_NEW_CARD);
					cc_add_reported_carddata(reported_carddatas, buf, len);
					id++;

					flt = 1;
				}
			}
		}

		if (reader[r].caid[0] && !flt) {
			//cs_log("tcp_connected: %d card_status: %d ", reader[r].tcp_connected, reader[r].card_status);
			memset(buf, 0, sizeof(buf));
			buf[0] = id >> 24;
			buf[1] = id >> 16;
			buf[2] = id >> 8;
			buf[3] = id & 0xff;
			buf[5] = reader[r].cc_id >> 16;
			buf[6] = reader[r].cc_id >> 8;
			buf[7] = reader[r].cc_id & 0xFF;
			if (!reader[r].cc_id) {
				buf[6] = 0x99;
				buf[7] = 0x63 + r;
			}
			buf[8] = reader[r].caid[0] >> 8;
			buf[9] = reader[r].caid[0] & 0xff;
			buf[10] = hop;
			buf[11] = reshare;
			if (!reader[r].audisabled && client[cs_idx].au)
				memcpy(buf + 12, reader[r].hexserial, 8);
			buf[20] = reader[r].nprov;
			for (j = 0; j < reader[r].nprov; j++) {
				if (!(reader[r].typ & R_IS_CASCADING)) //(reader[r].card_status == CARD_INSERTED)
					memcpy(buf + 21 + (j * 7), reader[r].prid[j] + 1, 3);
				else
					memcpy(buf + 21 + (j * 7), reader[r].prid[j], 3);
				//cs_log("Main CCcam card report provider: %02X%02X%02X%02X", buf[21+(j*7)], buf[22+(j*7)], buf[23+(j*7)], buf[24+(j*7)]);
			}

			buf[21 + (j * 7)] = 1;
			memcpy(buf + 22 + (j * 7), cc->node_id, 8);
			id++;

			if ((reader[r].tcp_connected || reader[r].card_status
					== CARD_INSERTED) /*&& !reader[r].cc_id*/) {
				reader[r].cc_id = b2i(3, buf + 5);
				int len = 30 + (j * 7);
				cc_add_reported_carddata(reported_carddatas, buf, len);
				cc_cmd_send(buf, len, MSG_NEW_CARD);
				//cs_log("CCcam: local card or newcamd reader  %02X report ADD caid: %02X%02X %d %d %s subid: %06X", buf[7], buf[8], buf[9], reader[r].card_status, reader[r].tcp_connected, reader[r].label, reader[r].cc_id);
			} else if ((reader[r].card_status != CARD_INSERTED)
					&& (!reader[r].tcp_connected) && reader[r].cc_id) {
				reader[r].cc_id = 0;
				cc_cmd_send(buf, 30 + (j * 7), MSG_CARD_REMOVED);
				//cs_log("CCcam: local card or newcamd reader %02X report REMOVE caid: %02X%02X %s", buf[7], buf[8], buf[9], reader[r].label);
			}
		}

		//SS: Hack:
		if (reader[r].typ == R_CCCAM && !flt) {
			if (cc->caid_infos && checkCaidInfos(r, &cc->caid_size)) {
				freeCaidInfos(cc->caid_infos);
				cc->caid_infos = NULL;
			}
			if (!cc->caid_infos)
				cc->caid_infos = loadCaidInfos(r);
			if (cc->caid_infos) {
				LLIST_ITR itr;
				struct cc_caid_info *caid_info = llist_itr_init(cc->caid_infos,
						&itr);
				while (caid_info) {
					if (caid_info->hop <= maxhops) {
						memset(buf, 0, sizeof(buf));
						buf[0] = id >> 24;
						buf[1] = id >> 16;
						buf[2] = id >> 8;
						buf[3] = id & 0xff;
						buf[5] = reader[r].cc_id >> 16;
						buf[6] = reader[r].cc_id >> 8;
						buf[7] = reader[r].cc_id & 0xFF;
						if (!reader[r].cc_id) {
							buf[6] = 0x99;
							buf[7] = 0x63 + r;
						}
						buf[8] = caid_info->caid >> 8;
						buf[9] = caid_info->caid & 0xff;
						buf[10] = caid_info->hop+1;
						buf[11] = reshare;
						//memcpy(buf + 12, caid_info->hexserial, 8);
						int j = 0;
						LLIST_ITR itr_prov;
						uint8 *prov = llist_itr_init(caid_info->provs, &itr_prov);
						while (prov) {
							memcpy(buf + 21 + (j * 7), prov, 3);
							prov = llist_itr_next(&itr_prov);
							j++;
						}
						buf[20] = j;

						buf[21 + (j * 7)] = 1;
						memcpy(buf + 22 + (j * 7), cc->node_id, 8);
						id++;

						reader[r].cc_id = b2i(3, buf + 5);
						int len = 30 + (j * 7);
						cc_cmd_send(buf, len, MSG_NEW_CARD);
						cc_add_reported_carddata(reported_carddatas, buf, len);
					}
					caid_info = llist_itr_next(&itr);
				}
			}
		}
		//SS: Hack end
	}
	cc->report_carddata_id = id;

	//Reported deleted cards:
	cc_free_reported_carddata(cc->reported_carddatas, 1);
	cc->reported_carddatas = reported_carddatas;

	int count = llist_count(reported_carddatas);
	cs_log("%s reported %d cards to client", getprefix(), count);
	return count;
}

static int cc_srv_connect() {
	int i;
	ulong cmi;
	uint seed;
	uint8 buf[CC_MAXMSGSIZE];
	uint8 data[16];
	char usr[21], pwd[21];
	struct s_auth *account;
	struct cc_data *cc;

	memset(usr, 0, sizeof(usr));
	memset(pwd, 0, sizeof(pwd));

	//SS: Use last cc data for faster reconnects:
	cc = client[cs_idx].cc;
	if (!cc) {
		// init internals data struct
		cc = malloc(sizeof(struct cc_data));
		if (cc == NULL) {
			cs_log("%s cannot allocate memory", getprefix());
			return -1;
		}

		client[cs_idx].cc = cc;
		memset(client[cs_idx].cc, 0, sizeof(struct cc_data));
		cc->server_card = malloc(sizeof(struct cc_card));
	}
	cc->server_ecm_pending = 0;
	cc_use_rc4 = 0;
	is_server = 1;
	
	// calc + send random seed
	seed = (unsigned int) time((time_t*) 0);
	uint16 sum = 0x1234;
	for (i = 0; i < 14; i++) {
		data[i] = fast_rnd();
		sum += data[i];
	}
	//Create special data to detect oscam-cccam:
	data[14] = sum >> 8;
	data[15] = sum & 0xff;

	send(client[cs_idx].udp_fd, data, 16, 0);

	cc_xor(data); // XOR init bytes with 'CCcam'

	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, data, 16);
	SHA1_Final(buf, &ctx);

	//Special check for 2.0.11 clients
	//2.0.11 uses rc4 crypt
	//So we need to test data for validity:
	struct cc_crypt_block *block_rc4 = malloc(sizeof(struct cc_crypt_block)*2);
	uint8 *data_rc4 = malloc(16);
	uint8 *buf_rc4 = malloc(CC_MAXMSGSIZE);
	memcpy(data_rc4, data, sizeof(data));
	memcpy(buf_rc4, buf, CC_MAXMSGSIZE);
	memcpy(block_rc4, cc->block, sizeof(struct cc_crypt_block)*2);
	char usr_rc4[21];
	memset(usr_rc4, 0, sizeof(usr_rc4));

	//2.1.1 and newer clients:
	cc_init_crypt(&cc->block[ENCRYPT], buf, 20);
	cc_crypt(&cc->block[ENCRYPT], data, 16, DECRYPT);
	cc_init_crypt(&cc->block[DECRYPT], data, 16);
	cc_crypt(&cc->block[DECRYPT], buf, 20, DECRYPT);

	//2.0.11 client:
	cc_init_crypt(&block_rc4[ENCRYPT], buf_rc4, 20);
	cc_rc4_crypt(&block_rc4[ENCRYPT], data_rc4, 16, DECRYPT);
	cc_init_crypt(&block_rc4[DECRYPT], data_rc4, 16);
	cc_rc4_crypt(&block_rc4[DECRYPT], buf_rc4, 20, DECRYPT);

	if ((i = recv(pfd, buf, 20, MSG_WAITALL)) == 20) {
		cs_ddump(buf, 20, "cccam: recv:");
		memcpy(buf_rc4, buf, CC_MAXMSGSIZE);
		cc_crypt(&cc->block[DECRYPT], buf, 20, DECRYPT);
		cc_rc4_crypt(&block_rc4[DECRYPT], buf_rc4, 20, DECRYPT);
		cs_ddump(buf, 20, "cccam: hash:");
		cs_ddump(buf_rc4, 20, "cccam: hash rc4:");
	} 

	// receive username
	if ((i = recv(pfd, buf, 20, MSG_WAITALL)) == 20) {
		memcpy(buf_rc4, buf, CC_MAXMSGSIZE);
		cc_crypt(&cc->block[DECRYPT], buf, 20, DECRYPT);
		cc_rc4_crypt(&block_rc4[DECRYPT], buf_rc4, 20, DECRYPT);

		strncpy(usr, (char *) buf, sizeof(usr));
		strncpy(usr_rc4, (char *) buf_rc4, sizeof(usr_rc4));
		
		//test for nonprintable characters:
		cc_use_rc4 = -1;
		for (i = 0; i < 20; i++)
		{
			if (usr[i] > 0 && usr[i] < 0x20) { //found nonprintable char
				cc_use_rc4 = 1;
				break;
			}
			if (usr_rc4[i] > 0 && usr_rc4[i] < 0x20) { //found nonprintable char
				cc_use_rc4 = 0;
				break;
			}
		}
		if (cc_use_rc4 == 0)
			cs_ddump(buf, 20, "cccam: username '%s':", usr);
		else if (cc_use_rc4 == 1)
			cs_ddump(buf_rc4, 20, "cccam: username rc4 '%s':", usr_rc4);
		else
			cs_debug("illegal username received");
	} 

	for (account = cfg->account; account; account = account->next) {
		if (strcmp(usr, account->usr) == 0) {
			strncpy(pwd, account->pwd, sizeof(pwd));
			cc_use_rc4 = 0; //We found a user by cc_crypt
			break;
		}
		if (strcmp(usr_rc4, account->usr) == 0) {
			strncpy(pwd, account->pwd, sizeof(pwd));
			cc_use_rc4 = 1; //We found a user by cc_rc4_crypt
			break;
		}
	}
	 
	if (!account || cc_use_rc4 == -1) {
		cs_log("account '%s' not found!", cc_use_rc4?usr_rc4:usr);
		return -1;
	}
	
	if (cc_use_rc4) {
		cs_log("%s client is using version 2.0.11 rc4", getprefix());
		memcpy(cc->block, block_rc4, sizeof(struct cc_crypt_block)*2);
	}
	free(block_rc4);
	free(data_rc4);
	free(buf_rc4);

	// receive passwd / 'CCcam'
	cc_crypt(&cc->block[DECRYPT], (uint8 *) pwd, strlen(pwd), DECRYPT);
	if ((i = recv(pfd, buf, 6, MSG_WAITALL)) == 6) {
		cc_crypt(&cc->block[DECRYPT], buf, 6, DECRYPT);
		cs_ddump(buf, 6, "cccam: pwd check '%s':", buf);
	} else
		return -1;

	client[cs_idx].crypted = 1;
	if (cs_auth_client(account, NULL))
		return -1;
	//cs_auth_client((struct s_auth *)(-1), NULL);

	// send passwd ack
	memset(buf, 0, 20);
	memcpy(buf, "CCcam\0", 6);
	cs_ddump(buf, 20, "cccam: send ack:");
	cc_crypt(&cc->block[ENCRYPT], buf, 20, ENCRYPT);
	send(pfd, buf, 20, 0);

	// recv cli data
	memset(buf, 0, sizeof(buf));
	i = cc_msg_recv(buf);
	if (i < 0)
		return -1;
	cs_ddump(buf, i, "cccam: cli data:");
	memcpy(cc->peer_node_id, buf + 24, 8);
	cs_log("%s client '%s' (%s) running v%s (%s)", getprefix(), buf + 4,
			cs_hexdump(0, cc->peer_node_id, 8), buf + 33, buf + 65);

	// send cli data ack
	cc_cmd_send(NULL, 0, MSG_CLI_DATA);

	if (cc_send_srv_data() < 0)
		return -1;

	// report cards
	ulong hexserial_crc = get_reader_hexserial_crc();
	cc_srv_report_cards();
	int caid_info_count = cc->caid_infos ? llist_count(cc->caid_infos) : 0;
	cs_ftime(&cc->ecm_time);

	cmi = 0;
	// check for client timeout, if timeout occurs try to send keepalive
	for (;;) {
		i = process_input(mbuf, sizeof(mbuf), 10); //cfg->cmaxidle);
		//cs_log("srv process input i=%d cmi=%d", i, cmi);
		if (i == -9) {
			cmi += 10;
			if (cfg->cmaxidle && cmi >= cfg->cmaxidle) {
				cmi = 0;
				cs_debug_mask(D_TRACE, "%s keepalive after maxidle is reached", getprefix());
				break;
			}
		} else if (i <= 0)
			break;
		else {
			cmi = 0;
			if (!cc->server_ecm_pending) {
				struct timeb timeout;	
				struct timeb cur_time;
				cs_ftime(&cur_time);
				timeout = cc->ecm_time;
				timeout.millitm += cfg->ctimeout*20; //ctimeout normaly 6000ms, 20x6000ms = 20x6s = 120s = 2min
				timeout.time += timeout.millitm / 1000;
				timeout.millitm = timeout.millitm % 1000;
			
				int force_card_updates = comp_timeb(&cur_time, &timeout) > 0;
				int new_caid_info_count = cc->caid_infos ? llist_count(cc->caid_infos) : 0;
				ulong new_hexserial_crc = get_reader_hexserial_crc();
				if (force_card_updates || new_caid_info_count != caid_info_count || new_hexserial_crc != hexserial_crc) {
					cs_debug_mask(D_TRACE, "%s update share list", getprefix());
					cc_srv_report_cards();
					caid_info_count = new_caid_info_count;
					hexserial_crc = new_hexserial_crc;
					cc->ecm_time = cur_time;
				}
			}
		}
	}
	return 0;
}

void cc_srv_init() {
	pfd = client[cs_idx].udp_fd;
	//cc_auth_client(client[cs_idx].ip);
	if (cc_srv_connect() < 0)
		cs_log("cccam: %d failed errno: %d (%s)", __LINE__, errno, strerror(
				errno));
	cs_disconnect_client();

	cs_exit(1);
}

int cc_cli_init_int() {
	
	if (reader[ridx].tcp_connected)
		return -1;
	
	struct protoent *ptrp;
	int p_proto;

	pfd = 0;
	if (reader[ridx].r_port <= 0) {
		cs_log("%s invalid port %d for server %s", getprefix(),
				reader[ridx].r_port, reader[ridx].device);
		return (1);
	}
	if ((ptrp = getprotobyname("tcp")))
		p_proto = ptrp->p_proto;
	else
		p_proto = 6;

	//		client[cs_idx].ip = 0;
	//		memset((char *) &loc_sa, 0, sizeof(loc_sa));
	//		loc_sa.sin_family = AF_INET;
	//#ifdef LALL
	//		if (cfg->serverip[0])
	//		loc_sa.sin_addr.s_addr = inet_addr(cfg->serverip);
	//		else
	//#endif
	//		loc_sa.sin_addr.s_addr = INADDR_ANY;
	//		loc_sa.sin_port = htons(reader[ridx].l_port);

	if ((client[cs_idx].udp_fd = socket(PF_INET, SOCK_STREAM, p_proto)) <= 0) {
		cs_log("%s Socket creation failed (errno=%d, socket=%d)", getprefix(), errno, client[cs_idx].udp_fd);
		return -10;
	}
	//cs_log("%s 1 socket created: cs_idx=%d, fd=%d errno=%d", getprefix(), cs_idx, client[cs_idx].udp_fd, errno);

#ifdef SO_PRIORITY
	if (cfg->netprio)
		setsockopt(client[cs_idx].udp_fd, SOL_SOCKET, SO_PRIORITY,
			(void *)&cfg->netprio, sizeof(ulong));
#endif
	reader[ridx].tcp_ito = 1; //60sec...This now invokes ph_idle()

	memset((char *) &client[cs_idx].udp_sa, 0, sizeof(client[cs_idx].udp_sa));
	client[cs_idx].udp_sa.sin_family = AF_INET;
	client[cs_idx].udp_sa.sin_port = htons((u_short) reader[ridx].r_port);

	if (reader[ridx].tcp_rto <= 0)
		 reader[ridx].tcp_rto = 60 * 60 * 10; // timeout to 10 hours
	cs_debug("cccam: reconnect timeout set to: %d", reader[ridx].tcp_rto);
	cc_check_version(reader[ridx].cc_version, reader[ridx].cc_build);
	cs_log(
			"proxy reader: %s (%s:%d) cccam v%s build %s, maxhop: %d, retry ecm: %d, auto block: %d",
			reader[ridx].label, reader[ridx].device, reader[ridx].r_port,
			reader[ridx].cc_version, reader[ridx].cc_build,
			reader[ridx].cc_maxhop, !reader[ridx].cc_disable_retry_ecm,
			!reader[ridx].cc_disable_auto_block);

	return cc_cli_connect();
}

static int cc_cli_init()
{
	while (cc_cli_init_int() != 0) {
		network_tcp_connection_close(&reader[ridx], client[cs_idx].udp_fd);
		if (master_pid!=getppid()) cs_exit(0);
		cs_sleepms(cfg->reader_restart_seconds * 1000); // SS: wait
		cs_log("restarting reader %s (index=%d)", reader[ridx].label, ridx);                        
	}
	return 0;
}

/**
 * return 1 if we are able to send requests:
 */
int cc_available(int ridx, int checktype) {
	//cs_debug_mask(D_TRACE, "checking reader %s availibility", reader[ridx].label);
	if (!reader[ridx].cc || reader[ridx].tcp_connected != 2 || reader[ridx].card_status != CARD_INSERTED)
		return 0;
	
	if (checktype == AVAIL_CHECK_LOADBALANCE && !reader[ridx].available) {
		cs_debug_mask(D_TRACE, "checking reader %s availibility=0 (unavail)", reader[ridx].label);
		return 0; //We are not initialized or not connected!
	}

	return 1;
}

void cc_cleanup(void) {
	if (!is_server) {
		cc_cli_close(); // we need to close open fd's 
		cc_free(reader[ridx].cc);
		reader[ridx].cc = NULL;
	} else {
		cc_free(client[cs_idx].cc);
		client[cs_idx].cc = NULL;
	}
}

void module_cccam(struct s_module *ph) {
	strcpy(ph->desc, "cccam");
	ph->type = MOD_CONN_TCP;
	ph->logtxt = ", crypted";
	ph->watchdog = 1;
	ph->recv = cc_recv;
	ph->cleanup = cc_cleanup;
	ph->c_multi = 1;
	ph->c_init = cc_cli_init;
	ph->c_idle = cc_idle;
	ph->c_recv_chk = cc_recv_chk;
	ph->c_send_ecm = cc_send_ecm;
	ph->c_send_emm = cc_send_emm;
	ph->s_ip = cfg->cc_srvip;
	ph->s_handler = cc_srv_init;
	ph->send_dcw = cc_send_dcw;
	ph->c_available = cc_available;
	static PTAB ptab;
	ptab.ports[0].s_port = cfg->cc_port;
	ph->ptab = &ptab;
	ph->ptab->nports = 1;
}
