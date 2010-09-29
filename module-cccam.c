#include <string.h>
#include <stdlib.h>
#include "globals.h"
#include "module-cccam.h"
#include "module-obj-llist.h"
#include <time.h>
#include "reader-common.h"
#include <poll.h>

extern struct s_reader *reader;
extern int pthread_mutexattr_settype (pthread_mutexattr_t *__attr, int __kind); //Needs extern defined???

//Mode names for CMD_05 command:
const char *cmd05_mode_name[] = { "UNKNOWN", "PLAIN", "AES", "CC_CRYPT", "RC4",
		"LEN=0" };

extern unsigned int seed;

char *getprefix() {
	struct s_client *cl = &client[cs_idx];
	struct cc_data *cc = cl->cc;
	if (!cc)
		return "";
		
	if (cc->prefix)
		return cc->prefix;

	cc->prefix = malloc(100);
	if (cl->is_server)
		sprintf(cc->prefix, "cccam(s) %s: ", cl->usr);
	else
		sprintf(cc->prefix, "cccam(r) %s: ", reader[cl->ridx].label);
	while (strlen(cc->prefix) < 22)
		strcat(cc->prefix, " ");
	return cc->prefix;
}

int comp_timeb(struct timeb *tpa, struct timeb *tpb) {
	if (tpa->time > tpb->time)
		return (1);
	if (tpa->time < tpb->time)
		return (-1);
	if (tpa->millitm > tpb->millitm)
		return (1);
	if (tpa->millitm < tpb->millitm)
		return (-1);
	return (0);
}

void cc_init_crypt(struct cc_crypt_block *block, uint8 *key, int len) {
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

int is_au() {
	struct s_client *cl = &client[cs_idx];
	int au = cl->au;
	if ((au < 0) || (au > CS_MAXREADER))
		return 0;
	return 1;
}

void cc_crypt(struct cc_crypt_block *block, uint8 *data, int len,
		cc_crypt_mode_t mode) {
	struct s_client *cl = &client[cs_idx];
	struct cc_data *cc = cl->cc;
	int i;
	uint8 z;

	for (i = 0; i < len; i++) {
		block->counter++;
		block->sum += block->keytable[block->counter];
		SWAPC(&block->keytable[block->counter], &block->keytable[block->sum]);
		z = data[i];
		data[i] = z ^ block->keytable[(block->keytable[block->counter]
				+ block->keytable[block->sum]) & 0xff];
		if (!cc->cc_use_rc4)
			data[i] ^= block->state;
		if (!mode)
			z = data[i];
		block->state = block->state ^ z;
	}
}

void cc_rc4_crypt(struct cc_crypt_block *block, uint8 *data, int len,
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

void cc_xor(uint8 *buf) {
	const char cccam[] = "CCcam";
	uint8 i;

	for (i = 0; i < 8; i++) {
		buf[8 + i] = i * buf[i];
		if (i <= 5) {
			buf[i] ^= cccam[i];
		}
	}
}

void cc_cw_crypt(uint8 *cws, uint32 cardid) {
	struct s_client *cl = &client[cs_idx];
	struct cc_data *cc = cl->cc;
	uint64 node_id;
	uint8 tmp;
	int i;

	if (!cl->is_server) {
		node_id = b2ll(8, cc->node_id);
	} else {
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
void cc_clear_auto_blocked(LLIST *cc_auto_blocked_list) {
	LLIST_ITR itr;
	struct cc_auto_blocked *auto_blocked = llist_itr_init(cc_auto_blocked_list,
			&itr);
	while (auto_blocked) {
		free(auto_blocked);
		auto_blocked = llist_itr_remove(&itr);
	}
}

void cc_free_auto_blocked(LLIST *cc_auto_blocked_list) {
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
int cc_remove_from_auto_blocked(LLIST *cc_auto_blocked_list,
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

int sid_eq(struct cc_srvid *srvid1, struct cc_srvid *srvid2) {
	return (srvid1->sid == srvid2->sid && srvid1->ecmlen == srvid2->ecmlen);
}

/**
 * reader
 * add caid:prov:sid to the autoblock list
 */
int cc_add_auto_blocked(LLIST *cc_auto_blocked_list, uint16 caid,
		uint32 prov, struct cc_srvid *srvid) {
	LLIST_ITR itr;
	struct cc_auto_blocked *auto_blocked = llist_itr_init(cc_auto_blocked_list,
			&itr);
	while (auto_blocked) {
		if (auto_blocked->caid == caid && auto_blocked->prov == prov && sid_eq(
				&auto_blocked->srvid, srvid)) {
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
	cs_debug_mask(D_TRACE, "%s adding %04X:%04X:%04X(%d) to auto block list",
			getprefix(), caid, prov, srvid->sid, srvid->ecmlen);
	return 1;
}

/**
 * reader
 * checks if caid:prov:sid is on the autoblock list
 */
int cc_is_auto_blocked(LLIST *cc_auto_blocked_list, uint16 caid,
		uint32 prov, struct cc_srvid *srvid, int timeout) {
	LLIST_ITR itr;
	struct cc_auto_blocked *auto_blocked = llist_itr_init(cc_auto_blocked_list,
			&itr);
	while (auto_blocked) {
		if (auto_blocked->caid == caid && auto_blocked->prov == prov && sid_eq(
				&auto_blocked->srvid, srvid)) {
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

int is_sid_blocked(struct cc_card *card, struct cc_srvid *srvid_blocked) {
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

int is_good_sid(struct cc_card *card, struct cc_srvid *srvid_good) {
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

void add_sid_block(struct cc_card *card, struct cc_srvid *srvid_blocked) {
	if (is_sid_blocked(card, srvid_blocked))
		return;

	struct cc_srvid *srvid = malloc(sizeof(struct cc_srvid));
	if (srvid) {
		*srvid = *srvid_blocked;
		llist_append(card->badsids, srvid);
		cs_debug_mask(D_TRACE, "%s added sid block %04X(%d) for card %08x",
				getprefix(), srvid_blocked->sid, srvid_blocked->ecmlen,
				card->id);
	}
}

void remove_sid_block(struct cc_card *card,
		struct cc_srvid *srvid_blocked) {
	LLIST_ITR sitr;
	struct cc_srvid *srvid = llist_itr_init(card->badsids, &sitr);
	while (srvid) {
		if (sid_eq(srvid, srvid_blocked)) {
			free(srvid);
			srvid = llist_itr_remove(&sitr);
		} else
			srvid = llist_itr_next(&sitr);
	}
}

void remove_good_sid(struct cc_card *card, struct cc_srvid *srvid_good) {
	LLIST_ITR sitr;
	struct cc_srvid *srvid = llist_itr_init(card->goodsids, &sitr);
	while (srvid) {
		if (sid_eq(srvid, srvid_good)) {
			free(srvid);
			srvid = llist_itr_remove(&sitr);
		} else
			srvid = llist_itr_next(&sitr);
	}
}

void add_good_sid(struct cc_card *card, struct cc_srvid *srvid_good) {
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

void free_current_cards(LLIST *current_cards) {
	LLIST_ITR itr;
	struct cc_current_card *c = llist_itr_init(current_cards, &itr);
	while (c) {
		free(c);
		c = llist_itr_remove(&itr);
	}
}

/**
 * reader
 * clears and frees values for reinit
 */
void cc_cli_close() {
	cs_debug_mask(D_FUT, "cc_cli_close in");
	struct s_client *cl = &client[cs_idx];
	struct s_reader *rdr = &reader[cl->ridx];
	rdr->tcp_connected = 0;
	rdr->card_status = NO_CARD;
	rdr->available = 0;
	rdr->card_system = 0;
	rdr->ncd_msgid = 0;
	rdr->last_s = reader->last_g = 0;

	//network_tcp_connection_close(rdr, cl->udp_fd); //Calls c_init, cc_cli_init -->recursive crash
	close(cl->udp_fd);
	cl->pfd = 0;
	cl->udp_fd = 0;

	struct cc_data *cc = cl->cc;
	if (cc) {
		//pthread_mutex_unlock(&cc->lock);
		//pthread_mutex_unlock(&cc->ecm_busy);
		//pthread_mutex_unlock(&cc->cards_busy);
		cc_clear_auto_blocked(cc->auto_blocked);
		cc->just_logged_in = 0;
		free_current_cards(cc->current_cards);
	}
	cs_debug_mask(D_FUT, "cc_cli_close out");
}

struct cc_extended_ecm_idx *add_extended_ecm_idx(uint8 send_idx,
		ushort ecm_idx, struct cc_card *card, struct cc_srvid srvid) {
	struct s_client *cl = &client[cs_idx];
	struct cc_data *cc = cl->cc;
	struct cc_extended_ecm_idx *eei =
			malloc(sizeof(struct cc_extended_ecm_idx));
	eei->send_idx = send_idx;
	eei->ecm_idx = ecm_idx;
	eei->card = card;
	eei->srvid = srvid;
	llist_append(cc->extended_ecm_idx, eei);
	//cs_debug_mask(D_TRACE, "%s add extended ecm-idx: %d:%d", getprefix(), send_idx, ecm_idx);
	return eei;
}

struct cc_extended_ecm_idx *get_extended_ecm_idx(uint8 send_idx,
		int remove) {
	struct s_client *cl = &client[cs_idx];
	struct cc_data *cc = cl->cc;
	struct cc_extended_ecm_idx *eei;
	LLIST_ITR itr;
	eei = llist_itr_init(cc->extended_ecm_idx, &itr);
	while (eei) {
		if (eei->send_idx == send_idx) {
			if (remove)
				llist_itr_remove(&itr);
			//cs_debug_mask(D_TRACE, "%s get by send-idx: %d FOUND: %d",
			//		getprefix(), send_idx, eei->ecm_idx);
			return eei;
		}
		eei = llist_itr_next(&itr);
	}
	cs_debug_mask(D_TRACE, "%s get by send-idx: %d NOT FOUND", getprefix(),
			send_idx);
	return NULL;
}

struct cc_extended_ecm_idx *get_extended_ecm_idx_by_idx(ushort ecm_idx,
		int remove) {
	struct s_client *cl = &client[cs_idx];
	struct cc_data *cc = cl->cc;
	struct cc_extended_ecm_idx *eei;
	LLIST_ITR itr;
	eei = llist_itr_init(cc->extended_ecm_idx, &itr);
	while (eei) {
		if (eei->ecm_idx == ecm_idx) {
			if (remove)
				llist_itr_remove(&itr);
			//cs_debug_mask(D_TRACE, "%s get by ecm-idx: %d FOUND: %d",
			//		getprefix(), ecm_idx, eei->send_idx);
			return eei;
		}
		eei = llist_itr_next(&itr);
	}
	cs_debug_mask(D_TRACE, "%s get by ecm-idx: %d NOT FOUND", getprefix(),
			ecm_idx);
	return NULL;
}

void free_extended_ecm_idx_by_card(struct cc_card *card) {
	struct s_client *cl = &client[cs_idx];
	struct cc_data *cc = cl->cc;
	struct cc_extended_ecm_idx *eei;
	LLIST_ITR itr;
	eei = llist_itr_init(cc->extended_ecm_idx, &itr);
	while (eei) {
		if (eei->card == card) {
			free(eei);
			eei = llist_itr_remove(&itr);
		} else
			eei = llist_itr_next(&itr);
	}
}

void free_extended_ecm_idx(struct cc_data *cc) {
	struct cc_extended_ecm_idx *eei;
	LLIST_ITR itr;
	eei = llist_itr_init(cc->extended_ecm_idx, &itr);
	while (eei) {
		free(eei);
		eei = llist_itr_remove(&itr);
	}
}

/**
 * reader
 * closes the connection and reopens it.
 */
//static void cc_cycle_connection() {
//	cc_cli_close();
//	cc_cli_init_int();
//}

/**
 * reader+server:
 * receive a message
 */
int cc_msg_recv(uint8 *buf) {
	struct s_client *cl = &client[cs_idx];
	struct s_reader *rdr = cl->is_server?NULL:&reader[cl->ridx];
	
	int len;
	uint8 netbuf[CC_MAXMSGSIZE + 4];
	struct cc_data *cc = cl->cc;

	int handle = cl->udp_fd;

	if (handle < 0)
		return -1;

	len = recv(handle, netbuf, 4, MSG_WAITALL);
	if (!cl->is_server)
		rdr->last_g = time(NULL);

	if (!len)
		return 0;

	if (len != 4) { // invalid header length read
		cs_log("%s invalid header length (expected 4, read %d)", getprefix(),
				len);
		return -1;
	}

	cc_crypt(&cc->block[DECRYPT], netbuf, 4, DECRYPT);
	cs_ddump(netbuf, 4, "cccam: decrypted header:");

	cc->g_flag = netbuf[0];

	int size = (netbuf[2] << 8) | netbuf[3];
	if (size) { // check if any data is expected in msg
		if (size > CC_MAXMSGSIZE - 2) {
			cs_log("%s message too big (size=%d)", getprefix(), size);
			return 0;
		}

		len = recv(handle, netbuf + 4, size, MSG_WAITALL); // read rest of msg
		if (!cl->is_server)
			rdr->last_g = time(NULL);

		if (len != size) {
			cs_log("%s invalid message length read (expected %d, read %d)",
					getprefix(), size, len);
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
int cc_cmd_send(uint8 *buf, int len, cc_msg_type_t cmd) {
	struct s_client *cl = &client[cs_idx];
	struct s_reader *rdr = cl->is_server?NULL:&reader[cl->ridx];
	
	int n;
	uint8 netbuf[len + 4];
	struct cc_data *cc = cl->cc;

	memset(netbuf, 0, len + 4);

	if (cmd == MSG_NO_HEADER) {
		memcpy(netbuf, buf, len);
	} else {
		// build command message
		netbuf[0] = cc->g_flag; // flags??
		netbuf[1] = cmd & 0xff;
		netbuf[2] = len >> 8;
		netbuf[3] = len & 0xff;
		if (buf)
			memcpy(netbuf + 4, buf, len);
		len += 4;
	}

	cs_ddump(netbuf, len, "cccam: send:");
	cc_crypt(&cc->block[ENCRYPT], netbuf, len, ENCRYPT);

	n = send(cl->udp_fd, netbuf, len, 0);
	if (!cl->is_server)
		rdr->last_s = time(NULL);

	if (n != len) {
		if (cl->is_server)
			cs_disconnect_client();
		else
			cc_cli_close();
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
void cc_check_version(char *cc_version, char *cc_build) {
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
int cc_send_cli_data() {
	struct s_client *cl = &client[cs_idx];
	struct s_reader *rdr = &reader[cl->ridx];
	
	int i;
	struct cc_data *cc = cl->cc;

	cs_debug("cccam: send client data");

	seed = (unsigned int) time((time_t*) 0);
	for (i = 0; i < 8; i++)
		cc->node_id[i] = fast_rnd();

	uint8 buf[CC_MAXMSGSIZE];
	memset(buf, 0, CC_MAXMSGSIZE);

	memcpy(buf, rdr->r_usr, sizeof(rdr->r_usr));
	memcpy(buf + 20, cc->node_id, 8);
	buf[28] = rdr->cc_want_emu; // <-- Client want to have EMUs, 0 - NO; 1 - YES
	memcpy(buf + 29, rdr->cc_version, sizeof(rdr->cc_version)); // cccam version (ascii)
	memcpy(buf + 61, rdr->cc_build, sizeof(rdr->cc_build)); // build number (ascii)

	cs_log("%s sending own version: %s, build: %s", getprefix(),
			rdr->cc_version, rdr->cc_build);

	i = cc_cmd_send(buf, 20 + 8 + 6 + 26 + 4 + 28 + 1, MSG_CLI_DATA);

	return i;
}

/**
 * server
 * sends version information to the client
 */
int cc_send_srv_data() {
	struct s_client *cl = &client[cs_idx];
	struct s_reader *rdr = &reader[cl->ridx];
	int i;
	struct cc_data *cc = cl->cc;

	cs_debug("cccam: send server data");

	seed = (unsigned int) time((time_t*) 0);
	for (i = 0; i < 8; i++)
		cc->node_id[i] = fast_rnd();

	uint8 buf[CC_MAXMSGSIZE];
	memset(buf, 0, CC_MAXMSGSIZE);

	memcpy(buf, cc->node_id, 8);
	cc_check_version((char *) cfg->cc_version, rdr->cc_build);
	memcpy(buf + 8, cfg->cc_version, sizeof(rdr->cc_version)); // cccam version (ascii)
	memcpy(buf + 40, rdr->cc_build, sizeof(rdr->cc_build)); // build number (ascii)

	cs_log("%s version: %s, build: %s nodeid: %s", getprefix(),
			cfg->cc_version, rdr->cc_build, cs_hexdump(0,
					cc->peer_node_id, 8));

	return cc_cmd_send(buf, 0x48, MSG_SRV_DATA);
}

/**
 * reader
 * retrieves the next waiting ecm request
 */
int cc_get_nxt_ecm() {
	struct s_client *cl = &client[cs_idx];
	int n, i;
	time_t t;

	t = time(NULL);
	n = -1;
	for (i = 0; i < CS_MAXPENDING; i++) {
		if ((t - (ulong) cl->ecmtask[i].tps.time > ((cfg->ctimeout + 500) / 1000)
				+ 1) && (cl->ecmtask[i].rc >= 10)) // drop timeouts
		{
			cl->ecmtask[i].rc = 0;
		}

		if (cl->ecmtask[i].rc >= 10 && cl->ecmtask[i].rc != 101) { // stil active and waiting
			// search for the ecm with the lowest time, this should be the next to go
			if ((n < 0 || cl->ecmtask[n].tps.time - cl->ecmtask[i].tps.time < 0)
					&& &cl->ecmtask[n])
				n = i;
		}
	}
	return n;
}

/**
 * sends the secret cmd05 answer to the server 
 */
int send_cmd05_answer() {
	struct s_client *cl = &client[cs_idx];
	struct s_reader *rdr = &reader[cl->ridx];
	struct cc_data *cc = cl->cc;
	if (!cc->cmd05_active || !rdr->available) //exit if not in cmd05 or waiting for ECM answer
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
			for (i = 0; i < 256; i += 16)
				AES_encrypt((unsigned char *) data + i, (unsigned char *) &out
						+ i, &key);

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
	cs_debug_mask(D_TRACE, "%s sending CMD_05 back! MODE: %s len=%d",
			getprefix(), cmd05_mode_name[cmd05_mode], cc->cmd05_data_len);

	return 1;
}

struct cc_current_card *cc_find_current_card(struct cc_data *cc,
		struct cc_card *card) {
	LLIST_ITR itr;
	struct cc_current_card *c = llist_itr_init(cc->current_cards, &itr);
	while (c) {
		if (c->card == card)
			return c;
		c = llist_itr_next(&itr);
	}
	return NULL;
}

struct cc_current_card *cc_find_current_card_by_srvid(
		struct cc_data *cc, ushort caid, ulong prov, struct cc_srvid *srvid) {
	LLIST_ITR itr;
	struct cc_current_card *c = llist_itr_init(cc->current_cards, &itr);
	while (c) {
		if (c->card->caid == caid && c->prov == prov
				&& sid_eq(&c->srvid, srvid))
			return c;
		c = llist_itr_next(&itr);
	}
	return NULL;
}

void cc_remove_current_card(struct cc_data *cc,
		struct cc_current_card *current_card) {
	LLIST_ITR itr;
	struct cc_current_card *c = llist_itr_init(cc->current_cards, &itr);
	while (c) {
		if (c == current_card) {
			free(c);
			c = llist_itr_remove(&itr);
		} else
			c = llist_itr_next(&itr);
	}

}

void cc_UA_oscam2cccam(uint8 *in, uint8 *out) {
	out[7] = in[5];
	out[6] = in[4];
	out[5] = in[3];
	out[4] = in[2];
	out[3] = 0;//in[1];
	out[2] = 0;//in[0];
	out[1] = 0;//in[7];
	out[0] = 0;//in[6];
}

void cc_UA_cccam2oscam(uint8 *in, uint8 *out) {
	out[5] = in[7];
	out[4] = in[6];
	out[3] = in[5];
	out[2] = in[4];
	out[1] = in[3];
	out[0] = in[2];
	out[7] = in[1];
	out[6] = in[0];
}

void cc_SA_oscam2cccam(uint8 *in, uint8 *out) {
	out[0] = in[3];
	out[1] = 0;
	out[2] = 0;
	out[3] = 0;
}

void cc_SA_cccam2oscam(uint8 *in, uint8 *out) {
	out[0] = 0;
	out[1] = 0;
	out[2] = 0;
	out[3] = in[3];
}

int cc_UA_valid(uint8 *ua) {
	int i;
	for (i = 0; i < 8; i++)
		if (ua[i])
			return 1;
	return 0;
}

/**
 * reader
 * sends a ecm request to the connected CCCam Server
 */
int cc_send_ecm(ECM_REQUEST *er, uchar *buf) {
	cs_debug_mask(D_FUT, "cc_send_ecm in");
	struct s_client *cl = &client[cs_idx];
	struct s_reader *rdr = &reader[cl->ridx];
	
	//cs_debug_mask(D_TRACE, "%s cc_send_ecm", getprefix());
	cc_cli_init_int();
	
	int n, h = -1;
	struct cc_data *cc = cl->cc;
	struct cc_card *card;
	struct cc_current_card *current_card;
	LLIST_ITR itr;
	ECM_REQUEST *cur_er;
	struct timeb cur_time;
	cs_ftime(&cur_time);

	if (!cc || (cl->pfd < 1) || !rdr->tcp_connected) {
		if (er) {
			er->rc = 0;
			er->rcEx = 0x27;
			cs_debug_mask(D_TRACE, "%s server not init! ccinit=%d pfd=%d",
					getprefix(), cc ? 1 : 0, cl->pfd);
			write_ecm_answer(rdr, client[0].fd_m2c, er);
		}
		cc_cli_close();
		cs_debug_mask(D_FUT, "cc_send_ecm out");
		return 0;
	}

	if (rdr->tcp_connected != 2) {
		cs_debug_mask(D_TRACE, "%s Waiting for CARDS", getprefix());
		return 0;
	}

	//No Card? Waiting for shares
	if (!llist_count(cc->cards)) {
		rdr->fd_error++;
		cs_debug_mask(D_TRACE, "%s NO CARDS!", getprefix());
		return 0;
	}

	cc->just_logged_in = 0;

	if (!cc->extended_mode) {
		//Without extended mode, only one ecm at a time could be send
		//this is a limitation of "O" CCCam
		if (pthread_mutex_trylock(&cc->ecm_busy) == EBUSY) { //Unlock by NOK or ECM ACK
			cs_debug_mask(
					D_TRACE,
					"%s ecm trylock: ecm busy, retrying later after msg-receive",
					getprefix());

			struct timeb timeout;
			timeout = cc->ecm_time;
			timeout.millitm += cfg->ctimeout * 4;
			timeout.time += timeout.millitm / 1000;
			timeout.millitm = timeout.millitm % 1000;

			if (comp_timeb(&cur_time, &timeout) < 0) { //TODO: Configuration?
				return 0; //pending send...
			} else {
				cs_debug_mask(D_TRACE,
						"%s unlocked-cycleconnection! timeout %ds",
						getprefix(), cfg->ctimeout * 4 / 1000);
				//cc_cycle_connection();
				cc_cli_close();
				cs_debug_mask(D_FUT, "cc_send_ecm out");
				return 0;
			}
		}
		cs_debug("cccam: ecm trylock: got lock");
	}
	cc->ecm_time = cur_time;
	rdr->available = cc->extended_mode;

	//Search next ECM to send:
	if ((n = cc_get_nxt_ecm()) < 0) {
		if (!cc->extended_mode) {
			rdr->available = 1;
			pthread_mutex_unlock(&cc->ecm_busy);
		}
		cs_debug("%s no ecm pending!", getprefix());
		if (!cc_send_pending_emms())
			send_cmd05_answer();
		cs_debug_mask(D_FUT, "cc_send_ecm out");
		return 0; // no queued ecms
	}
	cur_er = &cl->ecmtask[n];
	cur_er->rc = 101; //mark ECM as already send
	cs_debug("cccam: ecm-task %d", cur_er->idx);

	if (buf)
		memcpy(buf, cur_er->ecm, cur_er->l);

	struct cc_srvid cur_srvid;
	cur_srvid.sid = cur_er->srvid;
	cur_srvid.ecmlen = cur_er->l;

	pthread_mutex_lock(&cc->cards_busy);
	//search cache:
	current_card = cc_find_current_card_by_srvid(cc, cur_er->caid,
			cur_er->prid, &cur_srvid);
	if (current_card) {
		if (!current_card->card || is_sid_blocked(current_card->card,
				&cur_srvid)) {
			cc_remove_current_card(cc, current_card);
			current_card = NULL;
		}
	}
	if (current_card)
		card = current_card->card;
	else
		card = NULL;

	//then check all other cards
	int is_auto_blocked = 0;
	if (!card) {
		//check if auto blocked:
		if (!rdr->cc_disable_auto_block && cc_is_auto_blocked(
				cc->auto_blocked, cur_er->caid, cur_er->prid, &cur_srvid, 60
						* 60 * 1)) { //TODO: Timeout 60*60*1 = 1h, Config?
			is_auto_blocked = 1;
		} else {
			struct cc_card *ncard = llist_itr_init(cc->cards, &itr);
			while (ncard) {
				if (ncard->caid == cur_er->caid) { // caid matches
					int s = is_sid_blocked(ncard, &cur_srvid);

					LLIST_ITR pitr;
					struct cc_provider *provider = llist_itr_init(
							ncard->providers, &pitr);
					while (provider && !s) {
						if (!cur_er->prid || !provider->prov || provider->prov
								== cur_er->prid) { // provid matches
							if (h < 0 || ncard->hop < h || (ncard->hop == h
									&& cc_UA_valid(ncard->hexserial))) {
								// ncard is closer
								card = ncard;
								h = ncard->hop; // ncard has been matched
							}
						}
						provider = llist_itr_next(&pitr);
					}
				}
				ncard = llist_itr_next(&itr);
			}
		}
	}

	if (card) {
		if (!current_card) {
			current_card = malloc(sizeof(struct cc_current_card));
			current_card->card = card;
			current_card->prov = cur_er->prid;
			current_card->srvid = cur_srvid;
			llist_insert_first(cc->current_cards, current_card);
		}

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

		uint8 send_idx = 1;
		if (cc->extended_mode) {
			cc->server_ecm_idx++;
			if (cc->server_ecm_idx >= 256)
				cc->server_ecm_idx = 1;
			cc->g_flag = cc->server_ecm_idx; //Flag is used as index!
			send_idx = cc->g_flag;
		}

		add_extended_ecm_idx(send_idx, cur_er->idx, card, cur_srvid);

		rdr->cc_currenthops = card->hop;

		cs_log(
				"%s sending ecm for sid %04X(%d) to card %08x, hop %d, ecmtask %d",
				getprefix(), cur_er->srvid, cur_er->l, card->id, card->hop,
				cur_er->idx);
		cc_cmd_send(ecmbuf, cur_er->l + 13, MSG_CW_ECM); // send ecm

		//For EMM
		if (!rdr->audisabled) {
			rdr->card_system = get_cardsystem(card->caid);
			cc_UA_cccam2oscam(card->hexserial, rdr->hexserial);

			rdr->nprov = 0;
			LLIST_ITR pitr;
			struct cc_provider *provider = llist_itr_init(card->providers,
					&pitr);
			while (provider) {
				if (provider->prov == cur_er->prid) {
					memcpy(&rdr->prid[0], &provider->prov,
							sizeof(provider->prov));
					cc_SA_cccam2oscam(provider->sa, rdr->sa[0]);
					rdr->nprov = 1;
					break;
				}
				provider = llist_itr_next(&pitr);
			}
			char saprov[20] = { 0 };
			if (provider)
				sprintf(saprov, "%06lX:%02X%02X%02X%02X", provider->prov,
						provider->sa[0], provider->sa[1], provider->sa[2],
						provider->sa[3]);
			cs_debug_mask(D_EMM,
					"%s au info: caid %04X card system: %d UA: %s SA: %s",
					getprefix(), card->caid, rdr->card_system,
					cs_hexdump(0, rdr->hexserial, 8), saprov);
		}
		pthread_mutex_unlock(&cc->cards_busy);
		cs_debug_mask(D_FUT, "cc_send_ecm out");
		return 0;
	} else {
		//When connecting, it could happen than ecm requests come before all cards are received.
		//So if the last Message was a MSG_NEW_CARD, this "card receiving" is not already done
		//if this happens, we do not autoblock it and do not set rc status
		//So fallback could resolve it
		if (cc->last_msg != MSG_NEW_CARD && !cc->just_logged_in) {
			if (is_auto_blocked)
				cs_log("%s no suitable card on server (auto blocked)",
						getprefix());
			else
				cs_log("%s no suitable card on server", getprefix());

			cur_er->rc = 0;
			cur_er->rcEx = 0x27;
			write_ecm_answer(rdr, client[0].fd_m2c, cur_er);
			//cur_er->rc = 1;
			//cur_er->rcEx = 0;
			//cs_sleepms(300);
			rdr->last_s = rdr->last_g;

			card = llist_itr_init(cc->cards, &itr);
			while (card) {
				if (card->caid == cur_er->caid) { // caid matches
					LLIST_ITR sitr;
					struct cc_srvid *srvid = llist_itr_init(card->badsids,
							&sitr);
					while (srvid) {
						if (sid_eq(srvid, &cur_srvid)) {
							free(srvid);
							srvid = llist_itr_remove(&sitr);
						} else
							srvid = llist_itr_next(&sitr);
					}
				}
				card = llist_itr_next(&itr);
			}

			if (!rdr->cc_disable_auto_block) {
				cc_add_auto_blocked(cc->auto_blocked, cur_er->caid,
						cur_er->prid, &cur_srvid);
			}
		}
		pthread_mutex_unlock(&cc->cards_busy);
		if (!cc->extended_mode) {
			rdr->available = 1;
			pthread_mutex_unlock(&cc->ecm_busy);
		}
		cs_debug_mask(D_FUT, "cc_send_ecm out");
		return -1;
	}
}

/*
 int cc_abort_user_ecms(){
 int n, i;
 time_t t;//, tls;
 struct cc_data *cc = rdr->cc;

 t=time((time_t *)0);
 for (i=1,n=1; i<CS_MAXPENDING; i++)
 {
 if ((t-cl->ecmtask[i].tps.time > ((cfg->ctimeout + 500) / 1000) + 1) &&
 (cl->ecmtask[i].rc>=10))      // drop timeouts
 {
 cl->ecmtask[i].rc=0;
 }
 int td=abs(1000*(ecmtask[i].tps.time-cc->found->tps.time)+ecmtask[i].tps.millitm-cc->found->tps.millitm);
 if (ecmtask[i].rc>=10 && ecmtask[i].cidx==cc->found->cidx && &ecmtask[i]!=cc->found){
 cs_log("aborting idx:%d caid:%04x client:%d timedelta:%d",ecmtask[i].idx,ecmtask[i].caid,ecmtask[i].cidx,td);
 ecmtask[i].rc=0;
 ecmtask[i].rcEx=7;
 write_ecm_answer(rdr, fd_c2m, &ecmtask[i]);
 }
 }
 return n;

 }
 */

int cc_send_pending_emms() {
	cs_debug_mask(D_FUT, "cc_send_pending_emms in");
	struct s_client *cl = &client[cs_idx];
	struct s_reader *rdr = &reader[cl->ridx];
	struct cc_data *cc = cl->cc;

	LLIST_ITR itr;
	uint8 *emmbuf = llist_itr_init(cc->pending_emms, &itr);
	if (emmbuf) {
		if (!cc->extended_mode) {
			if (pthread_mutex_trylock(&cc->ecm_busy) == EBUSY) { //Unlock by NOK or ECM ACK
				return 0; //send later with cc_send_ecm
			}
			rdr->available = 0;
		}
		int size = emmbuf[11] + 12;

		cc->just_logged_in = 0;
		cs_ftime(&cc->ecm_time);

		cs_debug_mask(D_EMM, "%s emm send for card %08X", getprefix(), b2i(4,
				emmbuf + 7));

		cc_cmd_send(emmbuf, size, MSG_EMM_ACK); // send emm
		free(emmbuf);
		llist_itr_remove(&itr);
		return size;
	}
	cs_debug_mask(D_FUT, "cc_send_pending_emms out");
	return 0;
}

/**
 * READER only:
 * find card by hexserial
 * */
struct cc_card *get_card_by_hexserial(uint8 *hexserial, uint16 caid) {
	struct s_client *cl = &client[cs_idx];
	struct cc_data *cc = cl->cc;
	LLIST_ITR itr;
	struct cc_card *card = llist_itr_init(cc->cards, &itr);
	while (card) {
		if (card->caid == caid && memcmp(card->hexserial, hexserial, 8) == 0) { //found it!
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
int cc_send_emm(EMM_PACKET *ep) {
	cs_debug_mask(D_FUT, "cc_send_emm in");
	struct s_client *cl = &client[cs_idx];
	struct s_reader *rdr = &reader[cl->ridx];
	
	cc_cli_init_int();

	struct cc_data *cc = cl->cc;

	if (!cc || (cl->pfd < 1) || !rdr->tcp_connected) {
		cs_log("%s server not init! ccinit=%d pfd=%d", getprefix(), cc ? 1 : 0,
				cl->pfd);
		return 0;
	}
	if (rdr->audisabled) {
		cs_log("%s au is disabled", getprefix());
		return 0;
	}

	ushort caid = b2i(2, ep->caid);

	//Last used card is first card of current_cards:
	pthread_mutex_lock(&cc->cards_busy);
	LLIST_ITR itr;
	struct cc_current_card *current_card = llist_itr_init(cc->current_cards,
			&itr);
	while (current_card && current_card->card->caid != caid) {
		current_card = llist_itr_next(&itr);
	}
	struct cc_card *emm_card = (current_card != NULL) ? current_card->card
			: NULL;

	if (!emm_card || emm_card->caid != caid) {
		uint8 hs[8];
		cc_UA_oscam2cccam(ep->hexserial, hs);
		emm_card = get_card_by_hexserial(hs, caid);
	}

	if (!emm_card) { //Card for emm not found!
		cs_log("%s emm for client %d not possible, no card found!",
				getprefix(), ep->cidx);
		pthread_mutex_unlock(&cc->cards_busy);
		return 0;
	}

	cs_debug_mask(D_EMM,
			"%s emm received for client %d caid %04X for card %08X",
			getprefix(), ep->cidx, caid, emm_card->id);

	int size = ep->l + 12;
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

	pthread_mutex_unlock(&cc->cards_busy);

	llist_append(cc->pending_emms, emmbuf);
	cc_send_pending_emms();
	
	cs_debug_mask(D_FUT, "cc_send_emm out");
	return 1;
}

void cc_free_card(struct cc_card *card) {
	if (!card)
		return;

	if (card->providers) {
		LLIST_ITR bitr;
		struct cc_provider *provider = llist_itr_init(card->providers, &bitr);
		while (provider) {
			free(provider);
			provider = llist_itr_remove(&bitr);
		}
		llist_destroy(card->providers);
	}
	if (card->badsids)
		llist_destroy(card->badsids);
	if (card->goodsids)
		llist_destroy(card->goodsids);
	free(card);
}

/**
 * Server:
 * Adds a cccam-carddata buffer to the list of reported carddatas
 */
void cc_add_reported_carddata(LLIST *reported_carddatas, uint8 *buf,
		int len, struct s_reader *rdr) {
	struct cc_reported_carddata *carddata = malloc(
			sizeof(struct cc_reported_carddata));
	uint8 *buf_copy = malloc(len);
	memcpy(buf_copy, buf, len);
	carddata->buf = buf_copy;
	carddata->len = len;
	llist_append(reported_carddatas, carddata);

	cs_debug_mask(
			D_EMM,
			"%s:%s reported card %d CAID %04X UA: %02X%02X%02X%02X%02X%02X%02X%02X",
			getprefix(),
			rdr->label, //label
			b2i(4, buf), //card-id
			b2i(2, buf + 8), //CAID
			buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18],
			buf[19]); //UA
	int i;
	for (i = 0; i < buf[20]; i++) {
		int ofs = 21 + i * 7;
		cs_debug_mask(D_EMM, "   provider: %02X%02X%02X SA: %02X%02X%02X%02X",
				buf[ofs], buf[ofs + 1], buf[ofs + 2], buf[ofs + 3],
				buf[ofs + 4], buf[ofs + 5], buf[ofs + 6]);
	}
}

void cc_clear_reported_carddata(LLIST *reported_carddatas,
		int send_removed) {
	LLIST_ITR itr;
	struct cc_reported_carddata *carddata = llist_itr_init(reported_carddatas,
			&itr);
	while (carddata) {
		if (send_removed)
			cc_cmd_send(carddata->buf, 4, MSG_CARD_REMOVED);
		free(carddata->buf);
		free(carddata);
		carddata = llist_itr_remove(&itr);
	}

}

void cc_free_reported_carddata(LLIST *reported_carddatas,
		int send_removed) {
	if (reported_carddatas) {
		cc_clear_reported_carddata(reported_carddatas, send_removed);
		llist_destroy(reported_carddatas);
	}
}

void cc_free_cardlist(LLIST *card_list) {
	if (card_list) {
		LLIST_ITR itr;
		struct cc_card *card = llist_itr_init(card_list, &itr);
		while (card) {
			cc_free_card(card);
			card = llist_itr_remove(&itr);
		}
		llist_destroy(card_list);
	}
}
/**
 * Clears and free the cc datas
 */
void cc_free(struct cc_data *cc) {
	if (!cc)
		return;

	cs_debug_mask(D_FUT, "cc_free in");
	cc_free_cardlist(cc->cards);
	cc_free_reported_carddata(cc->reported_carddatas, 0);
	cc_free_auto_blocked(cc->auto_blocked);
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
	if (cc->current_cards) {
		free_current_cards(cc->current_cards);
		llist_destroy(cc->current_cards);
	}
	if (cc->extended_ecm_idx)
		free_extended_ecm_idx(cc);
	pthread_mutex_destroy(&cc->lock);
	pthread_mutex_destroy(&cc->ecm_busy);
	pthread_mutex_destroy(&cc->cards_busy);
	free(cc->prefix);
	free(cc);
	cs_debug_mask(D_FUT, "cc_free out");
}

int is_null_dcw(uint8 *dcw) {
	int i;
	for (i = 0; i < 15; i++)
		if (dcw[i])
			return 0;
	return 1;
}

/*int is_dcw_corrupted(uchar *dcw)
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

 void fix_dcw(uchar *dcw)
 {
 int i;
 for (i=0; i<16; i+=4)
 {
 dcw[i+3] = (dcw[i] + dcw[i+1] + dcw[i+2]) & 0xFF;
 }
 }*/

int check_extended_mode(char *msg) {
	struct s_client *cl = &client[cs_idx];
	//Extended mode: if PARTNER String is ending with [EXT], extended mode is activated
	//For future compatibilty the syntax should be compatible with
	//[PARAM1,PARAM2...PARAMn]
	//
	// EXT: Extended ECM Mode: Multiple ECMs could be send and received
	//                         ECMs are numbered, Flag (byte[0] is the index

	struct cc_data *cc = cl->cc;
	int has_param = 0;
	char *p = strtok(msg, "[");
	while (p) {
		p = strtok(NULL, ",]");
		if (p && strncmp(p, "EXT", 3) == 0) {
			cc->extended_mode = 1;
			cl->cc_extended_ecm_mode = 1;
			cs_log("%s extended ECM mode", getprefix());
			has_param = 1;
		}
	}
	return has_param;
}

void cc_idle() {
	cs_debug_mask(D_FUT, "cc_idle in");
	struct s_client *cl = &client[cs_idx];
	struct s_reader *rdr = &reader[cl->ridx];
	struct cc_data *cc = cl->cc;
	if (!rdr->tcp_connected)
		return;

	if (rdr->cc_keepalive && cc->answer_on_keepalive + 55 < time(NULL)) {
		cc_cmd_send(NULL, 0, MSG_KEEPALIVE);
		cs_debug("cccam: keepalive");
		cc->answer_on_keepalive = time(NULL);
	}
	cs_debug_mask(D_FUT, "cc_idle out");
}

struct cc_card *read_card(uint8 *buf) {
	struct cc_card *card = malloc(sizeof(struct cc_card));
	memset(card, 0, sizeof(struct cc_card));

	card->providers = llist_create();
	card->badsids = llist_create();
	card->goodsids = llist_create();
	card->id = b2i(4, buf);
	card->remote_id = b2i(3, buf + 5);
	card->caid = b2i(2, buf + 8);
	card->hop = buf[10];
	card->maxdown = buf[11];
	memcpy(card->hexserial, buf + 12, 8); //HEXSERIAL!!

	//cs_debug("cccam: card %08x added, caid %04X, hop %d, key %s, count %d",
	//		card->id, card->caid, card->hop, cs_hexdump(0, card->hexserial, 8),
	//		llist_count(cc->cards));

	int i;
	for (i = 0; i < buf[20]; i++) { // providers
		struct cc_provider *prov = malloc(sizeof(struct cc_provider));
		if (prov) {
			prov->prov = b2i(3, buf + 21 + (7 * i));
			memcpy(prov->sa, buf + 21 + (7 * i) + 3, 4);
			cs_debug("      prov %d, %06x, sa %08x", i + 1, prov->prov, b2i(4,
					prov->sa));

			llist_append(card->providers, prov);
		}
	}
	return card;
}

#define READ_CARD_TIMEOUT 100

int write_card(struct cc_data *cc, uint8 *buf, struct cc_card *card) {
	memset(buf, 0, CC_MAXMSGSIZE);
	buf[0] = card->id >> 24;
	buf[1] = card->id >> 16;
	buf[2] = card->id >> 8;
	buf[3] = card->id & 0xff;
	buf[5] = card->remote_id >> 16;
	buf[6] = card->remote_id >> 8;
	buf[7] = card->remote_id & 0xFF;
	buf[8] = card->caid >> 8;
	buf[9] = card->caid & 0xff;
	buf[10] = card->hop;
	buf[11] = card->maxdown;
	memcpy(buf + 12, card->hexserial, 8);
	int j = 0;
	LLIST_ITR itr_prov;
	struct cc_provider *prov = llist_itr_init(card->providers, &itr_prov);
	while (prov) {
		ulong prid = prov->prov;
		buf[21 + (j * 7)] = prid >> 16;
		buf[22 + (j * 7)] = prid >> 8;
		buf[23 + (j * 7)] = prid & 0xFF;
		memcpy(buf + 24 + (j * 7), prov->sa, 4);
		prov = llist_itr_next(&itr_prov);
		j++;
	}
	buf[20] = j;

	buf[21 + (j * 7)] = 1;
	memcpy(buf + 22 + (j * 7), cc->node_id, 8);

	return 30 + (j * 7);
}

void cc_card_removed(uint32 shareid) {
	struct s_client *cl = &client[cs_idx];
	struct cc_data *cc = cl->cc;
	struct cc_card *card;
	LLIST_ITR itr;

	pthread_mutex_lock(&cc->cards_busy);
	card = llist_itr_init(cc->cards, &itr);
	while (card) {
		if (card->id == shareid) {// && card->sub_id == b2i (3, buf + 9)) {
			//cs_debug("cccam: card %08x removed, caid %04X, count %d",
			//		card->id, card->caid, llist_count(cc->cards));
			struct cc_card *next_card = llist_itr_remove(&itr);
			struct cc_current_card *current_card;
			while ((current_card = cc_find_current_card(cc, card))) {
				cs_debug_mask(D_TRACE, "%s current card %08x removed!",
						getprefix(), card->id);
				cc_remove_current_card(cc, current_card);
			}
			free_extended_ecm_idx_by_card(card);
			cc_free_card(card);
			card = next_card;
			cc->cards_modified++;
			//break;
		} else {
			card = llist_itr_next(&itr);
		}
	}
	pthread_mutex_unlock(&cc->cards_busy);
}

int cc_parse_msg(uint8 *buf, int l) {
	cs_debug_mask(D_FUT, "cc_parse_msg in %d", buf[1]);
	struct s_client *cl = &client[cs_idx];
	struct s_reader *rdr = cl->is_server?NULL:&reader[cl->ridx];
	
	int ret = buf[1];
	struct cc_data *cc = cl->cc;

	cs_debug("%s parse_msg=%d", getprefix(), buf[1]);

	uint8 *data = buf + 4;
	memcpy(&cc->receive_buffer, data, l - 4);
	cc->last_msg = buf[1];
	switch (buf[1]) {
	case MSG_CLI_DATA:
		cs_debug("cccam: client data ack");
		break;
	case MSG_SRV_DATA:
		l -= 4;
		cs_log("%s MSG_SRV_DATA (payload=%d, hex=%02X)", getprefix(), l, l);
		data = (uint8*) &cc->receive_buffer;

		if (l == 0x48) { //72 bytes: normal server data
			memcpy(cc->peer_node_id, data, 8);
			memcpy(cc->peer_version, data + 8, 8);

			memcpy(cc->cmd0b_aeskey, cc->peer_node_id, 8);
			memcpy(cc->cmd0b_aeskey + 8, cc->peer_version, 8);
			cs_log("%s srv %s running v%s (%s)", getprefix(), cs_hexdump(0,
					cc->peer_node_id, 8), data + 8, data + 40);
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
			memcpy(cc->cmd05_aeskey, data + cc->cmd05_offset, 16);
			cc->cmd05_mode = MODE_AES;
			//
			//33 bytes: xor-algo mit payload-bytes, offset keyoffset
			//
		} else if (l == 0x21) {
			cc_init_crypt(&cc->cmd05_cryptkey, data + cc->cmd05_offset, l);
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
			//cycle_connection(); //Absolute unknown handling!
			cc_cli_close();
			//
			//44 bytes: set aes128 key, Key=16 bytes [Offset=len(password)]
			//
		} else if (l == 0x2c) {
			memcpy(cc->cmd05_aeskey, data + strlen(rdr->r_pwd), 16);
			cc->cmd05_mode = MODE_AES;
			//
			//45 bytes: set aes128 key, Key=16 bytes [Offset=len(username)]
			//
		} else if (l == 0x2d) {
			memcpy(cc->cmd05_aeskey, data + strlen(rdr->r_usr), 16);
			cc->cmd05_mode = MODE_AES;
			//
			//Unknown!!
			//
		} else {
			cs_log(
					"%s received improper MSG_SRV_DATA! No change to current mode, mode=%d",
					getprefix(), cc->cmd05_mode);
			break;
		}
		cs_debug_mask(D_TRACE, "%s MSG_SRV_DATA MODE=%s, len=%d", getprefix(),
				cmd05_mode_name[cc->cmd05_mode], l);

		break;
	case MSG_NEW_CARD: {
		if (buf[14] >= rdr->cc_maxhop)
			break;

		if (!chk_ctab(b2i(2, buf + 12), &rdr->ctab))
			break;

		rdr->tcp_connected = 2; //we have card
		rdr->card_status = CARD_INSERTED;

		pthread_mutex_lock(&cc->cards_busy);

		struct cc_card *card = read_card(buf + 4);
		
		card->hop++; //inkrementing hop

		//SS: Hack:
		//Check if we already have this card:
		LLIST_ITR itr;
		struct cc_card *old_card = llist_itr_init(cc->cards, &itr);
		while (old_card) {
			if (old_card->id == card->id) { //we aready have this card, delete it
				cc_free_card(card);
				card = old_card;
				break;
			}
			old_card = llist_itr_next(&itr);
		}

		card->time = time((time_t) 0);
		if (!old_card)
			llist_append(cc->cards, card);

		struct cc_provider *prov = llist_itr_init(card->providers, &itr);
		while (prov) {
			cc_remove_from_auto_blocked(cc->auto_blocked, card->caid,
					prov->prov);
			prov = llist_itr_next(&itr);
		}
		cc->cards_modified++;

		pthread_mutex_unlock(&cc->cards_busy);
		//SS: Hack end
	}
	break;

	case MSG_CARD_REMOVED: {
		cc_card_removed(b2i(4, buf + 4));
	}
	break;

	case MSG_CW_NOK1:
	case MSG_CW_NOK2:
		if (l > 4) {
			//Received NOK with payload:
			char *msg = (char*) buf + 4;
			cs_log("%s %s", getprefix(), msg);

			//Check for PARTNER connection:
			if (!cc->is_oscam_cccam && strncmp(msg, "PARTNER:", 8) == 0) {
				//When Data starts with "PARTNER:" we have an Oscam-cccam-compatible client/server!
				cc->is_oscam_cccam = 1;

				int has_param = check_extended_mode(msg);

				//send params back. At the moment there is only "EXT"
				char param[10];
				if (!has_param)
					param[0] = 0;
				else {
					strcpy(param, " [");
					if (cc->extended_mode)
						strcat(param, "EXT");
					strcat(param, "]");
				}

				sprintf((char*) buf, "PARTNER: OSCam v%s, build #%s (%s)%s",
						CS_VERSION, CS_SVN_VERSION, CS_OSTYPE, param);
				cc_cmd_send(buf, strlen((char*) buf) + 1, MSG_CW_NOK1);
			} else if (cc->is_oscam_cccam)
				check_extended_mode(msg);
			cs_debug_mask(D_FUT, "cc_parse_msg out");
			return ret;
		}

		if (cl->is_server) //for reader only
			return ret;

		if (cc->just_logged_in)
			return -1; // reader restart needed

		pthread_mutex_lock(&cc->cards_busy);
		struct cc_extended_ecm_idx *eei = get_extended_ecm_idx(
				cc->extended_mode ? cc->g_flag : 1, TRUE);
		if (eei == NULL) {
			cs_log("%s received extended ecm NOK id %d but not found!",
					getprefix(), cc->g_flag);
			pthread_mutex_unlock(&cc->cards_busy);
			cc_cli_close();
			cs_debug_mask(D_FUT, "cc_parse_msg out");
			return ret;
		}

		ushort ecm_idx = eei->ecm_idx;
		struct cc_card *card = eei->card;
		struct cc_srvid srvid = eei->srvid;
		free(eei);

		if (card) {
			if (buf[1] == MSG_CW_NOK1) //MSG_CW_NOK1: share no more available
				cc_card_removed(card->id);
			else if (!is_good_sid(card, &srvid)) //MSG_CW_NOK2: can't decode
				add_sid_block(card, &srvid);
			else
				remove_good_sid(card, &srvid);

			if (!rdr->cc_disable_retry_ecm) {
				//retry ecm:
				int i = 0;
				for (i = 0; i < CS_MAXPENDING; i++) {
					if (cl->ecmtask[i].idx == ecm_idx)
						cl->ecmtask[i].rc = 100; //Mark unused
				}
			}
		} else
			cs_log("%S NOK: NO CARD!", getprefix());
		pthread_mutex_unlock(&cc->cards_busy);
		
		if (!cc->extended_mode) {
			rdr->available = 1;
			pthread_mutex_unlock(&cc->ecm_busy);
		}

		cc_send_ecm(NULL, NULL);

		break;
	case MSG_CW_ECM:
		cc->just_logged_in = 0;
		if (cl->is_server) { //SERVER:
			ECM_REQUEST *er;

			struct cc_card *server_card = malloc(sizeof(struct cc_card));
			memset(server_card, 0, sizeof(struct cc_card));
			server_card->id = buf[10] << 24 | buf[11] << 16 | buf[12] << 8
					| buf[13];
			server_card->caid = b2i(2, data);

			if ((er = get_ecmtask())) {
				er->caid = b2i(2, buf + 4);
				er->srvid = b2i(2, buf + 14);
				er->l = buf[16];
				memcpy(er->ecm, buf + 17, er->l);
				er->prid = b2i(4, buf + 6);
				cc->server_ecm_pending++;
				er->idx = ++cc->server_ecm_idx;

				cs_debug_mask(
						D_TRACE,
						"%s ECM request from client: caid %04x srvid %04x(%d) prid %06x",
						getprefix(), er->caid, er->srvid, er->l, er->prid);

				struct cc_srvid srvid;
				srvid.sid = er->srvid;
				srvid.ecmlen = er->l;
				add_extended_ecm_idx(cc->extended_mode ? cc->g_flag : 1, er->idx,
						server_card, srvid);

				get_cw(er);

			} else {
				cs_debug_mask(D_TRACE, "%s NO ECMTASK!!!!", getprefix());
				free(server_card);
			}

		} else { //READER:
			pthread_mutex_lock(&cc->cards_busy);
			
			struct cc_extended_ecm_idx *eei = get_extended_ecm_idx(
					cc->extended_mode ? cc->g_flag : 1, TRUE);
			if (eei == NULL) {
				cs_log("%s received extended ecm id %d but not found!",
						getprefix(), cc->g_flag);
				pthread_mutex_unlock(&cc->cards_busy);
				cc_cli_close();
				cs_debug_mask(D_FUT, "cc_parse_msg out");
				return ret;
			}

			ushort ecm_idx = eei->ecm_idx;
			struct cc_card *card = eei->card;
			struct cc_srvid srvid = eei->srvid;
			free(eei);

			if (card) {
				if (!cc->extended_mode)
					cc_cw_crypt(buf + 4, card->id);
				memcpy(cc->dcw, buf + 4, 16);
				if (!cc->extended_mode)
					cc_crypt(&cc->block[DECRYPT], buf + 4, l - 4, ENCRYPT); // additional crypto step

				if (is_null_dcw(cc->dcw)) {
					cs_log("%s null dcw received! sid=%04X(%d)", getprefix(),
							srvid.sid, srvid.ecmlen);
					add_sid_block(card, &srvid);
					//ecm retry:
					int i = 0;
					for (i = 0; i < CS_MAXPENDING; i++) {
						if (cl->ecmtask[i].idx == ecm_idx)
							cl->ecmtask[i].rc = 100; //Mark unused
					}

					buf[1] = MSG_CW_NOK2; //So it's really handled like a nok!
				} else {
					cc->recv_ecmtask = ecm_idx;
					cs_debug_mask(D_TRACE, "%s cws: %d %s", getprefix(),
							ecm_idx, cs_hexdump(0, cc->dcw, 16));
					add_good_sid(card, &srvid);
				}
			} else {
				cs_log(
						"%s warning: ECM-CWS respond by CCCam server without current card!",
						getprefix());
			}
			pthread_mutex_unlock(&cc->cards_busy);

			if (!cc->extended_mode) {
				rdr->available = 1;
				pthread_mutex_unlock(&cc->ecm_busy);
			}

			//cc_abort_user_ecms();

			cc_send_ecm(NULL, NULL);

			if (cc->max_ecms)
				cc->ecm_counter++;
		}
		break;
		
	case MSG_KEEPALIVE:
		cc->just_logged_in = 0;
		if (!cl->is_server) {
			cs_debug("cccam: keepalive ack");
		} else {
			//Checking if last answer is one minute ago:
			if (cc->answer_on_keepalive + 55 < time(NULL)) {
				cc_cmd_send(NULL, 0, MSG_KEEPALIVE);
				cs_debug("cccam: keepalive");
				cc->answer_on_keepalive = time(NULL);
			}
		}
		break;
		
	case MSG_CMD_05:
		if (!cl->is_server) {
			cc->just_logged_in = 0;
			l = l - 4;//Header Length=4 Byte

			cs_log("%s MSG_CMD_05 recvd, payload length=%d mode=%d",
					getprefix(), l, cc->cmd05_mode);
			cc->cmd05_active = 1;
			cc->cmd05_data_len = l;
			memcpy(&cc->cmd05_data, buf + 4, l);
			if (rdr->available)
				send_cmd05_answer();
		}
		break;
	case MSG_CMD_0B: {
		// by Project:Keynation
		/*cs_log("%s MSG_CMD_0B received, cycle connection (payload=%d)!", getprefix(), l-4);*/
		cs_debug_mask(D_TRACE, "%s MSG_CMD_0B received (payload=%d)!",
				getprefix(), l - 4);
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

		break;
	}
	case MSG_EMM_ACK: {
		cc->just_logged_in = 0;
		if (cl->is_server) { //EMM Request received
			cc_cmd_send(NULL, 0, MSG_EMM_ACK); //Send back ACK
			if (l > 4) {
				cs_debug_mask(D_EMM, "%s EMM Request received!", getprefix());

				if (!is_au()) {
					cs_debug_mask(
							D_EMM,
							"%s EMM Request discarded because au is not assigned to an reader!",
							getprefix());
					return MSG_EMM_ACK;
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
			if (!cc->extended_mode) {
				rdr->available = 1;
				pthread_mutex_unlock(&cc->ecm_busy);
			}
			cc_send_ecm(NULL, NULL);
		}
		break;
	}
	default:
		cs_ddump(buf, l, "%s unhandled msg: %d len=%d", getprefix(), buf[1], l);
		break;
	}

	if (cc->max_ecms && (cc->ecm_counter > cc->max_ecms)) {
		cs_log("%s max ecms (%d) reached, cycle connection!", getprefix(),
				cc->max_ecms);
		//cc_cycle_connection();
		cc_cli_close();
		//cc_send_ecm(NULL, NULL);
	}
	cs_debug_mask(D_FUT, "cc_parse_msg out");
	return ret;
}

/**
 * Reader: write dcw to receive
 */
int cc_recv_chk(uchar *dcw, int *rc, uchar *buf) {
	cs_debug_mask(D_FUT, "cc_recv_chk in");
	struct s_client *cl = &client[cs_idx];
	struct cc_data *cc = cl->cc;

	if (buf[1] == MSG_CW_ECM) {
		memcpy(dcw, cc->dcw, 16);
		cs_debug("cccam: recv chk - MSG_CW %d - %s", cc->recv_ecmtask,
				cs_hexdump(0, dcw, 16));
		*rc = 1;
		cs_debug_mask(D_FUT, "cc_recv_chk out");
		return (cc->recv_ecmtask);
	} else if ((buf[1] == (MSG_CW_NOK1)) || (buf[1] == (MSG_CW_NOK2))) {
		//memset(dcw, 0, 16);
		//return *rc = 0;
		cs_debug_mask(D_FUT, "cc_recv_chk out");
		return -1;
	}

	cs_debug_mask(D_FUT, "cc_recv_chk out");
	return (-1);
}

//int is_softfail(int rc)
//{
//	//see oscam.c send_dcw() for a full list
//	switch(rc)
//	{
//		case 5: // 5 = timeout
//		case 6: // 6 = sleeping
//		case 7: // 7 = fake
//		case 10:// 10= no card
//		case 11:// 11= expdate
//		case 12:// 12= disabled
//		case 13:// 13= stopped
//		case 14:// 100= unhandled
//			return TRUE;
//	}
//	return FALSE;
//}

/**
 * Server: send DCW to client
 */
void cc_send_dcw(ECM_REQUEST *er) {
	cs_debug_mask(D_FUT, "cc_send_dcw in");
	struct s_client *cl = &client[cs_idx];
	uchar buf[16];
	struct cc_data *cc = cl->cc;

	memset(buf, 0, sizeof(buf));

	struct cc_extended_ecm_idx *eei =
			get_extended_ecm_idx_by_idx(er->idx, TRUE);

	if (er->rc <= 3 && eei && eei->card) {
		cc->g_flag = eei->send_idx;
		memcpy(buf, er->cw, sizeof(buf));
		cs_debug_mask(D_TRACE, "%s send cw: %s cpti: %d", getprefix(),
				cs_hexdump(0, buf, 16), er->cpti);
		if (!cc->extended_mode)
			cc_cw_crypt(buf, eei->card->id);
		cc_cmd_send(buf, 16, MSG_CW_ECM);
		if (!cc->extended_mode)
			cc_crypt(&cc->block[ENCRYPT], buf, 16, ENCRYPT); // additional crypto step
		free(eei->card);
	} else {
		cs_debug_mask(D_TRACE, "%s send cw: NOK cpti: %d", getprefix(),
				er->cpti);

		if (eei)
			cc->g_flag = eei->send_idx;

		int nok;
		if (!eei || !eei->card)
			nok = MSG_CW_NOK1; //share no more available
		else
			nok = MSG_CW_NOK2; //can't decode
		cc_cmd_send(NULL, 0, nok);
	}
	cc->server_ecm_pending--;
	free(eei);
	cs_debug_mask(D_FUT, "cc_send_dcw out");
}

int cc_recv(uchar *buf, int l) {
	struct s_client *cl = &client[cs_idx];
	int n;
	uchar *cbuf;
	struct cc_data *cc = cl->cc;

	if (buf == NULL || l <= 0)
		return -1;
	cbuf = malloc(l);
	memcpy(cbuf, buf, l); // make a copy of buf

	pthread_mutex_lock(&cc->lock);

	n = cc_msg_recv(cbuf); // recv and decrypt msg

	cs_ddump(cbuf, n, "cccam: received %d bytes from %s", n, remote_txt());
	cl->last = time((time_t *) 0);

	if (n <= 0) {
		cs_log("%s connection closed to %s", getprefix(), remote_txt());
		n = -1;
	} else if (n < 4) {
		cs_log("%s packet to small (%d bytes)", getprefix(), n);
		n = -1;
	} else {
		// parse it and write it back, if we have received something of value
		n = cc_parse_msg(cbuf, n);
		memcpy(buf, cbuf, l);
	}

	pthread_mutex_unlock(&cc->lock);

	NULLFREE(cbuf);

	if (n == -1) {
		if (cl->is_server)
			cs_disconnect_client();
		else
			cc_cli_close();
	}

	return n;
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
ulong get_reader_hexserial_crc() {
	if (!is_au())
		return 0;

	ulong crc = 0;
	int r;
	for (r = 0; r < CS_MAXREADER; r++) {
		if (reader[r].enable && !reader[r].deleted && reader[r].cidx
				&& !reader[r].audisabled)
			crc += crc32(0, reader[r].hexserial, 8);
	}
	return crc;
}

ulong get_reader_prid(int r, int j) {
	ulong prid;
	if (!(reader[r].typ & R_IS_CASCADING)) { // Read cardreaders have 4-byte Providers
		prid = (reader[r].prid[j][0] << 24) | (reader[r].prid[j][1] << 16)
				| (reader[r].prid[j][2] << 8) | (reader[r].prid[j][3] & 0xFF);
	} else { // Cascading/Network-reader 3-bytes Providers
		prid = (reader[r].prid[j][0] << 16) | (reader[r].prid[j][1] << 8)
				| (reader[r].prid[j][2] & 0xFF);
	}
	return prid;
}

int add_card_providers(struct cc_card *dest_card, struct cc_card *card) {
	int modified = 0;
	struct cc_provider *prov_info;
	LLIST_ITR itr_info;
	LLIST_ITR itr_card;
	struct cc_provider *provider = llist_itr_init(card->providers, &itr_card);
	while (provider) {
		prov_info = llist_itr_init(dest_card->providers, &itr_info);
		while (prov_info) {
			if (prov_info->prov == provider->prov)
				break;
			prov_info = llist_itr_next(&itr_info);
		}
		if (!prov_info) {
			struct cc_provider *prov_new = malloc(sizeof(struct cc_provider));
			memcpy(prov_new, provider, sizeof(struct cc_provider));
			llist_append(dest_card->providers, prov_new);
			modified = 1;
		}
		provider = llist_itr_next(&itr_card);
	}
	return modified;
}

struct cc_card *create_card(struct cc_card *card) {
	struct cc_card *card2 = malloc(sizeof(struct cc_card));
	memcpy(card2, card, sizeof(struct cc_card));
	card2->providers = llist_create();
	card2->badsids = llist_create();
	card2->goodsids = llist_create();
	return card2;
}
/**
 * Adds a new card to a cardlist.
 */
int add_card_to_serverlist(LLIST *cardlist, struct cc_card *card) {
	int modified = 0;
	LLIST_ITR itr;
	struct cc_card *card2 = llist_itr_init(cardlist, &itr);

	//Minimize all, transmit just CAID
	if (cfg->cc_minimize_cards == MINIMIZE_CAID) {
		while (card2) {
			if (card2->caid == card->caid)
				break;
			card2 = llist_itr_next(&itr);
		}
		if (!card2) {
			card2 = create_card(card);
			card2->hop = card->hop;
			card2->remote_id = card->remote_id;
			llist_append(cardlist, card2);
			modified = 1;

			//Null-Provider for all Providers!
			struct cc_provider *prov_new = malloc(sizeof(struct cc_provider));
			memset(prov_new, 0, sizeof(struct cc_provider));
			llist_append(card2->providers, prov_new);
		} else {
			if (card->hop < card2->hop) {
				card2->hop = card->hop;
				modified = 1;
			}
		}

	} else if (cfg->cc_minimize_cards == MINIMIZE_HOPS) {
		while (card2) {
			if (card2->caid == card->caid && llist_count(card2->providers)
					< CS_MAXPROV)
				break;
			card2 = llist_itr_next(&itr);
		}
		if (!card2) {
			card2 = create_card(card);
			card2->hop = card->hop;
			card2->remote_id = card->remote_id;
			llist_append(cardlist, card2);
			modified = 1;
		} else {
			if (card->hop < card2->hop) {
				card2->hop = card->hop;
				modified = 1;
			}
		}
		if (add_card_providers(card2, card))
			modified = 1;
	} else {
		while (card2) {
			if (card2->caid == card->caid && card2->hop == card->hop
					&& card2->remote_id == card->remote_id && llist_count(
					card2->providers) < CS_MAXPROV)
				break;
			card2 = llist_itr_next(&itr);
		}
		if (!card2) {
			card2 = create_card(card);
			card2->providers = llist_create();
			card2->hop = card->hop;
			card2->remote_id = card->remote_id;
			llist_append(cardlist, card2);
			modified = 1;
		}
		if (add_card_providers(card2, card))
			modified = 1;
	}
	return modified;
}

/**
 * Server:
 * Reports all caid/providers to the connected clients
 * returns total count of reported cards
 */
int cc_srv_report_cards() {
	struct s_client *cl = &client[cs_idx];
	int j;
	uint32 id;
	uint r, k;
	uint8 hop = 0;
	int reshare, usr_reshare, reader_reshare, maxhops, flt = 0;
	uint8 buf[CC_MAXMSGSIZE];
	struct cc_data *cc = cl->cc;

	struct s_auth *account = get_account(cl->usr);
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

	LLIST *server_cards = llist_create();
	LLIST *reported_carddatas = llist_create();

	for (r = 0; r < CS_MAXREADER; r++) {
		if (!reader[r].fd || !reader[r].enable || reader[r].deleted)
			continue;
		if (!(reader[r].grp & cl->grp))
			continue;
		reader_reshare = reader[r].cc_reshare;

		reshare = (reader_reshare < usr_reshare) ? reader_reshare : usr_reshare;
		if (reshare < 0)
			continue;

		if (!reader[r].cc_id) {
			reader[r].cc_id = fast_rnd() << 8 | fast_rnd();
		}

		int au_allowed = !reader[r].audisabled && is_au();

		flt = 0;
		if (reader[r].typ != R_CCCAM && reader[r].ftab.filts) {
			for (j = 0; j < CS_MAXFILTERS; j++) {
				if (reader[r].ftab.filts[j].caid && chk_ctab(
						reader[r].ftab.filts[j].caid, &cl->ctab)) {
					int ignore = 0;
					memset(buf, 0, sizeof(buf));
					buf[0] = id >> 24;
					buf[1] = id >> 16;
					buf[2] = id >> 8;
					buf[3] = id & 0xff;
					buf[5] = reader[r].cc_id >> 16;
					buf[6] = reader[r].cc_id >> 8;
					buf[7] = reader[r].cc_id & 0xFF;
					ushort caid = reader[r].ftab.filts[j].caid;
					buf[8] = caid >> 8;
					buf[9] = caid & 0xff;
					buf[10] = hop;
					buf[11] = reshare;
					//Setting UA: (Unique Address):
					if (au_allowed)
						cc_UA_oscam2cccam(reader[r].hexserial, buf + 12);
					buf[20] = reader[r].ftab.filts[j].nprids;
					//cs_log("Ident CCcam card report caid: %04X readr %s subid: %06X", reader[r].ftab.filts[j].caid, reader[r].label, reader[r].cc_id);
					for (k = 0; k < reader[r].ftab.filts[j].nprids; k++) {
						ulong prid = reader[r].ftab.filts[j].prids[k];
						if (!chk_srvid_by_caid_prov(caid, prid, cs_idx)) {
							ignore = 1;
							break;
						}
						int ofs = 21 + (k * 7);
						buf[ofs + 0] = prid >> 16;
						buf[ofs + 1] = prid >> 8;
						buf[ofs + 2] = prid & 0xFF;
						//cs_log("Ident CCcam card report provider: %02X%02X%02X", buf[21 + (k*7)]<<16, buf[22 + (k*7)], buf[23 + (k*7)]);
						if (au_allowed) {
							int l;
							for (l = 0; l < reader[r].nprov; l++) {
								ulong rprid = get_reader_prid(r, l);
								if (rprid == prid)
									cc_SA_oscam2cccam(&reader[r].sa[l][0], buf+ofs+3);
							}
						}
					}
					if (ignore) //Filtered by services
						continue;

					buf[21 + (k * 7)] = 1;
					memcpy(buf + 22 + (k * 7), cc->node_id, 8);
					/*
					 buf[21 + (k*7)+8] = 1;
					 memcpy(buf + 22 + (k*7)+8, cc->node_id, 7);//8);
					 cc_cmd_send(buf, 30 + (k*7) + 9, MSG_NEW_CARD);
					 */
					int len = 30 + (k * 7);
					cc_cmd_send(buf, len, MSG_NEW_CARD);
					cc_add_reported_carddata(reported_carddatas, buf, len, &reader[r]);
					id++;
					flt = 1;
				}
			}
		}

		if (reader[r].typ != R_CCCAM && !reader[r].caid[0] && !flt) {
			flt = 0;
			for (j = 0; j < CS_MAXCAIDTAB; j++) {
				//cs_log("CAID map CCcam card report caid: %04X cmap: %04X", reader[r].ctab.caid[j], reader[r].ctab.cmap[j]);
				ushort lcaid = reader[r].ctab.caid[j];

				if (!chk_ctab(lcaid, &cl->ctab))
					continue;

				if (!lcaid || (lcaid == 0xFFFF))
					lcaid = reader[r].ctab.cmap[j];

				if (lcaid && (lcaid != 0xFFFF)) {
					memset(buf, 0, sizeof(buf));
					buf[0] = id >> 24;
					buf[1] = id >> 16;
					buf[2] = id >> 8;
					buf[3] = id & 0xff;
					buf[5] = reader[r].cc_id >> 16;
					buf[6] = reader[r].cc_id >> 8;
					buf[7] = reader[r].cc_id & 0xFF;
					buf[8] = lcaid >> 8;
					buf[9] = lcaid & 0xff;
					buf[10] = hop;
					buf[11] = reshare;
					if (au_allowed)
						cc_UA_oscam2cccam(reader[r].hexserial, buf + 12);
					buf[20] = 1;
					//cs_log("CAID map CCcam card report caid: %04X nodeid: %s subid: %06X", lcaid, cs_hexdump(0, cc->peer_node_id, 8), reader[r].cc_id);
					//buf[21] = 0;
					//buf[22] = 0;
					//buf[23] = 0;
					buf[21 + 7] = 1;
					memcpy(buf + 22 + 7, cc->node_id, 8);
					int len = 30 + 7;
					cc_cmd_send(buf, len, MSG_NEW_CARD);
					cc_add_reported_carddata(reported_carddatas, buf, len, &reader[r]);
					id++;
					flt = 1;
				}
			}
		}

		if (reader[r].typ != R_CCCAM && reader[r].caid[0] && !flt && chk_ctab(
				reader[r].caid[0], &cl->ctab)) {
			//cs_log("tcp_connected: %d card_status: %d ", reader[r].tcp_connected, reader[r].card_status);
			memset(buf, 0, sizeof(buf));
			buf[0] = id >> 24;
			buf[1] = id >> 16;
			buf[2] = id >> 8;
			buf[3] = id & 0xff;
			buf[5] = reader[r].cc_id >> 16;
			buf[6] = reader[r].cc_id >> 8;
			buf[7] = reader[r].cc_id & 0xFF;
			ushort caid = reader[r].caid[0];
			buf[8] = caid >> 8;
			buf[9] = caid & 0xff;
			buf[10] = hop;
			buf[11] = reshare;
			if (au_allowed)
				cc_UA_oscam2cccam(reader[r].hexserial, buf + 12);
			buf[20] = reader[r].nprov;
			for (j = 0; j < reader[r].nprov; j++) {
				ulong prid = get_reader_prid(r, j);
				int ofs = 21 + (j * 7);
				buf[ofs + 0] = prid >> 16;
				buf[ofs + 1] = prid >> 8;
				buf[ofs + 2] = prid & 0xFF;
				//Setting SA (Shared Addresses):
				if (au_allowed)
					cc_SA_oscam2cccam(&reader[r].sa[j][0], buf+ofs+3);
				//cs_log("Main CCcam card report provider: %02X%02X%02X%02X", buf[21+(j*7)], buf[22+(j*7)], buf[23+(j*7)], buf[24+(j*7)]);
			}
			buf[21 + (j * 7)] = 1;
			memcpy(buf + 22 + (j * 7), cc->node_id, 8);
			id++;

			if ((reader[r].tcp_connected || reader[r].card_status
					== CARD_INSERTED) /*&& !reader[r].cc_id*/) {
				//reader[r].cc_id = b2i(3, buf + 5);
				int len = 30 + (j * 7);
				cc_add_reported_carddata(reported_carddatas, buf, len, &reader[r]);
				cc_cmd_send(buf, len, MSG_NEW_CARD);
				//cs_log("CCcam: local card or newcamd reader  %02X report ADD caid: %02X%02X %d %d %s subid: %06X", buf[7], buf[8], buf[9], reader[r].card_status, reader[r].tcp_connected, reader[r].label, reader[r].cc_id);
			} else if ((reader[r].card_status != CARD_INSERTED)
					&& (!reader[r].tcp_connected) && reader[r].cc_id) {
				//reader[r].cc_id = 0;
				cc_cmd_send(buf, 30 + (j * 7), MSG_CARD_REMOVED);
				//cs_log("CCcam: local card or newcamd reader %02X report REMOVE caid: %02X%02X %s", buf[7], buf[8], buf[9], reader[r].label);
			}
		}

		if (reader[r].typ == R_CCCAM && !flt) {

			cs_debug_mask(D_TRACE, "%s asking reader %s for cards...",
					getprefix(), reader[r].label);

			struct cc_card *card;
			struct s_client *rc = &client[reader[r].cidx];
			struct cc_data *rcc = rc->cc;

			int count = 0;
			if (rcc && rcc->cards) {
				pthread_mutex_lock(&rcc->cards_busy);

				LLIST_ITR itr;
				card = llist_itr_init(rcc->cards, &itr);
				while (card) {
					if (card->hop <= maxhops && //card->maxdown > 0 &&
							chk_ctab(card->caid, &cl->ctab) && chk_ctab(
							card->caid, &reader[r].ctab)) {
						int ignore = 0;

						LLIST_ITR itr_prov;
						struct cc_provider *prov = llist_itr_init(
								card->providers, &itr_prov);
						while (prov) {
							ulong prid = prov->prov;
							prov = llist_itr_next(&itr_prov);
							if (!chk_srvid_by_caid_prov(card->caid, prid,
									cs_idx) || !chk_srvid_by_caid_prov(
									card->caid, prid, reader[r].cidx)) {
								ignore = 1;
								break;
							}
						}
						if (!ignore) { //Filtered by service
							card->maxdown = reshare;
							add_card_to_serverlist(server_cards, card);
							count++;
						}
					}
					card = llist_itr_next(&itr);

				}
				pthread_mutex_unlock(&rcc->cards_busy);
			}
			cs_debug_mask(D_TRACE, "%s got %d cards from %s", getprefix(),
					count, reader[r].label);
		}
	}

	//report reshare cards:
	//cs_debug_mask(D_TRACE, "%s reporting %d cards", getprefix(), llist_count(server_cards));
	LLIST_ITR itr;
	struct cc_card *card = llist_itr_init(server_cards, &itr);
	while (card) {
		//cs_debug_mask(D_TRACE, "%s card %d caid %04X hop %d", getprefix(), card->id, card->caid, card->hop);
		memset(buf, 0, sizeof(buf));
		buf[0] = id >> 24;
		buf[1] = id >> 16;
		buf[2] = id >> 8;
		buf[3] = id & 0xff;
		buf[5] = card->remote_id >> 16;
		buf[6] = card->remote_id >> 8;
		buf[7] = card->remote_id & 0xFF;
		buf[8] = card->caid >> 8;
		buf[9] = card->caid & 0xff;
		buf[10] = card->hop;
		buf[11] = card->maxdown;
		//memcpy(buf + 12, card->hexserial, 8);
		//We never reshare UA / SA !!
		int j = 0;
		LLIST_ITR itr_prov;
		struct cc_provider *prov = llist_itr_init(card->providers, &itr_prov);
		while (prov) {
			ulong prid = prov->prov;
			buf[21 + (j * 7)] = prid >> 16;
			buf[22 + (j * 7)] = prid >> 8;
			buf[23 + (j * 7)] = prid & 0xFF;
			//memcpy(buf+24+(j*7), prov->sa, 4);
			prov = llist_itr_next(&itr_prov);
			j++;
		}
		buf[20] = j;
		buf[21 + (j * 7)] = 1;
		memcpy(buf + 22 + (j * 7), cc->node_id, 8);
		id++;

		int len = 30 + (j * 7);
		cc_cmd_send(buf, len, MSG_NEW_CARD);
		cc_add_reported_carddata(reported_carddatas, buf, len, &reader[r]);
		card = llist_itr_next(&itr);
	}
	cc_free_cardlist(server_cards);

	cc->report_carddata_id = id;
	//Reported deleted cards:
	cc_free_reported_carddata(cc->reported_carddatas, 1);
	cc->reported_carddatas = reported_carddatas;

	int count = llist_count(reported_carddatas);
	cs_log("%s reported %d cards to client", getprefix(), count);
	return count;
}

void cc_init_cc(struct cc_data *cc) {
	pthread_mutexattr_t   mta;
        pthread_mutexattr_init(&mta);
#if defined(OS_CYGWIN32) || defined(OS_HPUX) || defined(OS_FREEBSD)  || defined(OS_MACOSX)
        pthread_mutexattr_settype(&mta, PTHREAD_MUTEX_RECURSIVE);
#else
        pthread_mutexattr_settype(&mta, PTHREAD_MUTEX_RECURSIVE_NP);
#endif                      		
	pthread_mutex_init(&cc->lock, &mta);
	pthread_mutex_init(&cc->ecm_busy, &mta);
	pthread_mutex_init(&cc->cards_busy, &mta);

	//pthread_mutex_init(&cc->lock, NULL);
	//pthread_mutex_init(&cc->ecm_busy, NULL);
	//pthread_mutex_init(&cc->cards_busy, NULL);
}

/**
 * Starting readers to get cards:
 **/
int cc_srv_wakeup_readers(struct s_client *cl) {
	int r;
	int wakeup = 0;
	for (r = 0; r < CS_MAXREADER; r++) {
		if (reader[r].typ != R_CCCAM)
			continue;
		if (!reader[r].fd || !reader[r].enable || reader[r].deleted || reader[r].tcp_connected == 2)
			continue;
		if (!(reader[r].grp & cl->grp))
			continue;
	
		//This wakeups the reader:
		uchar dummy;
		write_to_pipe(reader[r].fd, PIP_ID_CIN, &dummy, sizeof(dummy));
		wakeup++;
	}
	return wakeup;
}

int cc_cards_modified() {
	int r, modified = 0;
	for (r = 0; r < CS_MAXREADER; r++) {
        	if (reader[r].typ == R_CCCAM && reader[r].fd) {
        		struct s_client *clr = &client[reader[r].cidx];
        		if (clr->cc) {
        			struct cc_data *ccr = clr->cc;
       				modified += ccr->cards_modified;
        		}
                }
	}
	return modified;	                                         
}

int cc_srv_connect(struct s_client *cl) {
	cs_debug_mask(D_FUT, "cc_srv_connect in");
	int i;
	ulong cmi;
	uint8 buf[CC_MAXMSGSIZE];
	uint8 data[16];
	char usr[21], pwd[21];
	struct s_auth *account;
	struct cc_data *cc = cl->cc;
	uchar mbuf[1024];

	memset(usr, 0, sizeof(usr));
	memset(pwd, 0, sizeof(pwd));

	//SS: Use last cc data for faster reconnects:
	if (!cc) {
		// init internals data struct
		cc = malloc(sizeof(struct cc_data));
		if (cc == NULL) {
			cs_log("%s cannot allocate memory", getprefix());
			return -1;
		}

		cl->cc = cc;
		memset(cl->cc, 0, sizeof(struct cc_data));
		cc->extended_ecm_idx = llist_create();
		
		cc_init_cc(cc);
	}
	cc->server_ecm_pending = 0;
	cc->extended_mode = 0;
	cl->cc_extended_ecm_mode = 0;
	cc->cc_use_rc4 = 0;
	cl->is_server = 1;

	//Partner detection:
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

	send(cl->udp_fd, data, 16, 0);

	cc_xor(data); // XOR init bytes with 'CCcam'

	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, data, 16);
	SHA1_Final(buf, &ctx);

	//Special check for 2.0.11 clients
	//2.0.11 uses rc4 crypt
	//So we need to test data for validity:
	struct cc_crypt_block *block_rc4 =
			malloc(sizeof(struct cc_crypt_block) * 2);
	uint8 *data_rc4 = malloc(16);
	uint8 *buf_rc4 = malloc(CC_MAXMSGSIZE);
	memcpy(data_rc4, data, sizeof(data));
	memcpy(buf_rc4, buf, CC_MAXMSGSIZE);
	memcpy(block_rc4, cc->block, sizeof(struct cc_crypt_block) * 2);
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

	if ((i = recv(cl->pfd, buf, 20, MSG_WAITALL)) == 20) {
		cs_ddump(buf, 20, "cccam: recv:");
		memcpy(buf_rc4, buf, CC_MAXMSGSIZE);
		cc_crypt(&cc->block[DECRYPT], buf, 20, DECRYPT);
		cc_rc4_crypt(&block_rc4[DECRYPT], buf_rc4, 20, DECRYPT);
		cs_ddump(buf, 20, "cccam: hash:");
		cs_ddump(buf_rc4, 20, "cccam: hash rc4:");
	}

	// receive username
	if ((i = recv(cl->pfd, buf, 20, MSG_WAITALL)) == 20) {
		memcpy(buf_rc4, buf, CC_MAXMSGSIZE);
		cc_crypt(&cc->block[DECRYPT], buf, 20, DECRYPT);
		cc_rc4_crypt(&block_rc4[DECRYPT], buf_rc4, 20, DECRYPT);

		strncpy(usr, (char *) buf, sizeof(usr));
		strncpy(usr_rc4, (char *) buf_rc4, sizeof(usr_rc4));

		//test for nonprintable characters:
		cc->cc_use_rc4 = -1;
		for (i = 0; i < 20; i++) {
			if (usr[i] > 0 && usr[i] < 0x20) { //found nonprintable char
				cc->cc_use_rc4 = 1;
				break;
			}
			if (usr_rc4[i] > 0 && usr_rc4[i] < 0x20) { //found nonprintable char
				cc->cc_use_rc4 = 0;
				break;
			}
		}
		if (cc->cc_use_rc4 == 0)
			cs_ddump(buf, 20, "cccam: username '%s':", usr);
		else if (cc->cc_use_rc4 == 1)
			cs_ddump(buf_rc4, 20, "cccam: username rc4 '%s':", usr_rc4);
		else
			cs_debug("illegal username received");
	}

	for (account = cfg->account; account; account = account->next) {
		if (strcmp(usr, account->usr) == 0) {
			strncpy(pwd, account->pwd, sizeof(pwd));
			cc->cc_use_rc4 = 0; //We found a user by cc_crypt
			break;
		}
		if (strcmp(usr_rc4, account->usr) == 0) {
			strncpy(pwd, account->pwd, sizeof(pwd));
			cc->cc_use_rc4 = 1; //We found a user by cc_rc4_crypt
			break;
		}
	}

	if (!account || cc->cc_use_rc4 == -1) {
		cs_log("account '%s' not found!", cc->cc_use_rc4 ? usr_rc4 : usr);
		return -1;
	}

	if (cc->cc_use_rc4) {
		cs_log("%s client is using version 2.0.11 rc4", getprefix());
		memcpy(cc->block, block_rc4, sizeof(struct cc_crypt_block) * 2);
	}
	free(block_rc4);
	free(data_rc4);
	free(buf_rc4);

	// receive passwd / 'CCcam'
	cc_crypt(&cc->block[DECRYPT], (uint8 *) pwd, strlen(pwd), DECRYPT);
	if ((i = recv(cl->pfd, buf, 6, MSG_WAITALL)) == 6) {
		cc_crypt(&cc->block[DECRYPT], buf, 6, DECRYPT);
		cs_ddump(buf, 6, "cccam: pwd check '%s':", buf);
	} else
		return -1;

	cl->crypted = 1;
	if (cs_auth_client(account, NULL))
		return -1;
	//cs_auth_client((struct s_auth *)(-1), NULL);

	//Starting readers to get cards:
	int wakeup = cc_srv_wakeup_readers(cl);
	
	// send passwd ack
	memset(buf, 0, 20);
	memcpy(buf, "CCcam\0", 6);
	cs_ddump(buf, 20, "cccam: send ack:");
	cc_crypt(&cc->block[ENCRYPT], buf, 20, ENCRYPT);
	send(cl->pfd, buf, 20, 0);

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
	
	if (wakeup > 0) //give readers time to get cards:
	  cs_sleepms(500);
	
	cc_srv_report_cards();
	cs_ftime(&cc->ecm_time);

	cmi = 0;
	// check for client timeout, if timeout occurs try to send keepalive
	for (;;) {
		i = process_input(mbuf, sizeof(mbuf), 10); //cfg->cmaxidle);
		//cs_log("srv process input i=%d cmi=%d", i, cmi);
		int update_cards = 0;
		if (i == -9) {
			cmi += 10;
			if (cfg->cmaxidle && cmi >= cfg->cmaxidle) {
				cmi = 0;
				cs_debug_mask(D_TRACE, "%s keepalive after maxidle is reached",
						getprefix());
				break; //Disconnect client
			}
			update_cards = 1;
			
		} else if (i <= 0)
			break; //Disconnected by client
		else {
			cmi = 0;
			update_cards = 1;
		}
		
		if (update_cards) {
			if (!cc->server_ecm_pending) {
				struct timeb timeout;
				struct timeb cur_time;
				cs_ftime(&cur_time);
				timeout = cc->ecm_time;
				timeout.millitm += cfg->cc_update_interval * 1000;
				timeout.time += timeout.millitm / 1000;
				timeout.millitm = timeout.millitm % 1000;

				int needs_card_updates = cfg->cc_update_interval && comp_timeb(
						&cur_time, &timeout) > 0;
						
				if (needs_card_updates) {
					cc->ecm_time = cur_time;
					ulong new_hexserial_crc = get_reader_hexserial_crc();
					int cards_modified = cc_cards_modified();
					if (new_hexserial_crc != hexserial_crc || cards_modified != cc->cards_modified) {
						cs_debug_mask(D_TRACE, "%s update share list", getprefix());
						
						hexserial_crc = new_hexserial_crc;
						cc->cards_modified = cards_modified;
						
						cc_srv_report_cards();
					}
				}
			}
		}
	}
	
	cs_debug_mask(D_FUT, "cc_srv_connect out");
	return 0;
}

void * cc_srv_init(struct s_client *cl ) {
	cl->thread=pthread_self();
	cs_debug_mask(D_FUT, "cc_srv_init in");
	//struct s_client *cl = &client[cs_idx];
	cl->pfd = cl->udp_fd;
	//cc_auth_client(cl->ip);
	if (cc_srv_connect(cl) < 0)
		cs_log("cccam: %d failed errno: %d (%s)", __LINE__, errno, strerror(
				errno));
	cs_disconnect_client();

	//cs_exit(1);
	cc_cleanup();
	cs_debug_mask(D_FUT, "cc_srv_init out");
	return NULL; //suppress compiler warning
}

int cc_cli_connect() {
	cs_debug_mask(D_FUT, "cc_cli_connect in");
	struct s_client *cl = &client[cs_idx];
	struct s_reader *rdr = &reader[cl->ridx];
	
	int handle, n;
	uint8 data[20];
	uint8 hash[SHA_DIGEST_LENGTH];
	uint8 buf[CC_MAXMSGSIZE];
	char pwd[64];

	// check cred config
	if (rdr->device[0] == 0 || rdr->r_pwd[0] == 0
			|| rdr->r_usr[0] == 0 || rdr->r_port == 0) {
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
	if ((n = recv(handle, data, 16, MSG_WAITALL)) != 16) {
		int err = errno;
		cs_log(
				"%s server does not return 16 bytes (n=%d, handle=%d, udp_fd=%d, errno=%d)",
				getprefix(), n, handle, cl->udp_fd, err);
		return -2;
	}
	struct cc_data *cc = cl->cc;

	if (!cc) {
		// init internals data struct
		cc = malloc(sizeof(struct cc_data));
		if (cc == NULL) {
			cs_log("%s cannot allocate memory", getprefix());
			return -1;
		}
		memset(cc, 0, sizeof(struct cc_data));
		cc->cards = llist_create();
		cl->cc = cc;
		cc->auto_blocked = llist_create();
		cc->pending_emms = llist_create();
		cc->extended_ecm_idx = llist_create();
		cc->current_cards = llist_create();
		cc_init_cc(cc);
	}
	cc->ecm_counter = 0;
	cc->max_ecms = 0;
	cc->cmd05_mode = MODE_UNKNOWN;
	cc->cmd05_offset = 0;
	cc->cmd05_active = 0;
	cc->cmd05_data_len = 0;
	cc->answer_on_keepalive = time(NULL);
	cc->extended_mode = 0;
	cl->cc_extended_ecm_mode = 0;
	memset(&cc->cmd05_data, 0, sizeof(cc->cmd05_data));

	cs_ddump(data, 16, "cccam: server init seed:");

	uint16 sum = 0x1234;
	uint16 recv_sum = (data[14] << 8) | data[15];
	int i;
	for (i = 0; i < 14; i++) {
		sum += data[i];
	}
	//Create special data to detect oscam-cccam:
	cc->is_oscam_cccam = sum == recv_sum;

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
	memcpy(buf, rdr->r_usr, strlen(rdr->r_usr));
	cs_ddump(buf, 20, "cccam: username '%s':", buf);
	cc_cmd_send(buf, 20, MSG_NO_HEADER); // send usr '0' padded -> 20 bytes

	memset(buf, 0, sizeof(buf));
	memset(pwd, 0, sizeof(pwd));

	cs_debug("cccam: 'CCcam' xor");
	memcpy(buf, "CCcam", 5);
	strncpy(pwd, rdr->r_pwd, sizeof(pwd) - 1);
	cc_crypt(&cc->block[ENCRYPT], (uint8 *) pwd, strlen(pwd), ENCRYPT);
	cc_cmd_send(buf, 6, MSG_NO_HEADER); // send 'CCcam' xor w/ pwd

	if ((n = recv(handle, data, 20, MSG_WAITALL)) != 20) {
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

	cs_debug("cccam: last_s=%d, last_g=%d", rdr->last_s,
			rdr->last_g);

	cl->pfd = cl->udp_fd;
	cs_debug("cccam: pfd=%d", cl->pfd);

	if (cc_send_cli_data() <= 0) {
		cs_log("%s login failed, could not send client data", getprefix());
		return -3;
	}

	//Trick: when discovered partner is an Oscam Client, then we send him our version string:
	if (cc->is_oscam_cccam) {
		sprintf((char*) buf, "PARTNER: OSCam v%s, build #%s (%s) [EXT]",
				CS_VERSION, CS_SVN_VERSION, CS_OSTYPE);
		cc_cmd_send(buf, strlen((char*) buf) + 1, MSG_CW_NOK1);
	}

	rdr->caid[0] = rdr->ftab.filts[0].caid;
	rdr->nprov = rdr->ftab.filts[0].nprids;
	for (n = 0; n < rdr->nprov; n++) {
		rdr->availkeys[n][0] = 1;
		rdr->prid[n][0] = rdr->ftab.filts[0].prids[n] >> 24;
		rdr->prid[n][1] = rdr->ftab.filts[0].prids[n] >> 16;
		rdr->prid[n][2] = rdr->ftab.filts[0].prids[n] >> 8;
		rdr->prid[n][3] = rdr->ftab.filts[0].prids[n] & 0xff;
	}

	rdr->card_status = CARD_NEED_INIT;
	rdr->last_g = rdr->last_s = time((time_t *) 0);
	rdr->tcp_connected = 1;
	rdr->available = 1;

	cc->just_logged_in = 1;

	cs_debug_mask(D_FUT, "cc_cli_connect out");
	return 0;
}

int cc_cli_init_int() {
	cs_debug_mask(D_FUT, "cc_cli_init_int");
	struct s_client *cl = &client[cs_idx];
	struct s_reader *rdr = &reader[cl->ridx];
	if (rdr->tcp_connected)
		return -1;

	struct protoent *ptrp;
	int p_proto;

	cl->pfd = 0;
	if (rdr->r_port <= 0) {
		cs_log("%s invalid port %d for server %s", getprefix(),
				rdr->r_port, rdr->device);
		return (1);
	}
	if ((ptrp = getprotobyname("tcp")))
		p_proto = ptrp->p_proto;
	else
		p_proto = 6;

	//		cl->ip = 0;
	//		memset((char *) &loc_sa, 0, sizeof(loc_sa));
	//		loc_sa.sin_family = AF_INET;
	//#ifdef LALL
	//		if (cfg->serverip[0])
	//		loc_sa.sin_addr.s_addr = inet_addr(cfg->serverip);
	//		else
	//#endif
	//		loc_sa.sin_addr.s_addr = INADDR_ANY;
	//		loc_sa.sin_port = htons(rdr->l_port);

	if ((cl->udp_fd = socket(PF_INET, SOCK_STREAM, p_proto)) <= 0) {
		cs_log("%s Socket creation failed (errno=%d, socket=%d)", getprefix(),
				errno, cl->udp_fd);
		return -10;
	}
	//cs_log("%s 1 socket created: cs_idx=%d, fd=%d errno=%d", getprefix(), cs_idx, cl->udp_fd, errno);

#ifdef SO_PRIORITY
	if (cfg->netprio)
		setsockopt(cl->udp_fd, SOL_SOCKET, SO_PRIORITY,
			(void *)&cfg->netprio, sizeof(ulong));
#endif
	rdr->tcp_ito = 1; //60sec...This now invokes ph_idle()
	if (rdr->cc_maxhop <= 0)
		rdr->cc_maxhop = 10;

	memset((char *) &cl->udp_sa, 0, sizeof(cl->udp_sa));
	cl->udp_sa.sin_family = AF_INET;
	cl->udp_sa.sin_port = htons((u_short) rdr->r_port);

	if (rdr->tcp_rto <= 0)
		rdr->tcp_rto = 60 * 60 * 10; // timeout to 10 hours
	cs_debug("cccam: reconnect timeout set to: %d", rdr->tcp_rto);
	cc_check_version(rdr->cc_version, rdr->cc_build);
	cs_log(
			"proxy reader: %s (%s:%d) cccam v%s build %s, maxhop: %d, retry ecm: %d, auto block: %d",
			rdr->label, rdr->device, rdr->r_port,
			rdr->cc_version, rdr->cc_build,
			rdr->cc_maxhop, !rdr->cc_disable_retry_ecm,
			!rdr->cc_disable_auto_block);

	int res = cc_cli_connect();
	if (res < 0)
		cc_cli_close();
	cs_debug_mask(D_FUT, "cc_cli_init out");
	return res;
}

int cc_cli_init() {
	struct s_client *cl = &client[cs_idx];
	if (!cl->cc)
		cc_cli_init_int();
		
	return 0;
}

/**
 * return 1 if we are able to send requests:
 *
 * THREADED: ridx should be replaced with reader-pointer
 */
int cc_available(int ridx, int checktype) {
	struct s_reader *rdr = &reader[ridx];
	struct s_client *cl = &client[rdr->cidx];
	
	//cs_debug_mask(D_TRACE, "checking reader %s availibility", rdr->label);
	if (!cl->cc || rdr->tcp_connected != 2
			|| rdr->card_status != CARD_INSERTED)
		return 1; //Not connected? Connect!

	if (checktype == AVAIL_CHECK_LOADBALANCE && !rdr->available) {
		cs_debug_mask(D_TRACE, "checking reader %s availibility=0 (unavail)",
				rdr->label);
		return 0; //We are processing EMMs/ECMs
	}

	return 1;
}

/**
 *
 *
 **/
void cc_card_info() {
	cs_debug_mask(D_FUT, "cc_card_info in");
	struct s_client *cl = &client[cs_idx];
	struct s_reader *rdr = &reader[cl->ridx];
	
	if (!rdr->tcp_connected)
		cc_cli_init_int();
	cs_debug_mask(D_FUT, "cc_card_info out");
}

void cc_cleanup(void) {
	cs_debug_mask(D_FUT, "cc_cleanup in");
	struct s_client *cl = &client[cs_idx];
	if (!cl->is_server) {
		cc_cli_close(); // we need to close open fd's 
	}
	cc_free(cl->cc);
	cl->cc = NULL;
	cs_debug_mask(D_FUT, "cc_cleanup out");
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
	ph->c_card_info = cc_card_info;
	static PTAB ptab; //since there is always only 1 cccam server running, this is threadsafe
	ptab.ports[0].s_port = cfg->cc_port;
	ph->ptab = &ptab;
	ph->ptab->nports = 1;
	ph->num=R_CCCAM;
}
