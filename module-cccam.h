/*
 * module-cccam.h
 *
 *  Created on: 23.04.2010
 *      Author: alno
 */
#ifndef MODULECCCAM_H_
#define MODULECCCAM_H_

#include "module-obj-llist.h"

#define CC_MAXMSGSIZE 512
#define CC_MAX_PROV   16
#define CC_CAIDINFO_REBUILD 200 //SS: Rebuid Caidinfos after 200 Card-Updates
#define SWAPC(X, Y) do { char p; p = *X; *X = *Y; *Y = p; } while(0)

#if (defined(WIN32) || defined(OS_CYGWIN32)) && !defined(MSG_WAITALL)
#  define MSG_WAITALL 0
#endif

#define MINIMIZE_NONE 0
#define MINIMIZE_HOPS 1
#define MINIMIZE_CAID 2

typedef enum {
	DECRYPT, ENCRYPT
} cc_crypt_mode_t;

typedef enum {
	MSG_CLI_DATA = 0,
	MSG_CW_ECM = 1,
	MSG_EMM_ACK = 2,
	MSG_CARD_REMOVED = 4,
	MSG_CMD_05 = 5,
	MSG_KEEPALIVE = 6,
	MSG_NEW_CARD = 7,
	MSG_SRV_DATA = 8,
	MSG_CMD_0A = 0x0a,
	MSG_CMD_0B = 0x0b,
	MSG_CW_NOK1 = 0xfe, //Node no more available
	MSG_CW_NOK2 = 0xff, //No decoding
	MSG_NO_HEADER = 0xffff
} cc_msg_type_t;

struct cc_crypt_block {
	uint8 keytable[256];
	uint8 state;
	uint8 counter;
	uint8 sum;
};

struct cc_srvid {
	uint16 sid;
	uint8 ecmlen;
};

struct cc_provider {
	ulong prov;  //provider
	uint8 sa[4]; //shared address
};

struct cc_card {
	uint32 id; // cccam card (share) id
	uint32 remote_id;
	uint16 caid;
	uint8 hop;
	uint8 maxdown;
	uint8 hexserial[8]; // card serial (for au)
	LLIST *providers; // providers (struct cc_provider)
	LLIST *badsids; // sids that have failed to decode (struct cc_srvid)
	time_t time;
	LLIST *goodsids; //sids that could decoded (struct cc_srvid)
};

struct cc_reported_carddata {
	uint8 *buf;
	int len;
};

struct cc_auto_blocked {
	uint16 caid;
	uint32 prov;
	struct cc_srvid srvid;
	time_t time;
};

struct cc_current_card {
	struct cc_card *card;
	uint32 prov;
	struct cc_srvid srvid;
};

typedef enum {
	MODE_UNKNOWN = 0,
	MODE_PLAIN = 1,
	MODE_AES = 2,
	MODE_CC_CRYPT = 3,
	MODE_RC4_CRYPT = 4,
	MODE_LEN0 = 5,
} cc_cmd05_mode;

struct cc_extended_ecm_idx {
	uint8 send_idx;
	ushort ecm_idx;
	struct cc_card *card;
	struct cc_srvid srvid;
} EXTENDED_ECM_IDX;

struct cc_data {
	struct cc_crypt_block block[2]; // crypto state blocks
	
	uint8 node_id[8], // client node id
		peer_node_id[8], // server node id
		peer_version[8], // server version
		dcw[16]; // control words
	uint8 cmd0b_aeskey[16];
	uint8 cmd05_aeskey[16];
	struct cc_crypt_block cmd05_cryptkey;

	int is_oscam_cccam;
	int cmd05_active;
	int cmd05_data_len;
	uint8 cmd05_data[256];
	cc_cmd05_mode cmd05_mode;
	int cmd05_offset;
	uint8 receive_buffer[CC_MAXMSGSIZE];
	
	LLIST *cards; // cards list

	int max_ecms;
	int ecm_counter;
	uint32 report_carddata_id; //Server only
	LLIST *reported_carddatas; //struct cc_reported_carddata //struct cc_reported_carddata
	LLIST *auto_blocked; //struct cc_auto_blocked //struct cc_auto_blocked
	int just_logged_in; //true for checking NOK direct after login
	uint8 key_table; //key for CMD 0B

	LLIST *pending_emms; //pending emm list
	
	uint32 recv_ecmtask;

	LLIST *current_cards; //reader: current card cache
	int server_ecm_pending;                    //initialized by server
	LLIST *server_caid_infos[CS_MAXREADER];
	long server_caid_size[CS_MAXREADER];
	ushort server_ecm_idx;
	
	pthread_mutex_t lock;
	pthread_mutex_t ecm_busy;
	struct timeb ecm_time;
	time_t answer_on_keepalive;
	uint8 last_msg;
	
	//Extended Mode for SPECIAL clients:
	int extended_mode;
	LLIST *extended_ecm_idx;
};

int cc_cli_init();
int cc_cli_init_int();
int cc_cli_connect();
int cc_get_nxt_ecm();
int cc_send_pending_emms();
void cc_rc4_crypt(struct cc_crypt_block *block, uint8 *data, int len,
		cc_crypt_mode_t mode);
void free_extended_ecm_idx(struct cc_data *cc);
void cc_free_card(struct cc_card *card);

struct cc_card *read_card_from(int pipe);
int cc_request_server_cards(int ridx, int dest_cs_idx);
void cc_close_request_server_cards(int pipe, int dest_cs_idx);

#endif /* MODULECCCAM_H_ */
