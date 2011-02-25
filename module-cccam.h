/*
 * module-cccam.h
 *
 *  Created on: 23.04.2010
 *      Author: alno
 */
#ifndef MODULECCCAM_H_
#define MODULECCCAM_H_

#include "module-datastruct-llist.h"
#include "globals.h"

#include "cscrypt/rc6.h"
#include "cscrypt/idea.h"

#define CC_MAXMSGSIZE 0x400 //by Project::Keynation: Buffer size is limited on "O" CCCam to 1024 bytes
#define CC_MAX_PROV   32
#define SWAPC(X, Y) do { char p; p = *X; *X = *Y; *Y = p; } while(0)

#if (defined(WIN32) || defined(OS_CYGWIN32)) && !defined(MSG_WAITALL)
#  define MSG_WAITALL 0
#endif

#define MINIMIZE_NONE 0
#define MINIMIZE_HOPS 1
#define MINIMIZE_CAID 2
#define MINIMIZE_TRANSPARENT 3

#define CCCAM_MODE_NOTINIT 0
#define CCCAM_MODE_NORMAL 1
#define CCCAM_MODE_SHUTDOWN 0xFF

#define QUITERROR 1

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
	MSG_CMD_0C = 0x0c, // CCCam 2.2.x fake client checks
	MSG_CMD_0D = 0x0d, // "
	MSG_CMD_0E = 0x0e, // "
	MSG_NEW_CARD_SIDINFO = 0x0f,
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

typedef enum {
		CT_LOCALCARD,
		CT_CARD_BY_SERVICE,
		CT_CARD_BY_CAID,
		CT_REMOTECARD
} cc_card_type;

struct cc_card {
	uint32 internal_id;	
	uint32 id; // cccam card (share) id - reader
	uint32 remote_id;
	uint16 caid;
	uint8 hop;
	uint8 maxdown;
	uint8 hexserial[8]; // card serial (for au)
	LLIST *providers; // providers (struct cc_provider)
	LLIST *badsids; // sids that have failed to decode (struct cc_srvid)
	time_t time;
	LLIST *goodsids; //sids that could decoded (struct cc_srvid)
	LLIST *remote_nodes; //remote note id, 8 bytes
	struct s_reader  *origin_reader;
	uint32 origin_id;
	cc_card_type card_type;
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

typedef enum {
	MODE_CMD_0x0C_NONE = 0,
	MODE_CMD_0x0C_RC6 = 1,
	MODE_CMD_0x0C_RC4 = 2,
	MODE_CMD_0x0C_CC_CRYPT = 3,
	MODE_CMD_0x0C_AES = 4,
	MODE_CMD_0x0C_IDEA = 5,
} cc_cmd0c_mode;


struct cc_extended_ecm_idx {
	uint8 send_idx;
	ushort ecm_idx;
	struct cc_card *card;
	struct cc_srvid srvid;
} EXTENDED_ECM_IDX;

struct cc_data {
	uint8 g_flag;
	char *prefix;

	struct cc_crypt_block block[2]; // crypto state blocks
	
	uint8 node_id[8], // client node id
		peer_node_id[8], // server node id
		peer_version[8], // server version
		dcw[16]; // control words
	uint8 cmd0b_aeskey[16];
	uint8 cmd05_aeskey[16];
	struct cc_crypt_block cmd05_cryptkey;

	uint8 is_oscam_cccam;
	uint8 cmd05_active;
	int cmd05_data_len;
	uint8 cmd05_data[256];
	cc_cmd05_mode cmd05_mode;
	int cmd05_offset;

	cc_cmd0c_mode cmd0c_mode;
	struct cc_crypt_block cmd0c_cryptkey;
	RC6KEY cmd0c_RC6_cryptkey;
	AES_KEY cmd0c_AES_key;
	IDEA_KEY_SCHEDULE cmd0c_IDEA_dkey;

	uint8 receive_buffer[CC_MAXMSGSIZE];
	
	LLIST *cards; // cards list

	int max_ecms;
	int ecm_counter;
	LLIST *reported_carddatas; //struct cc_reported_carddata //struct cc_reported_carddata
	int card_added_count;
	int card_removed_count;
	int card_dup_count;
	uint8 just_logged_in; //true for checking NOK direct after login
	uint8 key_table; //key for CMD 0B

	LLIST *pending_emms; //pending emm list
	
	uint32 recv_ecmtask;

	struct cc_card *last_emm_card;
	int server_ecm_pending;                    //initialized by server
	ushort server_ecm_idx;
	
	pthread_mutex_t lock;
	pthread_mutex_t lockcmd;
	pthread_mutex_t ecm_busy;
	pthread_mutex_t cards_busy;
	struct timeb ecm_time;
	time_t answer_on_keepalive;
	uint8 last_msg;
	uint8 cmd05NOK;

	char remote_version[7];
	char remote_build[7];
	char remote_oscam[200];
	uint8 cccam220;

	uint8 mode;
		
	//Extended Mode for SPECIAL clients:
	uint8 extended_mode;
	LLIST *extended_ecm_idx;
};

int cc_cli_init();
int cc_cli_init_int(struct s_client *cl);
void cc_cleanup(struct s_client *cl);
int cc_cli_connect(struct s_client *cl);
int cc_get_nxt_ecm(struct s_client *cl);
int cc_send_pending_emms(struct s_client *cl);
void cc_rc4_crypt(struct cc_crypt_block *block, uint8 *data, int len,
		cc_crypt_mode_t mode);
void free_extended_ecm_idx(struct cc_data *cc);
void cc_free_card(struct cc_card *card);
int cc_UA_valid(uint8 *ua);
void cc_UA_cccam2oscam(uint8 *in, uint8 *out, uint16 caid);
int cc_cmd_send(struct s_client *cl, uint8 *buf, int len, cc_msg_type_t cmd);
int sid_eq(struct cc_srvid *srvid1, struct cc_srvid *srvid2);
int same_card(struct cc_card *card1, struct cc_card *card2);
void cc_UA_oscam2cccam(uint8 *in, uint8 *out, uint16 caid);
void cc_SA_oscam2cccam(uint8 *in, uint8 *out);
void cc_free_cardlist(LLIST *card_list, int destroy_list);

#endif /* MODULECCCAM_H_ */
