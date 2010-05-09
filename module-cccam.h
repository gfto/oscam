/*
 * module-cccam.h
 *
 *  Created on: 23.04.2010
 *      Author: alno
 */
#include "module-obj-llist.h"

#ifndef MODULECCCAM_H_
#define MODULECCCAM_H_

#define CC_MAXMSGSIZE 512
#define CC_MAX_PROV   16
#define CC_CAIDINFO_REBUILD 200 //SS: Rebuid Caidinfos after 200 Card-Updates

#define SWAPC(X, Y) do { char p; p = *X; *X = *Y; *Y = p; } while(0)

#if (defined(WIN32) || defined(OS_CYGWIN32)) && !defined(MSG_WAITALL)
#  define MSG_WAITALL 0
#endif

typedef enum {
	DECRYPT,
	ENCRYPT
} cc_crypt_mode_t;

typedef enum
{
	MSG_CLI_DATA = 0,
	MSG_CW_ECM = 1,
	MSG_EMM_ACK = 2,
	MSG_CARD_REMOVED = 4,
	MSG_BAD_ECM = 5,
	MSG_KEEPALIVE = 6,
	MSG_NEW_CARD = 7,
	MSG_SRV_DATA = 8,
	MSG_CMD_0B = 0x0b,
	MSG_CW_NOK1 = 0xfe,
	MSG_CW_NOK2 = 0xff,
	MSG_NO_HEADER = 0xffff
} cc_msg_type_t;

struct cc_crypt_block
{
	uint8 keytable[256];
	uint8 state;
	uint8 counter;
	uint8 sum;
};

struct cc_card {
	uint32 id;        // cccam card (share) id
	uint32 sub_id;   // subshare id
	uint16 caid;
	uint8 hop;
	uint8 key[8];     // card serial (for au)
	LLIST *provs;     // providers
	LLIST *badsids;   // sids that have failed to decode
	time_t time;
};

//SS: Hack:
struct cc_reported_carddata {
	uint8 *buf;
	int len;
};

struct cc_caid_info {
	uint16 caid;
	LLIST *provs;
	uint8 hop;
};

struct cc_auto_blocked {
	uint16 caid;
	uint32 prov;
	uint16 sid;
	time_t time;
};

//SS: Hack end

struct cc_data {
	struct cc_crypt_block block[2];    // crypto state blocks

	uint8 node_id[8],           // client node id
	peer_node_id[8],      // server node id
	dcw[16];              // control words

	struct cc_card *cur_card;   // ptr to selected card
	LLIST *cards;               // cards list

	//SS: Hack:
	LLIST *caid_infos;
	long caid_size;
	uint16 needs_rebuild_caidinfo;
	int limit_ecms;
	int max_ecms;
	int ecm_counter;
	int report_carddata_id; //Server only
	LLIST *reported_carddatas; //struct cc_reported_carddata
	LLIST *auto_blocked; //struct cc_auto_blocked
	//SS: Hack end

	uint32 send_ecmtask;
	uint32 recv_ecmtask;
	uint16 cur_sid;

	int last_nok;
	ECM_REQUEST *found;

	unsigned long crc;

	pthread_mutex_t lock;
	pthread_mutex_t ecm_busy;
	pthread_mutex_t list_busy;
};

#endif /* MODULECCCAM_H_ */
