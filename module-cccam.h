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
#define CC_MAX_ECMS   150  // before reconnect
#define CC_MAX_KEEPALIVE 500 //SS: Hack: before reconnect

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
	MSG_CLI_DATA,
	MSG_CW_ECM,
	MSG_CARD_REMOVED = 4,
	MSG_BAD_ECM,
	MSG_KEEPALIVE,
	MSG_NEW_CARD,
	MSG_SRV_DATA,
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
};

//SS: Hack:
struct cc_caid_info {
	uint16 caid;
	LLIST *provs;
};
//SS: Hack end

struct cc_data {
	struct cc_crypt_block block[2];    // crypto state blocks

	uint8 node_id[8],           // client node id
	peer_node_id[8],      // server node id
	dcw[16];              // control words

	struct cc_card *cur_card;   // ptr to selected card
	LLIST *cards;               // cards list
	int card_count;

	//SS: Hack:
	LLIST *caid_infos;
	long caid_size;
	//SS: Hack end

	uint32 count;
	uint32 ecm_count;
	uint32 keepalive_count; //SS: Hack: CycleConnection when >CC_MAX_KEEPALIVE
	uint16 cur_sid;

	int last_nok;
	ECM_REQUEST *found;

	unsigned long crc;

	pthread_mutex_t lock;
	pthread_mutex_t ecm_busy;
};

#endif /* MODULECCCAM_H_ */
