#include "globals.h"
#ifdef MODULE_GBOX

// The following headers are used in parsing mg-encrypted parameter
#if defined(__APPLE__) || defined(__FreeBSD__)
#include <net/if_dl.h>
#include <ifaddrs.h>
#elif defined(__SOLARIS__)
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/sockio.h>
#else
#include <net/if.h>
#endif

#include "module-gbox.h"
#include "module-gbox-helper.h"
#include "module-cccam.h"
#include "module-cccam-data.h"
#include "oscam-failban.h"
#include "oscam-client.h"
#include "oscam-ecm.h"
#include "oscam-lock.h"
#include "oscam-net.h"
#include "oscam-chk.h"
#include "oscam-string.h"
#include "oscam-time.h"
#include "oscam-reader.h"
#include "oscam-garbage.h"

#define FILE_GBOX_VERSION       "/tmp/gbx.ver"
#define FILE_SHARED_CARDS_INFO  "/tmp/gbx_card.info"
#define FILE_ATTACK_INFO        "/tmp/gbx_attack.txt"
#define FILE_GBOX_PEER_ONL  	"/tmp/gbx_peer.onl"

#define GBOX_STAT_HELLOL	0
#define GBOX_STAT_HELLOS	1
#define GBOX_STAT_HELLOR	2
#define GBOX_STAT_HELLO3	3
#define GBOX_STAT_HELLO4	4

#define RECEIVE_BUFFER_SIZE	1024

#define LOCAL_GBOX_MAJOR_VERSION	0x02
#define LOCAL_GBOX_MINOR_VERSION	0x25
#define LOCAL_GBOX_TYPE			0x40

enum
{
	MSG_ECM = 0x445c,
	MSG_CW = 0x4844,
	MSG_HELLO = 0xddab,
	MSG_HELLO1 = 0x4849,
	MSG_CHECKCODE = 0x41c0,
	MSG_GOODBYE = 0x9091,
	MSG_GSMS_ACK = 0x9098,
	MSG_GSMS = 0xff0,
	MSG_BOXINFO = 0xa0a1,
	MSG_UNKNWN1 = 0x9099,
	MSG_UNKNWN2 = 0x48F9,
};

struct gbox_srvid
{
	uint16_t sid;
	uint16_t peer_idcard;
	uint32_t provid_id;
};

struct gbox_card
{
	uint16_t peer_id;
	uint16_t caid;
	uint32_t provid;
	uint32_t provid_1;
	uint8_t slot;
	uint8_t dist;
	uint8_t lvl;
	LLIST *badsids; // sids that have failed to decode (struct cc_srvid)
	LLIST *goodsids; //sids that could be decoded (struct cc_srvid)
};

struct gbox_data
{
	uint16_t id;
	uchar password[4];
	uchar checkcode[7];
	uint8_t minor_version;
	uint8_t type;
	LLIST *cards;
};

struct gbox_peer
{
	struct gbox_data gbox;
	uchar *hostname;
	int32_t online;
	int32_t hello_stat;
	int32_t goodbye_cont;
	uchar ecm_idx;
	uchar gbox_count_ecm;
	CS_MUTEX_LOCK lock;
	pthread_mutex_t hello_expire_mut;
	pthread_cond_t hello_expire_cond;
};

static struct gbox_data local_gbox;

static void    gbox_send_boxinfo(struct s_client *cli);
static void    gbox_send_hello(struct s_client *cli);
static void    gbox_send_hello_packet(struct s_client *cli, int8_t number, uchar *outbuf, uchar *ptr, int32_t nbcards);
static void    gbox_send_checkcode(struct s_client *cli);
static void    gbox_expire_hello(struct s_client *cli);
static void    gbox_local_cards(struct s_client *cli);
static void    gbox_init_ecm_request_ext(struct gbox_ecm_request_ext *ere); 	
static int32_t gbox_client_init(struct s_client *cli);
static int8_t gbox_check_header(struct s_client *cli, uchar *data, int32_t l);
static int8_t gbox_incoming_ecm(struct s_client *cli, uchar *data, int32_t n);
static int32_t gbox_recv_chk(struct s_client *cli, uchar *dcw, int32_t *rc, uchar *data, int32_t UNUSED(n));
static int32_t gbox_checkcode_recv(struct s_client *cli, uchar *checkcode);
static int32_t gbox_decode_cmd(uchar *buf);
static uint8_t gbox_compare_pw(uchar *my_pw, uchar *rec_pw);
static uint16_t gbox_convert_password_to_id(uchar *password);
uint32_t gbox_get_ecmchecksum(ECM_REQUEST *er);
static void	init_local_gbox(void);

void gbox_write_peer_onl(void)
{
	FILE *fhandle = fopen(FILE_GBOX_PEER_ONL, "w");
	if(!fhandle)
	{
		cs_log("Couldn't open %s: %s\n", FILE_GBOX_PEER_ONL, strerror(errno));
		return;
	}
	struct s_client *cl;
	for(cl = first_client; cl; cl = cl->next)
	{
		if(cl->gbox && cl->typ == 'p')
		{
			struct gbox_peer *peer = cl->gbox;
			if (peer->online)
				{ fprintf(fhandle, "1 %s  %s %04X 2.%02X\n",cl->reader->device, cs_inet_ntoa(cl->ip),peer->gbox.id, peer->gbox.minor_version); }
			else
				{ fprintf(fhandle, "0 %s  %s %04X 0.00\n",cl->reader->device, cs_inet_ntoa(cl->ip),peer->gbox.id); }
		}
	}
	fclose(fhandle);
	return;
}	

void gbox_write_version(void)
{
	FILE *fhandle = fopen(FILE_GBOX_VERSION, "w");
	if(!fhandle)
	{
		cs_log("Couldn't open %s: %s\n", FILE_GBOX_VERSION, strerror(errno));
		return;
	}
	fprintf(fhandle, "%02X.%02X\n", LOCAL_GBOX_MAJOR_VERSION, LOCAL_GBOX_MINOR_VERSION);
	fclose(fhandle);
}

void gbox_write_shared_cards_info(void)
{
	int32_t card_count = 0;
	int32_t i = 0;

	FILE *fhandle;
	fhandle = fopen(FILE_SHARED_CARDS_INFO, "w");
	if(!fhandle)
	{
		cs_log("Couldn't open %s: %s\n", FILE_SHARED_CARDS_INFO, strerror(errno));
		return;
	}

	LL_ITER it;
	struct gbox_card *card;

	//write local cards
	it = ll_iter_create(local_gbox.cards);
	while((card = ll_iter_next(&it)))
	{
		fprintf(fhandle, "CardID %4d at oscam Card %08X Sl:%2d Lev:%2d dist:%2d id:%04X\n",
				card_count, card->provid_1,
				card->slot, card->lvl, card->dist, card->peer_id);
		card_count++;
	} // end of while ll_iter_next

	struct s_client *cl;
	for(i = 0, cl = first_client; cl; cl = cl->next, i++)
	{
		if(cl->gbox)
		{
			struct gbox_peer *peer = cl->gbox;

			if((cl->reader->card_status == CARD_INSERTED) && (cl->typ == 'p'))
			{
				it = ll_iter_create(peer->gbox.cards);
				while((card = ll_iter_next(&it)))
				{
					fprintf(fhandle, "CardID %4d at %s Card %08X Sl:%2d Lev:%2d dist:%2d id:%04X\n",
							card_count, cl->reader->device, card->provid_1,
							card->slot, card->lvl, card->dist, card->peer_id);
					card_count++;
				} // end of while ll_iter_next
			} // end of if INSERTED && 'p'
		} // end of if cl->gbox
	} // end of for cl->next
	fclose(fhandle);
	return;
}

void hostname2ip(char *hostname, IN_ADDR_T *ip)
{
	cs_resolve(hostname, ip, NULL, NULL);
}

static uint8_t gbox_compare_pw(uchar *my_pw, uchar *rec_pw)
{
	return my_pw[0] == rec_pw[0] && my_pw[1] == rec_pw[1] && my_pw[2] == rec_pw[2] && my_pw[3] == rec_pw[3];
}

static uint16_t gbox_convert_password_to_id(uchar *password)
{
	return (password[0] ^ password[2]) << 8 | (password[1] ^ password[3]);
}

void gbox_add_good_card(struct s_client *cl, uint16_t id_card, uint16_t caid, uint32_t prov, uint16_t sid_ok)
{
	struct gbox_peer *peer = cl->gbox;
	struct gbox_card *card = NULL;
	struct gbox_srvid *srvid = NULL;
	LL_ITER it = ll_iter_create(peer->gbox.cards);
	while((card = ll_iter_next(&it)))
	{
		if(card->peer_id == id_card && card->caid == caid && card->provid == prov)
		{
			cl->reader->currenthops = card->dist;
			LL_ITER it2 = ll_iter_create(card->goodsids);
			while((srvid = ll_iter_next(&it2)))
			{
				if(srvid->sid == sid_ok)
				{
					return; // sid_ok is already in the list of goodsids
				}
			}

			LL_ITER it3 = ll_iter_create(card->badsids);
			while((srvid = ll_iter_next(&it3)))
			{
				if(srvid->sid == sid_ok)
				{
					ll_iter_remove_data(&it3); // remove sid_ok from badsids
					break;
				}
			}

			if(!cs_malloc(&srvid, sizeof(struct gbox_srvid)))
				{ return; }
			srvid->sid = sid_ok;
			srvid->peer_idcard = id_card;
			srvid->provid_id = card->provid;
			cs_debug_mask(D_READER, "GBOX Adding good SID: %04X for CAID: %04X Provider: %04X on CardID: %04X\n", sid_ok, caid, card->provid, id_card);
			ll_append(card->goodsids, srvid);
			break;
		}
	}//end of ll_iter_next
	//return dist_c;
}

void gbox_free_card(struct gbox_card *card)
{
	ll_destroy_data_NULL(card->badsids);
	ll_destroy_data_NULL(card->goodsids);
	add_garbage(card);
	return;
}

void gbox_remove_cards_without_goodsids(LLIST *card_list)
{
	if(card_list)
	{
		LL_ITER it = ll_iter_create(card_list);
		struct gbox_card *card;
		while((card = ll_iter_next(&it)))
		{
			if(ll_count(card->goodsids) == 0)
			{
				ll_iter_remove(&it);
				gbox_free_card(card);
			}
			else
			{
				ll_destroy_data_NULL(card->badsids);
			}
		}
	}
	return;
}

void gbox_free_cardlist(LLIST *card_list)
{
	if(card_list)
	{
		LL_ITER it = ll_iter_create(card_list);
		struct gbox_card *card;
		while((card = ll_iter_next_remove(&it)))
		{
			gbox_free_card(card);
		}
		ll_destroy_NULL(card_list);
	}
	return;
}

void gbox_init_ecm_request_ext(struct gbox_ecm_request_ext *ere)
{
/*	
	ere->gbox_crc = 0;
	ere->gbox_ecm_id = 0;
	ere->gbox_ecm_ok = 0;
*/	
	ere->gbox_hops = 0;
	ere->gbox_peer = 0;                		
	ere->gbox_mypeer = 0;
	ere->gbox_caid = 0;
	ere->gbox_prid = 0;
	ere->gbox_slot = 0;
	ere->gbox_version = 0;
	ere->gbox_unknown = 0;
	ere->gbox_type = 0;
}

struct s_client *get_gbox_proxy(uint16_t gbox_id)
{
	struct s_client *cl;
	for(cl = first_client; cl; cl = cl->next)
	{
		if(cl->typ == 'p' && cl->gbox && cl->gbox_peer_id == gbox_id)
		{
			return cl;
		}
	}
	return NULL;
}

// if input client is typ proxy get client and vice versa
struct s_client *switch_client_proxy(struct s_client *cli, uint16_t gbox_id)
{
	struct s_client *cl;
	int8_t typ;
	if(cli->typ == 'c')
		{ typ = 'p'; }
	else
		{ typ = 'c'; }
	for(cl = first_client; cl; cl = cl->next)
	{
		if(cl->typ == typ && cl->gbox && cl->gbox_peer_id == gbox_id)
		{
			return cl;
		}
	}
	return cli;
}

void gbox_reconnect_client(uint16_t gbox_id)
{
	struct s_client *cl;
	for(cl = first_client; cl; cl = cl->next)
	{
		if(cl->gbox && cl->typ == 'p' && cl->gbox_peer_id == gbox_id)
		{
			hostname2ip(cl->reader->device, &SIN_GET_ADDR(cl->udp_sa));
			SIN_GET_FAMILY(cl->udp_sa) = AF_INET;
			SIN_GET_PORT(cl->udp_sa) = htons((uint16_t)cl->reader->r_port);
			hostname2ip(cl->reader->device, &(cl->ip));
			cl->reader->tcp_connected = 0;
			cl->reader->card_status = CARD_NEED_INIT;
			struct gbox_peer *peer = cl->gbox;
			peer->online = 0;
			peer->ecm_idx = 0;
			peer->hello_stat = GBOX_STAT_HELLOL;
			cl->reader->last_s = cl->reader->last_g = 0;
			gbox_free_cardlist(peer->gbox.cards);
			peer->gbox.cards = ll_create("peer.cards");
			gbox_send_hello(cl);
		}
	}
}

static void *gbox_server(struct s_client *cli, uchar *b, int32_t l)
{
	if(l > 0)
	{
		cs_log("gbox:  gbox_server %s/%d", cli->reader->label, cli->port);
		gbox_check_header(cli, b, l);
	}
	return 0;
}

char *gbox_username(struct s_client *client)
{
	if(!client) { return "anonymous"; }
	if(client->reader)
		if(client->reader->r_usr[0])
		{
			return client->reader->r_usr;
		}
	return "anonymous";
}

static int8_t gbox_auth_client(struct s_client *cli, uchar *gbox_password)
{
	uint16_t gbox_id = gbox_convert_password_to_id(gbox_password);
	struct s_client *cl = switch_client_proxy(cli, gbox_id);
	if (cl->gbox)
	{
		struct gbox_peer *peer = cl->gbox;
		if (!gbox_compare_pw(&peer->gbox.password[0],gbox_password))
			{ return -1; }
	}
	if(cl->typ == 'p' && cl->gbox && cl->reader)
	{
		cli->crypted = 1; //display as crypted
		cli->gbox = cl->gbox; //point to the same gbox as proxy
		cli->reader = cl->reader; //point to the same reader as proxy
		cli->gbox_peer_id = cl->gbox_peer_id; //signal authenticated

		struct s_auth *account = get_account_by_name(gbox_username(cl));
		if(account)
		{
			cs_auth_client(cli, account, NULL);
			cli->account = account;
			cli->grp = account->grp;
			return 0;
		}
	}
	return -1;
}

static void gbox_server_init(struct s_client *cl)
{
	if(!cl->init_done)
	{
		if(IP_ISSET(cl->ip))
			{ cs_log("gbox: new connection from %s", cs_inet_ntoa(cl->ip)); }
		//We cannot authenticate here, because we don't know gbox pw
		cl->gbox_peer_id = NO_GBOX_ID;
		cl->init_done = 1;
	}
	return;
}

int32_t gbox_cmd_hello(struct s_client *cli, uchar *data, int32_t n)
{
	struct gbox_peer *peer = cli->gbox;
	int32_t i;
	int32_t ncards_in_msg = 0;
	int32_t payload_len = n;
	//TODO: checkcode_len can be made void
	int32_t checkcode_len = 0;
	int32_t hostname_len = 0;
	int32_t footer_len = 0;
	uint8_t *ptr = 0;

	if(!(gbox_decode_cmd(data) == MSG_HELLO1)) 
	{
		gbox_decompress(data, &payload_len);
	}
	cs_ddump_mask(D_READER, data, payload_len, "gbox: decompressed data (%d bytes):", payload_len);

	if((data[0x0B] == 0) | ((data[0x0A] == 1) && (data[0x0B] == 0x80)))
	{
		if(peer->gbox.cards)
			{ gbox_remove_cards_without_goodsids(peer->gbox.cards); }
		else
			{ peer->gbox.cards = ll_create("peer.cards"); }
	}
	if((data[0xB] & 0xF) == 0)
	{
		checkcode_len = 7;
		hostname_len = data[payload_len - 1];
		footer_len = hostname_len + 2;
	}

	if(gbox_decode_cmd(data) == MSG_HELLO1)
		{ ptr = data + 11; }
	else
		{ ptr = data + 12; }

	while(ptr < data + payload_len - footer_len - checkcode_len - 1)
	{
		uint16_t caid;
		uint32_t provid;
		uint32_t provid1;

		switch(ptr[0])
		{
			//Viaccess
		case 0x05:
			caid = ptr[0] << 8;
			provid =  ptr[1] << 16 | ptr[2] << 8 | ptr[3];
			break;
			//Cryptoworks
		case 0x0D:
			caid = ptr[0] << 8 | ptr[1];
			provid =  ptr[2];
			break;
		default:
			caid = ptr[0] << 8 | ptr[1];
			provid =  ptr[2] << 8 | ptr[3];
			break;
		}

		//caid check
		if(chk_ctab(caid, &cli->reader->ctab))
		{

			provid1 =  ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];
			uint8_t ncards = ptr[4];

			ptr += 5;

			for(i = 0; i < ncards; i++)
			{
				// for all n cards and current caid/provid,
				// create card info from data and add card to peer.cards
				struct gbox_card *card;
				if(!cs_malloc(&card, sizeof(struct gbox_card)))
					{ continue; }

				card->caid = caid;
				card->provid = provid;
				card->provid_1 = provid1;
				card->slot = ptr[0];
				card->dist = ptr[1] & 0xf;
				card->lvl = ptr[1] >> 4;
				card->peer_id = ptr[2] << 8 | ptr[3];
				ptr += 4;

				if((cli->reader->gbox_maxdist >= card->dist) && (card->peer_id != local_gbox.id))
				{

					LL_ITER it = ll_iter_create(peer->gbox.cards);
					struct gbox_card *card_s;
					uint8_t v_card = 0;
					while((card_s = ll_iter_next(&it)))    // don't add card if already in peer.cards list
					{
						if(card_s->peer_id == card->peer_id && card_s->provid_1 == card->provid_1)
						{
							gbox_free_card(card);
							card = NULL;
							v_card = 1;
							break;
						}
					}

					if(v_card != 1)    // new card - not in list
					{
						card->badsids = ll_create("badsids");
						card->goodsids = ll_create("goodsids");
						ll_append(peer->gbox.cards, card);
						ncards_in_msg++;
						cs_debug_mask(D_READER, "   card: caid=%04x, provid=%06x, slot=%d, level=%d, dist=%d, peer=%04x",
									  card->caid, card->provid, card->slot, card->lvl, card->dist, card->peer_id);
					}
				}
				else     // don't add card
				{
					gbox_free_card(card);
					card = NULL;
				}
				cli->reader->tcp_connected = 2; // we have card
			} // end for ncards
		}
		else
		{
			ptr += 5 + ptr[4] * 4; //skip cards because caid
		}
	} // end while caid/provid

	if(!(data[0x0B] & 0xF))  // first packet. We've got peer hostname
	{
		NULLFREE(peer->hostname);
		if(!cs_malloc(&peer->hostname, hostname_len + 1))
		{
			cs_writeunlock(&peer->lock);
			return -1;
		}
		memcpy(peer->hostname, data + payload_len - 1 - hostname_len, hostname_len);
		peer->hostname[hostname_len] = '\0';

		gbox_checkcode_recv(cli, data + payload_len - footer_len - checkcode_len - 1);
		peer->gbox.minor_version = data[payload_len - footer_len - 1];
		peer->gbox.type = data[payload_len - footer_len];
	} // end if first hello packet

	if(data[0x0B] & 0x80)   //last packet
	{
		peer->online = 1;
		if(!data[0xA])
		{
			cs_log("<-HelloS from %s (%s:%d) V2.%02X with %d cards", cli->reader->label, cs_inet_ntoa(cli->ip), cli->reader->r_port, peer->gbox.minor_version, ncards_in_msg);
			peer->hello_stat = GBOX_STAT_HELLOR;
			gbox_send_hello(cli);
		}
		else
		{
			cs_log("<-HelloR from %s (%s:%d) V2.%02X with %d cards", cli->reader->label, cs_inet_ntoa(cli->ip), cli->reader->r_port, peer->gbox.minor_version, ncards_in_msg);
			gbox_send_checkcode(cli);
		}
		if(peer->hello_stat == GBOX_STAT_HELLOS)
		{
			gbox_send_hello(cli);
		}
		cli->reader->tcp_connected = 2; //we have card
		cli->reader->card_status = CARD_INSERTED;
		if(ll_count(peer->gbox.cards) == 0)
			{ cli->reader->card_status = NO_CARD; }

		gbox_write_shared_cards_info();
		gbox_write_version();
		gbox_write_peer_onl();
	}
	return 0;
}

static int8_t gbox_incoming_ecm(struct s_client *cli, uchar *data, int32_t n)
{
	struct gbox_peer *peer;
	struct s_client *cl;
	int32_t diffcheck = 0;

	cl = switch_client_proxy(cli, cli->gbox_peer_id);
	peer = cl->gbox;

	// No ECMs with length < 8 expected
	if ((((data[19] & 0x0f) << 8) | data[20]) < 8) { return -1; }

	// GBOX_MAX_HOPS not violated
	if (data[n - 15] + 1 > GBOX_MAXHOPS) { return -1; }

	ECM_REQUEST *er;
	if(!(er = get_ecmtask())) { return -1; }

	struct gbox_ecm_request_ext *ere;
	if(!cs_malloc(&ere, sizeof(struct gbox_ecm_request_ext)))
	{
        	cs_writeunlock(&peer->lock);
              	return -1;
	}

	uchar *ecm = data + 18; //offset of ECM in gbx message

	er->src_data = ere;                
	gbox_init_ecm_request_ext(ere);

	peer->gbox_count_ecm++;
	er->gbox_ecm_id = peer->gbox.id;

	if(peer->ecm_idx == 100) { peer->ecm_idx = 0; }

	er->idx = peer->ecm_idx++;
	er->ecmlen = (((ecm[1] & 0x0f) << 8) | ecm[2]) + 3;

	er->pid = data[10] << 8 | data[11];
	er->srvid = data[12] << 8 | data[13];

	int32_t adr_caid_1 = (((data[19] & 0x0f) << 8) | data[20]) + 26;
	if(data[adr_caid_1] == 0x05)
		{ er->caid = (data[adr_caid_1] << 8); }
	else
		{ er->caid = (data[adr_caid_1] << 8 | data[adr_caid_1 + 1]); }

//	ei->extra = data[14] << 8 | data[15];
	memcpy(er->ecm, data + 18, er->ecmlen);
	ere->gbox_peer = ecm[er->ecmlen] << 8 | ecm[er->ecmlen + 1];
	ere->gbox_version = ecm[er->ecmlen + 2];
	ere->gbox_unknown = ecm[er->ecmlen + 3];
	ere->gbox_type = ecm[er->ecmlen + 4];
	ere->gbox_caid = ecm[er->ecmlen + 5] << 8 | ecm[er->ecmlen + 6];
	ere->gbox_prid = ecm[er->ecmlen + 7] << 8 | ecm[er->ecmlen + 8];
	ere->gbox_mypeer = ecm[er->ecmlen + 10] << 8 | ecm[er->ecmlen + 11];
	ere->gbox_slot = ecm[er->ecmlen + 12];

	diffcheck = gbox_checkcode_recv(cl, data + n - 14);
	//TODO: What do we do with our own checkcode @-7?
	er->gbox_crc = gbox_get_ecmchecksum(er);
	ere->gbox_hops = data[n - 15] + 1;
	memcpy(&ere->gbox_routing_info[0], &data[n - 15 - ere->gbox_hops + 1], ere->gbox_hops - 1);

	er->prid = chk_provid(er->ecm, er->caid);
	cs_debug_mask(D_READER, "<- ECM (%d<-) from server (%s:%d) to cardserver (%04X) SID %04X", ere->gbox_hops, peer->hostname, cli->port, ere->gbox_peer, er->srvid);
	get_cw(cl, er);

	//checkcode did not match gbox->peer checkcode
	if(diffcheck)
	{
		//        TODO: Send HelloS here?
		//        gbox->peer.hello_stat = GBOX_STAT_HELLOS;
		//                gbox_send_hello(cli);
	}
	return 0;
}

int32_t gbox_cmd_switch(struct s_client *cli, uchar *data, int32_t n)
{
	struct gbox_peer *peer = cli->gbox;
	int32_t n1 = 0, rc1 = 0, i1, idx;
	uchar dcw[16];

	switch(gbox_decode_cmd(data))
	{
	case MSG_BOXINFO:
		// Keep alive message
		pthread_mutex_lock(&peer->hello_expire_mut);
		pthread_cond_signal(&peer->hello_expire_cond);
		pthread_mutex_unlock(&peer->hello_expire_mut);
		gbox_send_hello(cli);
		break;
	case MSG_GOODBYE:
		//needfix what to do after Goodbye?
		//suspect: we get goodbye as signal of SID not found
		break;
	case MSG_HELLO1:
	case MSG_HELLO:
		if(gbox_cmd_hello(cli, data, n) < 0)
			{ return -1; }
		pthread_mutex_lock(&peer->hello_expire_mut);
		pthread_cond_signal(&peer->hello_expire_cond);
		pthread_mutex_unlock(&peer->hello_expire_mut);
		break;
	case MSG_CW:
		cli->last = time((time_t *)0);
		idx = gbox_recv_chk(cli, dcw, &rc1, data, rc1);
		if(idx < 0) { break; }  // no dcw received
		if(!idx) { idx = cli->last_idx; }
		cli->reader->last_g = time((time_t *)0); // for reconnect timeout
		for(i1 = 0, n1 = 0; i1 < cfg.max_pending && n1 == 0; i1++)
		{
			if(cli->ecmtask[i1].idx == idx)
			{
				cli->pending--;
				casc_check_dcw(cli->reader, i1, rc1, dcw);
				n1++;
			}
		}
		pthread_mutex_lock(&peer->hello_expire_mut);
		pthread_cond_signal(&peer->hello_expire_cond);
		pthread_mutex_unlock(&peer->hello_expire_mut);
		break;
	case MSG_CHECKCODE:
		gbox_checkcode_recv(cli, data + 10);
		pthread_mutex_lock(&peer->hello_expire_mut);
		pthread_cond_signal(&peer->hello_expire_cond);
		pthread_mutex_unlock(&peer->hello_expire_mut);
		break;
	case MSG_ECM:
	{
		gbox_incoming_ecm(cli, data, n);
		break;
	}
	default:
		cs_ddump_mask(D_READER, data, n, "gbox: unknown data received (%d bytes):", n);
	} // end switch
	return 0;
}

static int8_t gbox_check_header(struct s_client *cli, uchar *data, int32_t l)
{
	struct s_client *cl = switch_client_proxy(cli, cli->gbox_peer_id);

	//clients may timeout - attach to peer's gbox/reader
	cli->gbox = cl->gbox; //point to the same gbox as proxy
	cli->reader = cl->reader; //point to the same reader as proxy

	struct gbox_peer *peer = cl->gbox;

	char tmp[0x50];
	int32_t n = l;
	cs_ddump_mask(D_READER, data, n, "gbox: encrypted data received (%d bytes):", n);

	if(gbox_decode_cmd(data) == MSG_HELLO1)
		{ cs_log("test cs2gbox"); }
	else
		{ gbox_decrypt(data, n, local_gbox.password); }

	cs_ddump_mask(D_READER, data, n, "gbox: decrypted received data (%d bytes):", n);

	//verify my pass received
	if (gbox_compare_pw(&data[2],&local_gbox.password[0]))
	{
		cs_debug_mask(D_READER, "received data, peer : %04x   data: %s", cli->gbox_peer_id, cs_hexdump(0, data, l, tmp, sizeof(tmp)));

		if (gbox_decode_cmd(data) != MSG_CW)
		{
			if (cli->gbox_peer_id == NO_GBOX_ID)
			{
				if (gbox_auth_client(cli, &data[6]) < 0)
					{ return -1; }
				//NEEDFIX: Pretty sure this should not be done here
				gbox_local_cards(cli);	
				cl = switch_client_proxy(cli, cli->gbox_peer_id);

				//clients may timeout - attach to peer's gbox/reader
				cli->gbox = cl->gbox; //point to the same gbox as proxy
				cli->reader = cl->reader; //point to the same reader as proxy

				peer = cl->gbox;
			}
			if (!peer) { return -1; }
			if (!gbox_compare_pw(&data[6],&peer->gbox.password[0]))
			{
				cs_log("gbox peer: %04X sends wrong password", peer->gbox.id);
				return -1;
				//continue; // next client
			}
		} else 
		{
			// if my pass ok verify CW | pass to peer
			if((data[39] != ((local_gbox.id >> 8) & 0xff)) || (data[40] != (local_gbox.id & 0xff)))
			{
				cs_log("gbox peer: %04X sends CW for other than my id: %04X", cli->gbox_peer_id, local_gbox.id);
				return -1;
				//continue; // next client
			}
		}
	}  // error my pass
	else
	{
		cs_log("gbox: ATTACK ALERT: proxy %s:%d", cs_inet_ntoa(cli->ip), cli->reader->r_port);
		cs_log("received data, peer : %04x   data: %s", cli->gbox_peer_id, cs_hexdump(0, data, n, tmp, sizeof(tmp)));
		return -1;
		//continue; // next client
	}

	if (!IP_EQUAL(cli->ip, cl->ip))
	{ 
		gbox_reconnect_client(cli->gbox_peer_id); 
		return -1;	
	}

	if(!peer) { return -1; }
	
	cli->last = time((time_t *)0);

	cs_writelock(&peer->lock);
	if(gbox_cmd_switch(cl, data, n) < 0)
		{ return -1; }
	cs_writeunlock(&peer->lock);

	return 0;
}

static int32_t gbox_decode_cmd(uchar *buf)
{
	return buf[0] << 8 | buf[1];
}

void gbox_code_cmd(uchar *buf, int16_t cmd)
{
	buf[0] = cmd >> 8;
	buf[1] = cmd & 0xff;
}

static void gbox_calc_checkcode(void)
{
	int32_t i = 0;
	struct s_client *cl;
	
	local_gbox.checkcode[0] = 0x15;
	local_gbox.checkcode[1] = 0x30;
	local_gbox.checkcode[2] = 0x02;
	local_gbox.checkcode[3] = 0x04;
	local_gbox.checkcode[4] = 0x19;
	local_gbox.checkcode[5] = 0x19;
	local_gbox.checkcode[6] = 0x66;

	LL_ITER it = ll_iter_create(local_gbox.cards);
	struct gbox_card *card;
	while((card = ll_iter_next(&it)))
	{
		local_gbox.checkcode[0] ^= (0xFF & (card->provid_1 >> 24));
		local_gbox.checkcode[1] ^= (0xFF & (card->provid_1 >> 16));
		local_gbox.checkcode[2] ^= (0xFF & (card->provid_1 >> 8));
		local_gbox.checkcode[3] ^= (0xFF & (card->provid_1));
		local_gbox.checkcode[4] ^= (0xFF & (card->slot));
		local_gbox.checkcode[5] ^= (0xFF & (card->peer_id >> 8));
		local_gbox.checkcode[6] ^= (0xFF & (card->peer_id));
	}
	for(i = 0, cl = first_client; cl; cl = cl->next, i++)
	{
		if (cl->gbox && cl->typ == 'p')
		{
			struct gbox_peer *peer = cl->gbox;
			it = ll_iter_create(peer->gbox.cards);
			while((card = ll_iter_next(&it)))
			{
				local_gbox.checkcode[0] ^= (0xFF & (card->provid_1 >> 24));
				local_gbox.checkcode[1] ^= (0xFF & (card->provid_1 >> 16));
				local_gbox.checkcode[2] ^= (0xFF & (card->provid_1 >> 8));
				local_gbox.checkcode[3] ^= (0xFF & (card->provid_1));
				local_gbox.checkcode[4] ^= (0xFF & (card->slot));
				local_gbox.checkcode[5] ^= (0xFF & (card->peer_id >> 8));
				local_gbox.checkcode[6] ^= (0xFF & (card->peer_id));
			}
		}	
	}
}

//returns 1 if checkcode changed / 0 if not
static int32_t gbox_checkcode_recv(struct s_client *cli, uchar *checkcode)
{
	struct gbox_peer *peer = cli->gbox;
	char tmp[7];

	if(memcmp(peer->gbox.checkcode, checkcode, 7))
	{
		memcpy(peer->gbox.checkcode, checkcode, 7);
		cs_debug_mask(D_READER, "gbox: received new checkcode=%s",  cs_hexdump(0, peer->gbox.checkcode, 7, tmp, sizeof(tmp)));
		return 1;
	}
	return 0;
}

uint32_t gbox_get_ecmchecksum(ECM_REQUEST *er)
{

	uint8_t checksum[4];
	int32_t counter;

	checksum[3] = er->ecm[0];
	checksum[2] = er->ecm[1];
	checksum[1] = er->ecm[2];
	checksum[0] = er->ecm[3];

	for(counter = 1; counter < (er->ecmlen / 4) - 4; counter++)
	{
		checksum[3] ^= er->ecm[counter * 4];
		checksum[2] ^= er->ecm[counter * 4 + 1];
		checksum[1] ^= er->ecm[counter * 4 + 2];
		checksum[0] ^= er->ecm[counter * 4 + 3];
	}

	return checksum[3] << 24 | checksum[2] << 16 | checksum[1] << 8 | checksum[0];
}

static void gbox_expire_hello(struct s_client *cli)
{
	struct gbox_peer *peer = cli->gbox;
	int32_t callback = 60;

	set_thread_name(__func__);

	cs_pthread_cond_init(&peer->hello_expire_mut, &peer->hello_expire_cond);

	while(1)
	{
		struct timespec ts;
		add_ms_to_timespec(&ts, callback * 1000);

		pthread_mutex_lock(&peer->hello_expire_mut);
		if(pthread_cond_timedwait(&peer->hello_expire_cond, &peer->hello_expire_mut, &ts) == ETIMEDOUT)
		{
			switch(peer->hello_stat)
			{
			case GBOX_STAT_HELLOS:
				peer->hello_stat = GBOX_STAT_HELLOL;
				gbox_send_hello(cli);
				callback = 180;
				break;

			case GBOX_STAT_HELLOR:
				callback = 300;
				break;

			case GBOX_STAT_HELLO3:
				peer->hello_stat = GBOX_STAT_HELLOS;
				//          gbox_send_boxinfo(cli);
				//          gbox_send_hello(cli);
				callback = 900;
				peer->hello_stat = GBOX_STAT_HELLO3;
				break;

			case GBOX_STAT_HELLO4:
				gbox_send_boxinfo(cli);
				break;
			}
		}
		pthread_mutex_unlock(&peer->hello_expire_mut);
	}
}

static void gbox_send(struct s_client *cli, uchar *buf, int32_t l)
{
	struct gbox_peer *peer = cli->gbox;

	cs_ddump_mask(D_READER, buf, l, "gbox: decrypted data send (%d bytes):", l);

	hostname2ip(cli->reader->device, &SIN_GET_ADDR(cli->udp_sa));
	SIN_GET_FAMILY(cli->udp_sa) = AF_INET;
	SIN_GET_PORT(cli->udp_sa) = htons((uint16_t)cli->reader->r_port);

	gbox_encrypt(buf, l, peer->gbox.password);
	sendto(cli->udp_fd, buf, l, 0, (struct sockaddr *)&cli->udp_sa, cli->udp_sa_len);
	cs_ddump_mask(D_READER, buf, l, "gbox: encrypted data send (%d bytes):", l);
}

static void gbox_send_hello_packet(struct s_client *cli, int8_t number, uchar *outbuf, uchar *ptr, int32_t nbcards)
{
	struct gbox_peer *peer = cli->gbox;
	int32_t hostname_len = strlen(cfg.gbox_hostname);
	int32_t len;

	gbox_code_cmd(outbuf, MSG_HELLO);
	memcpy(outbuf + 2, peer->gbox.password, 4);
	memcpy(outbuf + 6, local_gbox.password, 4);
	// initial HELLO = 0, subsequent = 1
	if(peer->hello_stat > GBOX_STAT_HELLOS)
		{ outbuf[10] = 1; }
	else
		{ outbuf[10] = 0; }
	outbuf[11] = number;    // 0x80 (if last packet) else 0x00 | packet number

	if((number & 0x0F) == 0)
	{
		gbox_calc_checkcode();
		if(peer->hello_stat != GBOX_STAT_HELLOL)
			{ memcpy(++ptr, local_gbox.checkcode, 7); }
		else	
			{ memset(++ptr, 0, 7); }		
		ptr += 7;
		*ptr = local_gbox.minor_version;
		*(++ptr) = local_gbox.type;
		memcpy(++ptr, cfg.gbox_hostname, hostname_len);
		ptr += hostname_len;
		*ptr = hostname_len;
	}
	len = ptr - outbuf + 1;
	switch(peer->hello_stat)
	{
	case GBOX_STAT_HELLOL:
		cs_log("gbox: send HELLOL to %s", cli->reader->label);
		if((number & 0x80) == 0x80)
			{ peer->hello_stat = GBOX_STAT_HELLOS; }
		break;
	case GBOX_STAT_HELLOS:
		cs_log("gbox: send HELLOS total cards  %d to %s", nbcards, cli->reader->label);
		if((number & 0x80) == 0x80)
			{ peer->hello_stat = GBOX_STAT_HELLO3; }
		break;
	case GBOX_STAT_HELLOR:
		cs_log("gbox: send HELLOR total cards  %d to %s", nbcards, cli->reader->label);
		if((number & 0x80) == 0x80)
			{ peer->hello_stat = GBOX_STAT_HELLO3; }
		break;
	default:
		cs_log("gbox: send hello total cards  %d to %s", nbcards, cli->reader->label);
		break;
	}
	cs_ddump_mask(D_READER, outbuf, len, "send hello, (len=%d):", len);

	gbox_compress(outbuf, len, &len);

	gbox_send(cli, outbuf, len);
}

static void gbox_send_hello(struct s_client *cli)
{
	struct gbox_peer *peer = cli->gbox;

	int32_t nbcards = 0;
	int32_t packet;
	uchar buf[2048];
	/*
	  int32_t ok = 0;
	#ifdef WEBIF
	  ok = check_ip(cfg.http_allowed, cli->ip) ? 1 : 0;
	#endif
	*/
	packet = 0;
	uchar *ptr = buf + 11;
	if(ll_count(local_gbox.cards) != 0 && peer->hello_stat > GBOX_STAT_HELLOL)
	{
		memset(buf, 0, sizeof(buf));

		LL_ITER it = ll_iter_create(local_gbox.cards);
		struct gbox_card *card;
		while((card = ll_iter_next(&it)))
		{
			//send to user only cards which matching CAID from account and lvl > 0
			if(chk_ctab(card->caid, &cli->account->ctab) && card->lvl > 0)
			{
				*(++ptr) = card->provid_1 >> 24;
				*(++ptr) = card->provid_1 >> 16;
				*(++ptr) = card->provid_1 >> 8;
				*(++ptr) = card->provid_1 & 0xff;
				*(++ptr) = 1;       //note: original gbx is more efficient and sends all cards of one caid as package
				*(++ptr) = card->slot;
				//If you modify the next line you are going to destroy the community
				//It will be recognized by original gbx and you will get banned
				*(++ptr) = ((card->lvl - 1) << 4) + card->dist + 1;
				*(++ptr) = card->peer_id >> 8;
				*(++ptr) = card->peer_id & 0xff;
				nbcards++;
				if(nbcards == 100)    //check if 100 is good or we need more sophisticated algorithm
				{
					gbox_send_hello_packet(cli, packet, buf, ptr, nbcards);
					packet++;
					nbcards = 0;
					ptr = buf + 11;
					memset(buf, 0, sizeof(buf));
				}
			}
		}
	} // end if local card exists

	//last packet has bit 0x80 set
	gbox_send_hello_packet(cli, 0x80 | packet, buf, ptr, nbcards);
}

static void gbox_send_checkcode(struct s_client *cli)
{
	struct gbox_peer *peer = cli->gbox;
	uchar outbuf[20];

	gbox_calc_checkcode();
	gbox_code_cmd(outbuf, MSG_CHECKCODE);
	memcpy(outbuf + 2, peer->gbox.password, 4);
	memcpy(outbuf + 6, local_gbox.password, 4);
	memcpy(outbuf + 10, local_gbox.checkcode, 7);

	gbox_send(cli, outbuf, 17);
}

static void gbox_send_boxinfo(struct s_client *cli)
{
	struct gbox_peer *peer = cli->gbox;
	uchar outbuf[256];
	int32_t hostname_len = strlen(cfg.gbox_hostname);

	gbox_code_cmd(outbuf, MSG_BOXINFO);
	memcpy(outbuf + 2, peer->gbox.password, 4);
	memcpy(outbuf + 6, local_gbox.password, 4);
	outbuf[0xA] = local_gbox.minor_version;
	outbuf[0xB] = local_gbox.type;
	memcpy(&outbuf[0xC], cfg.gbox_hostname, hostname_len);
	gbox_send(cli, outbuf, hostname_len + 0xC);
}

static int32_t gbox_recv(struct s_client *cli, uchar *buf, int32_t l)
{
	uchar data[RECEIVE_BUFFER_SIZE];
	int32_t n = l;

	if(!cli->udp_fd || n > RECEIVE_BUFFER_SIZE) { return -1; }
	if(cli->is_udp && cli->typ == 'c')
	{
		n = recv_from_udpipe(buf);
		memcpy(&data[0], buf, n);

		gbox_check_header(cli, &data[0], n);

		//clients may timeout - dettach from peer's gbox/reader
		cli->gbox = NULL;
		cli->reader = NULL;
	}
	return 0;
}

static void gbox_send_dcw(struct s_client *cl, ECM_REQUEST *er)
{
	struct s_client *cli = switch_client_proxy(cl, cl->gbox_peer_id);
	struct gbox_peer *peer = cli->gbox;

	peer->gbox_count_ecm--;
	if(er->rc >= E_NOTFOUND)
	{
		cs_debug_mask(D_READER, "gbox: unable to decode!");
		return;
	}

	uchar buf[60];
	memset(buf, 0, sizeof(buf));

	struct gbox_ecm_request_ext *ere = er->src_data;

	gbox_code_cmd(buf, MSG_CW);
	buf[2] = peer->gbox.password[0];	//Peer key
	buf[3] = peer->gbox.password[1];	//Peer key
	buf[4] = peer->gbox.password[2];	//Peer key
	buf[5] = peer->gbox.password[3];	//Peer key
	buf[6] = er->pid >> 8;			//PID
	buf[7] = er->pid & 0xff;		//PID
	buf[8] = er->srvid >> 8;		//SrvID
	buf[9] = er->srvid & 0xff;		//SrvID
	buf[10] = ere->gbox_mypeer >> 8;	//From peer
	buf[11] = ere->gbox_mypeer & 0xff;	//From peer
	buf[12] = (ere->gbox_slot << 4) | (er->ecm[0] & 0x0f); //slot << 4 | even/odd
	buf[13] = ere->gbox_caid >> 8;		//CAID first byte
	memcpy(buf + 14, er->cw, 16);		//CW
	buf[30] = er->gbox_crc >> 24;		//CRC
	buf[31] = er->gbox_crc >> 16;		//CRC
	buf[32] = er->gbox_crc >> 8;		//CRC
	buf[33] = er->gbox_crc & 0xff;		//CRC
	buf[34] = ere->gbox_caid >> 8;		//CAID
	buf[35] = ere->gbox_caid & 0xff;	//CAID
	buf[36] = ere->gbox_slot;  		//Slot
	buf[37] = ere->gbox_prid >> 8;		//ProvID
	buf[38] = ere->gbox_prid & 0xff;	//ProvID
	buf[39] = ere->gbox_peer >> 8;		//Target peer
	buf[40] = ere->gbox_peer & 0xff;	//Target peer
	buf[41] = 0x04;           		//don't know what this is
	buf[42] = 0x33;           		//don't know what this is
	buf[43] = ere->gbox_unknown;		//meaning unknown, copied from ECM request

	//This copies the routing info from ECM to answer.
	//Each hop adds one byte and number of hops is in er->gbox_hops.
	memcpy(&buf[44], &ere->gbox_routing_info, ere->gbox_hops - 1);
	buf[44 + ere->gbox_hops - 1] = ere->gbox_hops - 1;	//Hops 
	/*
	char tmp[0x50];
	cs_log("sending dcw to peer : %04x   data: %s", er->gbox_peer, cs_hexdump(0, buf, er->gbox_hops + 44, tmp, sizeof(tmp)));
	*/
	gbox_send(cli, buf, ere->gbox_hops + 44);

	cs_debug_mask(D_READER, "-> CW  (->%d) from %s/%d (%04X) ", ere->gbox_hops, cli->reader->label, cli->port, ere->gbox_peer);
}

static uint8_t gbox_next_free_slot(uint16_t id)
{
	LL_ITER it = ll_iter_create(local_gbox.cards);
	struct gbox_card *c;
	uint8_t lastslot = 0;

	while((c = ll_iter_next(&it)))
	{
		if(id == c->peer_id && c->slot > lastslot)
			{ lastslot = c->slot; }
	}
	return ++lastslot;
}

static void gbox_add_local_card(uint16_t id, uint16_t caid, uint32_t prid, uint8_t slot, uint8_t card_reshare, uint8_t dist)
{
	struct gbox_card *c;

	//don't insert 0100:000000
	if((caid >> 8 == 0x01) && (!prid))
	{
		return;
	}
	//skip CAID 18XX providers
	if((caid >> 8 == 0x18) && (prid))
	{
		return;
	}
	if(!cs_malloc(&c, sizeof(struct gbox_card)))
	{
		return;
	}
	c->caid = caid;
	switch(caid >> 8)
	{
		// Viaccess
	case 0x05:
		c->provid_1 = (caid >> 8) << 24 | (prid & 0xFFFFFF);
		break;
		// Cryptoworks
	case 0x0D:
		c->provid_1 = (caid >> 8) << 24 | (caid & 0xFF) << 16 |
					  ((prid << 8) & 0xFF00);
		break;
	default:
		c->provid_1 = (caid >> 8) << 24 | (caid & 0xFF) << 16 |
					  (prid & 0xFFFF);
		break;
	}
	c->provid = prid;
	c->peer_id = id;
	c->slot = slot;
	c->lvl = card_reshare;
	c->dist = dist;
	ll_append(local_gbox.cards, c);
}

static void gbox_local_cards(struct s_client *cli)
{
	int32_t i;
	uint32_t prid = 0;
	int8_t slot = 0;
	char card_reshare;
#ifdef MODULE_CCCAM
	LL_ITER it, it2;
	struct cc_card *card = NULL;
	struct cc_data *cc;
	uint32_t checksum = 0;
	uint16_t cc_peer_id = 0;
	struct cc_provider *provider;
	uint8_t *node1 = NULL;
#endif

	if(!local_gbox.cards)
	{
		gbox_free_cardlist(local_gbox.cards);
	}
	local_gbox.cards = ll_create("local_cards");

	//value >5 not allowed in gbox network
	if(cli->reader->gbox_reshare > 5)
		{ card_reshare = 5; }
	else
		{ card_reshare = cli->reader->gbox_reshare; }

	struct s_client *cl;
	for(cl = first_client; cl; cl = cl->next)
	{
		if(cl->typ == 'r' && cl->reader && cl->reader->card_status == 2)
		{
			slot = gbox_next_free_slot(local_gbox.id);
			//SECA, Viaccess and Cryptoworks have multiple providers
			if((cl->reader->caid >> 8 == 0x01) || (cl->reader->caid >> 8 == 0x05) ||
					(cl->reader->caid >> 8 == 0x0D))
			{
				for(i = 0; i < cl->reader->nprov; i++)
				{
					prid = cl->reader->prid[i][1] << 16 |
						   cl->reader->prid[i][2] << 8 | cl->reader->prid[i][3];
					gbox_add_local_card(local_gbox.id, cl->reader->caid, prid, slot, card_reshare, 0);
				}
			}
			else
				{ 
					gbox_add_local_card(local_gbox.id, cl->reader->caid, 0, slot, card_reshare, 0); 

					//Check for Betatunnel on gbox account in oscam.user
					if (chk_is_betatunnel_caid(cl->reader->caid) == 1 && cli->ttab.n && cl->reader->caid == cli->ttab.bt_caidto[0])
					{
						//For now only first entry in tunnel tab. No sense in iteration?
						//Add betatunnel card to transmitted list
						gbox_add_local_card(local_gbox.id, cli->ttab.bt_caidfrom[0], 0, slot, card_reshare, 0);
						cs_debug_mask(D_READER, "gbox created betatunnel card for caid: %04X->%04X",cli->ttab.bt_caidfrom[0],cl->reader->caid);
					}
				}
		}   //end local readers
#ifdef MODULE_CCCAM
		if(cl->typ == 'p' && cl->reader
				&& cl->reader->typ == R_CCCAM && cl->cc)
		{
			cc = cl->cc;
			it = ll_iter_create(cc->cards);
			while((card = ll_iter_next(&it)))
			{
				//calculate gbox id from cc node
				//1st node is orgin, shorten to 32Bit by CRC, the GBX-ID like from PW
				node1 = ll_has_elements(card->remote_nodes);
				checksum = (uint32_t)crc32(0L, node1, 8);
				cc_peer_id = ((((checksum >> 24) & 0xFF) ^((checksum >> 8) & 0xFF)) << 8 |
							  (((checksum >> 16) & 0xFF) ^(checksum & 0xFF)));
				slot = gbox_next_free_slot(cc_peer_id);
				if((card->caid >> 8 == 0x01) || (card->caid >> 8 == 0x05) ||
						(card->caid >> 8 == 0x0D))
				{
					it2 = ll_iter_create(card->providers);
					while((provider = ll_iter_next(&it2)))
					{
						gbox_add_local_card(cc_peer_id, card->caid, provider->prov, slot, card->reshare, card->hop);
					}
				}
				else
					{ gbox_add_local_card(cc_peer_id, card->caid, 0, slot, card->reshare, card->hop); }
			}
		}   //end cccam
#endif
	} //end for clients
}

static int32_t gbox_client_init(struct s_client *cli)
{
	if(!cfg.gbox_hostname || strlen(cfg.gbox_hostname) > 128)
	{
		cs_log("gbox: error, no/invalid hostname '%s' configured in oscam.conf!",
			   cfg.gbox_hostname ? cfg.gbox_hostname : "");
		return -1;
	}

	if(!local_gbox.id)
	{
		cs_log("gbox: error, no/invalid password '%s' configured in oscam.conf!",
			   cfg.gbox_my_password ? cfg.gbox_my_password : "");
		return -1;
	}

	if(!cs_malloc(&cli->gbox, sizeof(struct gbox_peer)))
		{ return -1; }

	struct gbox_peer *peer = cli->gbox;
	struct s_reader *rdr = cli->reader;

	rdr->card_status = CARD_NEED_INIT;
	rdr->tcp_connected = 0;

	memset(peer, 0, sizeof(struct gbox_peer));

	uint32_t r_pwd = a2i(rdr->r_pwd, 4);
	int32_t i;
	for(i = 3; i >= 0; i--)
	{
		peer->gbox.password[3 - i] = (r_pwd >> (8 * i)) & 0xff;
	}

	cs_ddump_mask(D_READER, peer->gbox.password, 4, "Peer password: %s:", rdr->r_pwd);

	peer->gbox.id = gbox_convert_password_to_id(&peer->gbox.password[0]);	
	if (get_gbox_proxy(peer->gbox.id) || peer->gbox.id == NO_GBOX_ID || peer->gbox.id == local_gbox.id)
	{
		cs_log("gbox: error, double/invalid gbox id: %04X", peer->gbox.id);	
		return -1;
	}
	cli->gbox_peer_id = peer->gbox.id;	

	cli->pfd = 0;
	cli->crypted = 1;

	set_null_ip(&cli->ip);

	if((cli->udp_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
	{
		cs_log("socket creation failed (errno=%d %s)", errno, strerror(errno));
		cs_disconnect_client(cli);
	}

	int32_t opt = 1;
	setsockopt(cli->udp_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

#ifdef SO_REUSEPORT
	setsockopt(cli->udp_fd, SOL_SOCKET, SO_REUSEPORT, (void *)&opt, sizeof(opt));
#endif

	set_socket_priority(cli->udp_fd, cfg.netprio);

	memset((char *)&cli->udp_sa, 0, sizeof(cli->udp_sa));

	if(!hostResolve(rdr))
		{ return 0; }

	cli->port = rdr->r_port;
	SIN_GET_FAMILY(cli->udp_sa) = AF_INET;
	SIN_GET_PORT(cli->udp_sa) = htons((uint16_t)rdr->r_port);
	hostname2ip(cli->reader->device, &SIN_GET_ADDR(cli->udp_sa));

	cs_log("proxy %s:%d (fd=%d, peer id=%04x, my id=%04x, my hostname=%s, listen port=%d)",
		   rdr->device, rdr->r_port, cli->udp_fd, peer->gbox.id, local_gbox.id, cfg.gbox_hostname, rdr->r_port);

	cli->pfd = cli->udp_fd;

	cs_lock_create(&peer->lock, "gbox_lock", 5000);

	peer->online     = 0;
	peer->ecm_idx    = 0;
	peer->hello_stat = GBOX_STAT_HELLOL;

	cli->reader->card_status = CARD_NEED_INIT;
	gbox_send_hello(cli);

	if(!cli->reader->gbox_maxecmsend)
		{ cli->reader->gbox_maxecmsend = DEFAULT_GBOX_MAX_ECM_SEND; }

	if(!cli->reader->gbox_maxdist)
		{ cli->reader->gbox_maxdist = DEFAULT_GBOX_MAX_DIST; }

	// create expire thread
	pthread_t t;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
	int32_t ret = pthread_create(&t, &attr, (void *)gbox_expire_hello, cli);

	if(ret)
	{
		cs_log("ERROR: can't create gbox expire thread (errno=%d %s)", ret, strerror(ret));
		pthread_attr_destroy(&attr);
		return -1;
	}
	else
		{ pthread_detach(t); }

	pthread_attr_destroy(&attr);

	return 0;
}

static int32_t gbox_recv_chk(struct s_client *cli, uchar *dcw, int32_t *rc, uchar *data, int32_t UNUSED(n))
{
	uint16_t id_card = 0;
	struct s_client *cl;
	if(cli->typ != 'p')
	{
		cl = switch_client_proxy(cli, cli->gbox_peer_id);
	}
	else
	{
		cl = cli;
	}
	if(gbox_decode_cmd(data) == MSG_CW)
	{
		int i, n;
		*rc = 1;
		memcpy(dcw, data + 14, 16);
		uint32_t crc = data[30] << 24 | data[31] << 16 | data[32] << 8 | data[33];
		char tmp[16];
		cs_debug_mask(D_READER, "gbox: received cws=%s, peer=%04x, ecm_pid=%04x, sid=%04x, crc=%08x",
					  cs_hexdump(0, dcw, 16, tmp, sizeof(tmp)), data[10] << 8 | data[11], data[6] << 8 | data[7], data[8] << 8 | data[9], crc);

		for(i = 0, n = 0; i < cfg.max_pending && n == 0; i++)
		{
			if(cl->ecmtask[i].gbox_crc == crc)
			{
				id_card = data[10] << 8 | data[11];
				gbox_add_good_card(cl, id_card, cl->ecmtask[i].caid, cl->ecmtask[i].prid, cl->ecmtask[i].srvid);
				if(cl->ecmtask[i].gbox_ecm_ok == 0 || cl->ecmtask[i].gbox_ecm_ok == 2)
					{ return -1; }
				struct s_ecm_answer ea;
				memset(&ea, 0, sizeof(struct s_ecm_answer));
				cl->ecmtask[i].gbox_ecm_ok = 2;
				memcpy(ea.cw, dcw, 16);
				*rc = 1;
				return cl->ecmtask[i].idx;
			}
		}
		cs_debug_mask(D_READER, "gbox: no task found for crc=%08x", crc);
	}
	return -1;
}

static int32_t gbox_send_ecm(struct s_client *cli, ECM_REQUEST *er, uchar *UNUSED(buf))
{
	struct gbox_peer *peer = cli->gbox;
	int32_t cont_1;
	uint32_t sid_verified = 0;
/*	struct gbox_ecm_request_ext *ere;

	if (!er->src_data) {
                if(!cs_malloc(&ere, sizeof(struct gbox_ecm_request_ext)))
                {
                	cs_writeunlock(&gbox->lock);
                	return -1;
                }
		er->src_data = ere;
		gbox_init_ecm_request_ext(ere);
	}
	else
		ere = er->src_data;
*/
	if(!peer || !cli->reader->tcp_connected)
	{
		cs_debug_mask(D_READER, "gbox: %s server not init!", cli->reader->label);
		write_ecm_answer(cli->reader, er, E_NOTFOUND, 0x27, NULL, NULL);

		return 0;
	}

	if(!ll_count(peer->gbox.cards))
	{
		cs_debug_mask(D_READER, "gbox: %s NO CARDS!", cli->reader->label);
		write_ecm_answer(cli->reader, er, E_NOTFOUND, 0x27, NULL, NULL);
		return 0;
	}

	if(!peer->online)
	{
		cs_debug_mask(D_READER, "gbox: peer is OFFLINE!");
		write_ecm_answer(cli->reader, er, E_NOTFOUND, 0x27, NULL, NULL);
		//      gbox_send_hello(cli,0);
		return 0;
	}

	if(er->gbox_ecm_ok == 2)
	{
		cs_debug_mask(D_READER, "gbox: %s replied to this ecm already", cli->reader->label);
	}

	if(er->gbox_ecm_id == peer->gbox.id)
	{
		cs_debug_mask(D_READER, "gbox: %s provided ecm", cli->reader->label);
		write_ecm_answer(cli->reader, er, E_NOTFOUND, 0x27, NULL, NULL);
		return 0;
	}

	uint16_t ercaid = er->caid;
	uint32_t erprid = er->prid;

	if(cli->reader->gbox_maxecmsend == 0)
	{
		cli->reader->gbox_maxecmsend = DEFAULT_GBOX_MAX_ECM_SEND;
	}

	switch(ercaid >> 8)
	{
		//Viaccess
	case 0x05:
		ercaid = (ercaid & 0xFF00) | ((erprid >> 16) & 0xFF);
		erprid = erprid & 0xFFFF;
		break;
		//Cryptoworks
	case 0x0D:
		erprid = erprid << 8;
		break;
		//Nagra
	case 0x18:
		erprid = 0;
		break;
	}

	uchar send_buf_1[1024];
	int32_t len2;

	if(!er->ecmlen) { return 0; }

	len2 = er->ecmlen + 18;
	er->gbox_crc = gbox_get_ecmchecksum(er);

	memset(send_buf_1, 0, sizeof(send_buf_1));

	LL_ITER it = ll_iter_create(peer->gbox.cards);
	struct gbox_card *card;

	int32_t cont_send = 0;
	int32_t cont_card_1 = 0;

	send_buf_1[0] = MSG_ECM >> 8;
	send_buf_1[1] = MSG_ECM & 0xff;
	memcpy(send_buf_1 + 2, peer->gbox.password, 4);
	memcpy(send_buf_1 + 6, local_gbox.password, 4);

	send_buf_1[10] = (er->pid >> 8) & 0xFF;
	send_buf_1[11] = er->pid & 0xFF;

	send_buf_1[12] = (er->srvid >> 8) & 0xFF;
	send_buf_1[13] = er->srvid & 0xFF;
	send_buf_1[14] = 0x00;
	send_buf_1[15] = 0x00;

	send_buf_1[16] = cont_card_1;
	send_buf_1[17] = 0x00;

	memcpy(send_buf_1 + 18, er->ecm, er->ecmlen);

	send_buf_1[len2]   = (local_gbox.id >> 8) & 0xff;
	send_buf_1[len2 + 1] = local_gbox.id & 0xff;
	send_buf_1[len2 + 2] = LOCAL_GBOX_MINOR_VERSION;
	send_buf_1[len2 + 3] = 0x00;
	send_buf_1[len2 + 4] = LOCAL_GBOX_TYPE;

	send_buf_1[len2 + 5] = ercaid >> 8;
	send_buf_1[len2 + 6] = ercaid & 0xFF;

	send_buf_1[len2 + 7] = (erprid >> 8) & 0xFF;
	send_buf_1[len2 + 8] = erprid & 0xFF;
	send_buf_1[len2 + 9] = 0x00;
	cont_1 = len2 + 10;

	struct gbox_srvid *srvid1 = NULL;
	while((card = ll_iter_next(&it)))
	{
		if(card->caid == er->caid && card->provid == er->prid)
		{
			sid_verified = 0;

			LL_ITER it2 = ll_iter_create(card->goodsids);
			while((srvid1 = ll_iter_next(&it2)))
			{
				if(srvid1->provid_id == er->prid && srvid1->sid == er->srvid)
				{
					send_buf_1[cont_1] = card->peer_id >> 8;
					send_buf_1[cont_1 + 1] = card->peer_id;
					send_buf_1[cont_1 + 2] = card->slot;
					cont_1 = cont_1 + 3;
					cont_card_1++;
					cont_send++;
					sid_verified = 1;
					break;
				}
			}

			if(cont_send == cli->reader->gbox_maxecmsend)
				{ break; }

			if(sid_verified == 0)
			{
				LL_ITER itt = ll_iter_create(card->badsids);
				while((srvid1 = ll_iter_next(&itt)))
				{
					if(srvid1->provid_id == er->prid && srvid1->sid == er->srvid)
					{
						sid_verified = 1;
						break;
					}
				}

				if(sid_verified != 1)
				{
					send_buf_1[cont_1] = card->peer_id >> 8;
					send_buf_1[cont_1 + 1] = card->peer_id;
					send_buf_1[cont_1 + 2] = card->slot;
					cont_1 = cont_1 + 3;
					cont_card_1++;
					cont_send++;

					if(!cs_malloc(&srvid1, sizeof(struct gbox_srvid)))
						{ return 0; }

					srvid1->sid = er->srvid;
					srvid1->peer_idcard = card->peer_id;
					srvid1->provid_id = card->provid;
					ll_append(card->badsids, srvid1);

					if(cont_send == cli->reader->gbox_maxecmsend)
						{ break; }
				}
			}

			if(cont_send == cli->reader->gbox_maxecmsend)
				{ break; }
		}
	}

	if(!cont_card_1)
	{
		cs_debug_mask(D_READER, "GBOX: no valid card found for CAID: %04X PROVID: %04X", er->caid, er->prid);
		return 0;
	}

	send_buf_1[16] = cont_card_1;

	//Hops
	send_buf_1[cont_1] = 0;
	cont_1++;

	memcpy(&send_buf_1[cont_1], local_gbox.checkcode, 7);
	cont_1 = cont_1 + 7;
	memcpy(&send_buf_1[cont_1], peer->gbox.checkcode, 7);
	cont_1 = cont_1 + 7;

	cs_debug_mask(D_READER, "Gbox sending ecm for %06x : %s", er->prid , cli->reader->label);
	er->gbox_ecm_ok = 1;
	gbox_send(cli, send_buf_1, cont_1);
	cli->pending++;
	cli->reader->last_s = time((time_t *) 0);

	return 0;
}

static int32_t gbox_send_emm(EMM_PACKET *UNUSED(ep))
{
	// emms not yet supported

	return 0;
}

//init my gbox with id, password and cards crc
static void init_local_gbox(void)
{
	local_gbox.id = 0;
	memset(&local_gbox.password[0], 0, 4);
	memset(&local_gbox.checkcode[0], 0, 7);
	local_gbox.minor_version = LOCAL_GBOX_MINOR_VERSION;
	local_gbox.type = LOCAL_GBOX_TYPE;

	if(!cfg.gbox_my_password || strlen(cfg.gbox_my_password) != 8) { return; }

	uint32_t key = a2i(cfg.gbox_my_password, 4);
	int32_t i;
	for(i = 3; i >= 0; i--)
	{
		local_gbox.password[3 - i] = (key >> (8 * i)) & 0xff;
	}

	cs_ddump_mask(D_READER, local_gbox.password,      4, " My  password: %s:", cfg.gbox_my_password);

	local_gbox.id = gbox_convert_password_to_id(&local_gbox.password[0]);
	if (local_gbox.id == NO_GBOX_ID)
	{
		cs_log("gbox: invalid local gbox id: %04X", local_gbox.id);	
	}
}

void module_gbox(struct s_module *ph)
{
	init_local_gbox();
	ph->ptab.nports = 1;
	ph->ptab.ports[0].s_port = cfg.gbox_port;

	ph->desc = "gbox";
	ph->num = R_GBOX;
	ph->type = MOD_CONN_UDP;
	ph->large_ecm_support = 1;
	ph->listenertype = LIS_GBOX;

	ph->s_handler = gbox_server;
	ph->s_init = gbox_server_init;

	ph->send_dcw = gbox_send_dcw;

	ph->recv = gbox_recv;
	ph->c_init = gbox_client_init;
	ph->c_recv_chk = gbox_recv_chk;
	ph->c_send_ecm = gbox_send_ecm;
	ph->c_send_emm = gbox_send_emm;
}
#endif
