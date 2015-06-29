#define MODULE_LOG_PREFIX "gbox"

#include "globals.h"
#ifdef MODULE_GBOX

#include "module-gbox.h"
#include "module-gbox-helper.h"
#include "module-gbox-sms.h"
#include "module-gbox-cards.h"
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
#include "oscam-files.h"

#define RECEIVE_BUFFER_SIZE	1024
#define MIN_GBOX_MESSAGE_LENGTH	10 //CMD + pw + pw. TODO: Check if is really min
#define MIN_ECM_LENGTH		8
#define HELLO_KEEPALIVE_TIME	120 //send hello to peer every 2 min in case no ecm received
#define STATS_WRITE_TIME	300 //write stats file every 5 min

#define LOCAL_GBOX_MAJOR_VERSION	0x02

static struct gbox_data local_gbox;
static uint8_t local_gbox_initialized = 0;
static time_t last_stats_written;

static int32_t gbox_send_ecm(struct s_client *cli, ECM_REQUEST *er);

char *get_gbox_tmp_fname(char *fext)
{
	static char gbox_tmpfile_buf[64] = { 0 };	
	const char *slash = "/";
	if(!cfg.gbox_tmp_dir)
	{
		snprintf(gbox_tmpfile_buf, sizeof(gbox_tmpfile_buf), "%s%s%s",get_tmp_dir(), slash, fext);
	}
	else
	{ 
		if(cfg.gbox_tmp_dir[strlen(cfg.gbox_tmp_dir) - 1] == '/') { slash = ""; }
		snprintf(gbox_tmpfile_buf, sizeof(gbox_tmpfile_buf), "%s%s%s", cfg.gbox_tmp_dir, slash, fext);
	}
	return gbox_tmpfile_buf; 
}

uint16_t gbox_get_local_gbox_id(void)
{
	return local_gbox.id;
}

uint32_t gbox_get_local_gbox_password(void)
{
	return local_gbox.password;
}

static uint8_t gbox_get_my_vers (void)
{
	uint8_t gbx_vers = a2i(cfg.gbox_my_vers,1);

	return gbx_vers;
}

static uint8_t gbox_get_my_cpu_api (void)
{
/* For configurable later adapt according to these functions:
unsigned char *GboxAPI( unsigned char a ) {
	a = a & 7 ;
	switch ( a ) { 
		case 0 : strcpy ( s_24,"No API");
                	break;  
		case 1 : strcpy ( s_24,"API 1");
                        break;  
                case 2 : strcpy ( s_24,"API 2");
                        break;  
                case 3 : strcpy ( s_24,"API 3");
                        break;  
                case 4 : strcpy ( s_24,"IBM API");
                        break;  
                default : strcpy ( s_24," ");
	}
        return s_24 ;
}
                                                                                        
unsigned char *GboxCPU( unsigned char a ) {
	a = a & 112 ;
        a = a >> 4 ;
        switch ( a ) { 
	        case 1 : strcpy ( s_23,"80X86 compatible CPU");
        		break;  
        	case 2 : strcpy ( s_23,"Motorola PowerPC MPC823 CPU");
        		break;  
        	case 3 : strcpy ( s_23,"IBM PowerPC STB CPU");
        		break;  
		default : strcpy ( s_23," ");
	}
	return s_23:
}
*/
	return a2i(cfg.gbox_my_cpu_api,1);
}

static void write_goodnight_to_osd_file(struct s_client *cli)
{
	char *fext= FILE_GOODNIGHT_OSD; 
	char *fname = get_gbox_tmp_fname(fext); 
	if (file_exists(fname))
	{
	char buf[50];
	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf), "%s %s %s", fname, username(cli), cli->reader->device);
	cs_log_dbg(D_READER, "found file %s - write goodnight info from %s %s to OSD", fname, username(cli),cli->reader->device);
	char *cmd = buf;
              FILE *p;
              if ((p = popen(cmd, "w")) == NULL)
		{	
			cs_log("Error %s",fname);
			return;
		}
              pclose(p);
	}
	return;
}

void gbox_write_peer_onl(void)
{
	char *fext= FILE_GBOX_PEER_ONL; 
	char *fname = get_gbox_tmp_fname(fext); 
	FILE *fhandle = fopen(fname, "w");
	if(!fhandle)
	{
		cs_log("Couldn't open %s: %s", fname, strerror(errno));
		return;
	}
	cs_readlock(__func__, &clientlist_lock);
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
	cs_readunlock(__func__, &clientlist_lock);
	fclose(fhandle);
	return;
}	

void gbox_write_version(void)
{
	char *fext= FILE_GBOX_VERSION; 
	char *fname = get_gbox_tmp_fname(fext); 
	FILE *fhandle = fopen(fname, "w");
	if(!fhandle)
	{
		cs_log("Couldn't open %s: %s", get_gbox_tmp_fname(FILE_GBOX_VERSION), strerror(errno));
		return;
	}
	fprintf(fhandle, "%02X.%02X\n", LOCAL_GBOX_MAJOR_VERSION, gbox_get_my_vers());
	fclose(fhandle);
}

void hostname2ip(char *hostname, IN_ADDR_T *ip)
{
	cs_resolve(hostname, ip, NULL, NULL);
}

static uint16_t gbox_convert_password_to_id(uint32_t password)
{
	return (((password >> 24) & 0xff) ^ ((password >> 8) & 0xff)) << 8 | (((password >> 16) & 0xff) ^ (password & 0xff));
}

static int8_t gbox_remove_all_bad_sids(ECM_REQUEST *er, uint16_t sid)
{
	if (!er) { return -1; }

	struct gbox_card_pending *pending = NULL;
	LL_LOCKITER *li = ll_li_create(er->gbox_cards_pending, 0);
	while ((pending = ll_li_next(li)))
		{ gbox_remove_bad_sid(pending->id.peer, pending->id.slot, sid); }
	ll_li_destroy(li);
	return 0;
}

void gbox_free_cards_pending(ECM_REQUEST *er)
{ 
	ll_destroy_free_data(&er->gbox_cards_pending); 
}

void gbox_init_ecm_request_ext(struct gbox_ecm_request_ext *ere)
{
	ere->gbox_hops = 0;
	ere->gbox_peer = 0;                		
	ere->gbox_mypeer = 0;
	ere->gbox_slot = 0;
	ere->gbox_version = 0;
	ere->gbox_unknown = 0;
	ere->gbox_type = 0;
}

struct s_client *get_gbox_proxy(uint16_t gbox_id)
{
	struct s_client *cl;
	struct s_client *found = NULL;
	cs_readlock(__func__, &clientlist_lock);
	for(cl = first_client; cl; cl = cl->next)
	{
		if(cl->typ == 'p' && cl->gbox && cl->gbox_peer_id == gbox_id)
		{
			found = cl;
			break;
		}
	}
	cs_readunlock(__func__, &clientlist_lock);
	return found;
}

static int8_t gbox_peer_online(struct gbox_peer *peer, uint8_t online)
{
	if (!peer) { return -1; }

	peer->online = online;
	gbox_write_peer_onl();
	return 0;	
}

static int8_t gbox_reinit_peer(struct gbox_peer *peer)
{
	if (!peer) { return -1; }

	peer->ecm_idx		= 0;
	peer->next_hello	= 0;
	gbox_delete_cards(GBOX_DELETE_FROM_PEER, peer->gbox.id);
	gbox_peer_online(peer, GBOX_PEER_OFFLINE);
	
	return 0;
}

static int8_t gbox_reinit_proxy(struct s_client *proxy)
{
	if (!proxy) { return -1; }
		
	struct gbox_peer *peer = proxy->gbox;
	gbox_reinit_peer(peer);
	if (!proxy->reader) { return -1; }
	proxy->reader->tcp_connected	= 0;
	proxy->reader->card_status	= NO_CARD;
	proxy->reader->last_s		= proxy->reader->last_g = 0;

	return 0;
}

void gbox_send(struct s_client *cli, uchar *buf, int32_t l)
{
	struct gbox_peer *peer = cli->gbox;

	cs_log_dump_dbg(D_READER, buf, l, "<- decrypted data (%d bytes):", l);

	hostname2ip(cli->reader->device, &SIN_GET_ADDR(cli->udp_sa));
	SIN_GET_FAMILY(cli->udp_sa) = AF_INET;
	SIN_GET_PORT(cli->udp_sa) = htons((uint16_t)cli->reader->r_port);

	gbox_encrypt(buf, l, peer->gbox.password);
	sendto(cli->udp_fd, buf, l, 0, (struct sockaddr *)&cli->udp_sa, cli->udp_sa_len);
	cs_log_dump_dbg(D_READER, buf, l, "<- encrypted data (%d bytes):", l);
}

void gbox_send_hello_packet(struct s_client *cli, int8_t number, uchar *outbuf, uchar *ptr, int32_t nbcards, uint8_t hello_stat)
{
	struct gbox_peer *peer = cli->gbox;
	int32_t hostname_len = strlen(cfg.gbox_hostname);
	int32_t len;
	gbox_message_header(outbuf, MSG_HELLO, peer->gbox.password, local_gbox.password);
	// initial HELLO = 0, subsequent = 1
	if(hello_stat > GBOX_STAT_HELLOS)
		{ outbuf[10] = 1; }
	else
		{ outbuf[10] = 0; }
	outbuf[11] = number;    // 0x80 (if last packet) else 0x00 | packet number

	if((number & 0x0F) == 0)
	{
		if(hello_stat != GBOX_STAT_HELLOL)
			{ memcpy(++ptr, gbox_get_checkcode(), 7); }
		else	
			{ memset(++ptr, 0, 7); }		
		ptr += 7;
		*ptr = local_gbox.minor_version;
		*(++ptr) = local_gbox.cpu_api;
		memcpy(++ptr, cfg.gbox_hostname, hostname_len);
		ptr += hostname_len;
		*ptr = hostname_len;
	}
	len = ptr - outbuf + 1;
	switch(hello_stat)
	{
	case GBOX_STAT_HELLOL:
		cs_log("<- HelloL to %s", cli->reader->label);
		break;
	case GBOX_STAT_HELLOS:
		cs_log("<- HelloS total cards  %d to %s", nbcards, cli->reader->label);
		break;
	case GBOX_STAT_HELLOR:
		cs_log("<- HelloR total cards  %d to %s", nbcards, cli->reader->label);
		break;
	default:
		cs_log("<- hello total cards  %d to %s", nbcards, cli->reader->label);
		break;
	}
	cs_log_dump_dbg(D_READER, outbuf, len, "<- hello, (len=%d):", len);

	gbox_compress(outbuf, len, &len);

	gbox_send(cli, outbuf, len);
}

void gbox_send_hello(struct s_client *proxy, uint8_t hello_stat)
{
        if (!proxy)
        {
                cs_log("Invalid call to gbox_send_hello with proxy");
                return;
        }
        uint16_t nbcards = 0;
        uint8_t packet;
        uchar buf[2048];
        packet = 0;
        uchar *ptr = buf + 11;
        if(gbox_count_cards() != 0 && hello_stat > GBOX_STAT_HELLOL)
        {
                struct gbox_peer *peer = proxy->gbox;
                if (!peer || !peer->my_user || !peer->my_user->account)
                {
                        cs_log("Invalid call to gbox_send_hello with peer");
                        return;
                }
                memset(buf, 0, sizeof(buf));
                struct gbox_card *card;
                GBOX_CARDS_ITER *gci = gbox_cards_iter_create();
                while((card = gbox_cards_iter_next(gci)))
                {
                        //send to user only cards which matching CAID from account and lvl > 0
                        //do not send peer cards back
                        if(chk_ctab(gbox_get_caid(card->caprovid), &peer->my_user->account->ctab) && (card->lvl > 0) &&
                                (!card->origin_peer || (card->origin_peer && card->origin_peer->gbox.id != peer->gbox.id)))
                        {
                                *(++ptr) = card->caprovid >> 24;
                                *(++ptr) = card->caprovid >> 16;
                                *(++ptr) = card->caprovid >> 8;
                                *(++ptr) = card->caprovid & 0xff;
                                *(++ptr) = 1;       //note: original gbx is more efficient and sends all cards of one caid as package
                                *(++ptr) = card->id.slot;
                                *(++ptr) = ((card->lvl - 1) << 4) + card->dist + 1;
                                *(++ptr) = card->id.peer >> 8;
                                *(++ptr) = card->id.peer & 0xff;
                                nbcards++;
                                if(nbcards == 100)    //check if 100 is good or we need more sophisticated algorithm
                                {
                                        gbox_send_hello_packet(proxy, packet, buf, ptr, nbcards, hello_stat);
                                        packet++;
                                        nbcards = 0;
                                        ptr = buf + 11;
                                        memset(buf, 0, sizeof(buf));
                                }
                        }
                }
                gbox_cards_iter_destroy(gci);
        } // end if local card exists
        //last packet has bit 0x80 set
        gbox_send_hello_packet(proxy, 0x80 | packet, buf, ptr, nbcards, hello_stat);
        return;
}

void gbox_reconnect_client(uint16_t gbox_id)
{
	struct s_client *cl;
	cs_readlock(__func__, &clientlist_lock);
	for(cl = first_client; cl; cl = cl->next)
	{
		if(cl->gbox && cl->typ == 'p' && cl->gbox_peer_id == gbox_id)
		{
			hostname2ip(cl->reader->device, &SIN_GET_ADDR(cl->udp_sa));
			SIN_GET_FAMILY(cl->udp_sa) = AF_INET;
			SIN_GET_PORT(cl->udp_sa) = htons((uint16_t)cl->reader->r_port);
			hostname2ip(cl->reader->device, &(cl->ip));
			gbox_reinit_proxy(cl);
			gbox_send_hello(cl, GBOX_STAT_HELLOL);
		}
	}
	cs_readunlock(__func__, &clientlist_lock);
}

static void *gbox_server(struct s_client *cli, uchar *UNUSED(b), int32_t l)
{
	if(l > 0)
	{
		cs_log("gbox_server %s/%d", cli->reader->label, cli->port);
//		gbox_check_header(cli, NULL, b, l);
	}
	return 0;
}

char *gbox_username(struct s_client *client)
{
	if(!client) { return "anonymous"; }
	if(client->reader)
		if(client->reader->r_usr[0])
			{ return client->reader->r_usr; }
	return "anonymous";
}

static int8_t gbox_disconnect_double_peers(struct s_client *cli)
{
	struct s_client *cl;
	cs_writelock(__func__, &clientlist_lock);
	for(cl = first_client; cl; cl = cl->next)
	{
		if (cl->typ == 'c' && cl->gbox_peer_id == cli->gbox_peer_id && cl != cli)
		{
			cl->reader = NULL;
			cl->gbox = NULL;
			cs_log_dbg(D_READER, "disconnected double client %s",username(cl));
			cs_disconnect_client(cl);		
		}
	}
	cs_writeunlock(__func__, &clientlist_lock);
	return 0;
}

static int8_t gbox_auth_client(struct s_client *cli, uint32_t gbox_password)
{
	if (!cli) { return -1; }

	uint16_t gbox_id = gbox_convert_password_to_id(gbox_password);
	struct s_client *cl = get_gbox_proxy(gbox_id);

	if(cl->typ == 'p' && cl->gbox && cl->reader)
	{
		struct gbox_peer *peer = cl->gbox;
		struct s_auth *account = get_account_by_name(gbox_username(cl));

		if ((peer->gbox.password == gbox_password) && account)
		{
			cli->crypted = 1; //display as crypted
			cli->gbox = cl->gbox; //point to the same gbox as proxy
			cli->reader = cl->reader; //point to the same reader as proxy
			cli->gbox_peer_id = cl->gbox_peer_id; //signal authenticated
			gbox_disconnect_double_peers(cli);
			cs_auth_client(cli, account, NULL);
			cli->account = account;
			cli->grp = account->grp;
			cli->lastecm = time(NULL);
			peer->my_user = cli;
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
			{ cs_log("new connection from %s", cs_inet_ntoa(cl->ip)); }
		//We cannot authenticate here, because we don't know gbox pw
		cl->gbox_peer_id = NO_GBOX_ID;
		cl->init_done = 1;
		
		start_sms_sender();
	}
	return;
}

static uint16_t gbox_decode_cmd(uchar *buf)
{
	return buf[0] << 8 | buf[1];
}

int8_t gbox_message_header(uchar *buf, uint16_t cmd, uint32_t peer_password, uint32_t local_password)
{
	if (!buf) { return -1; }
	i2b_buf(2, cmd, buf);
	if (cmd == MSG_GSMS_1) { return 0; }
	i2b_buf(4, peer_password, buf + 2);
	if (cmd == MSG_CW) { return 0; }	
	i2b_buf(4, local_password, buf + 6);
	return 0;
}

//returns number of cards in a hello packet or -1 in case of error
int16_t read_cards_from_hello(uint8_t *ptr, uint8_t *len, CAIDTAB *ctab, uint8_t maxdist, struct gbox_peer *peer)
{	
	uint8_t *current_ptr = 0;
	uint32_t caprovid;
	int16_t ncards_in_msg = 0;

	while(ptr < len)
	{
		caprovid = ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];

		ncards_in_msg += ptr[4];
		//caid check
		if(chk_ctab(gbox_get_caid(caprovid), ctab))
		{
			current_ptr = ptr; 
			ptr += 5;

			// for all cards of current caid/provid,
			while (ptr < current_ptr + 5 + current_ptr[4] * 4)
			{
				if ((ptr[1] & 0xf) <= maxdist)
					{ gbox_add_card(ptr[2] << 8 | ptr[3], caprovid, ptr[0], ptr[1] >> 4, ptr[1] & 0xf, GBOX_CARD_TYPE_GBOX, peer); }
				ptr += 4; //next card
			} // end while cards for provider
		}
		else
			{ ptr += 5 + ptr[4] * 4; } //skip cards because caid
	} // end while < len
	return ncards_in_msg;
}

//returns 1 if checkcode changed / 0 if not
static int32_t gbox_checkcode_recv(struct s_client *cli, uchar *checkcode)
{
	struct gbox_peer *peer = cli->gbox;
	char tmp[14];

	if(memcmp(peer->checkcode, checkcode, 7))
	{
		memcpy(peer->checkcode, checkcode, 7);
		cs_log_dbg(D_READER, "-> new checkcode=%s",  cs_hexdump(0, peer->checkcode, 14, tmp, sizeof(tmp)));
		return 1;
	}
	return 0;
}

static void gbox_send_checkcode(struct s_client *cli)
{
	struct gbox_peer *peer = cli->gbox;
	uchar outbuf[20];

	gbox_message_header(outbuf, MSG_CHECKCODE, peer->gbox.password, local_gbox.password);
	memcpy(outbuf + 10, gbox_get_checkcode(), 7);

	gbox_send(cli, outbuf, 17);
}

int32_t gbox_cmd_hello(struct s_client *cli, uchar *data, int32_t n)
{
	if (!cli || !cli->gbox || !cli->reader || !data) { return -1; }

	struct gbox_peer *peer = cli->gbox;
	int16_t cards_number = 0;
	int32_t payload_len = n;
	int32_t hostname_len = 0;
	int32_t footer_len = 0;
	uint8_t *ptr = 0;

	if(!(gbox_decode_cmd(data) == MSG_HELLO1)) 
	{
		gbox_decompress(data, &payload_len);
		ptr = data + 12;
	}
	else
		{ ptr = data + 11; }		
	cs_log_dump_dbg(D_READER, data, payload_len, "decompressed data (%d bytes):", payload_len);

	if ((data[11] & 0xf) != peer->next_hello) //out of sync hellos
	{
		cs_log("-> out of sync hello from %s %s, expected: %02X, received: %02X"
			,username(cli), cli->reader->device, peer->next_hello, data[11] & 0xf);
		peer->next_hello = 0;
		gbox_send_hello(cli, GBOX_STAT_HELLOL);
		return 0;
	}
	
	if (!(data[11] & 0xf)) //is first packet 
	{
		gbox_delete_cards(GBOX_DELETE_FROM_PEER, peer->gbox.id);
		hostname_len = data[payload_len - 1];
		footer_len = hostname_len + 2 + 7;
		if(!peer->hostname || memcmp(peer->hostname, data + payload_len - 1 - hostname_len, hostname_len))
		{	
			NULLFREE(peer->hostname);
			if(!cs_malloc(&peer->hostname, hostname_len + 1))
			{
				return -1;
			}
			memcpy(peer->hostname, data + payload_len - 1 - hostname_len, hostname_len);
			peer->hostname[hostname_len] = '\0';
		}
		gbox_checkcode_recv(cli, data + payload_len - footer_len - 1);
		peer->gbox.minor_version = data[payload_len - footer_len - 1 + 7];
		peer->gbox.cpu_api = data[payload_len - footer_len + 7];
		peer->total_cards = 0;
	}

	cs_log_dbg(D_READER, "-> Hello packet no. %d received", (data[11] & 0xF) + 1);
	// read cards from hello
	cards_number = read_cards_from_hello(ptr, data + payload_len - footer_len - 1, &cli->reader->ctab, cli->reader->gbox_maxdist, peer);
	if (cards_number < 0)
		{ return -1; }
	else
		{ peer->total_cards += cards_number; }

	if(data[11] & 0x80)   //last packet
	{
		uchar tmpbuf[8];
		memset(&tmpbuf[0], 0xff, 7);		
		if(data[10] == 0x01 && !memcmp(data+12,tmpbuf,7)) //good night message
		{
			//This is a good night / reset packet (good night data[0xA] / reset !data[0xA] 
			cs_log("-> Good Night from %s %s",username(cli), cli->reader->device);
			write_goodnight_to_osd_file(cli);
			gbox_reinit_proxy(cli);
		}
		else	//last packet of Hello
		{
			peer->filtered_cards = gbox_count_peer_cards(peer->gbox.id);
			if(!data[10])
			{
				memset(&tmpbuf[0], 0, 7);		
				if (data[11] == 0x80 && !memcmp(data+12,tmpbuf,7))
				{
					cs_log("-> HelloL in %d packets from %s (%s:%d) V2.%02X with %d cards filtered to %d cards", (data[0x0B] & 0x0f)+1, cli->reader->label, cs_inet_ntoa(cli->ip), cli->reader->r_port, peer->gbox.minor_version, peer->total_cards, peer->filtered_cards);
					gbox_peer_online(peer, GBOX_PEER_ONLINE);
				}
				else
					{ cs_log("-> HelloS in %d packets from %s (%s:%d) V2.%02X with %d cards filtered to %d cards", (data[0x0B] & 0x0f)+1, cli->reader->label, cs_inet_ntoa(cli->ip), cli->reader->r_port, peer->gbox.minor_version, peer->total_cards, peer->filtered_cards); }			
				gbox_send_hello(cli, GBOX_STAT_HELLOR);
			}
			else
			{
				cs_log("-> HelloR in %d packets from %s (%s:%d) V2.%02X with %d cards filtered to %d cards", (data[0x0B] & 0x0f)+1, cli->reader->label, cs_inet_ntoa(cli->ip), cli->reader->r_port, peer->gbox.minor_version, peer->total_cards, peer->filtered_cards);
				gbox_send_checkcode(cli);
			}
			if(!peer->online)
			{
				gbox_send_hello(cli, GBOX_STAT_HELLOS);
				gbox_peer_online(peer, GBOX_PEER_ONLINE);
			}				
			cli->reader->tcp_connected = 2; //we have card
			if(!peer->filtered_cards)
				{ cli->reader->card_status = NO_CARD; }
			else	
				{ cli->reader->card_status = CARD_INSERTED; }			
		}		
		peer->next_hello = 0;
		gbox_write_share_cards_info();
		cli->last = time((time_t *)0); //hello is activity on proxy
	}
	else { peer->next_hello++; }
	return 0;
}

static int8_t is_blocked_peer(uint16_t peer)
{
	if (peer == NO_GBOX_ID) { return 1; }
	else { return 0; }
}

static int8_t gbox_incoming_ecm(struct s_client *cli, uchar *data, int32_t n)
{
	if (!cli || !cli->gbox || !data || !cli->reader) { return -1; }

	struct gbox_peer *peer;
	struct s_client *cl;
	int32_t diffcheck = 0;

	peer = cli->gbox;
	if (!peer || !peer->my_user) { return -1; }
	cl = peer->my_user;
	
	if(n < 21)
		{ return -1; }

	// No ECMs with length < MIN_LENGTH expected
	if ((((data[19] & 0x0f) << 8) | data[20]) < MIN_ECM_LENGTH) { return -1; }

	// GBOX_MAX_HOPS not violated
	if (data[n - 15] + 1 > GBOX_MAXHOPS) { return -1; }

	// ECM must not take more hops than allowed by gbox_reshare
	if (data[n - 15] + 1 > cli->reader->gbox_reshare) 
	{
		cs_log("-> ECM took more hops than allowed from gbox_reshare. Hops stealing detected!");	
		return -1;
	}

	//Check for blocked peers
	uint16_t requesting_peer = data[(((data[19] & 0x0f) << 8) | data[20]) + 21] << 8 | 
				   data[(((data[19] & 0x0f) << 8) | data[20]) + 22];
	if (is_blocked_peer(requesting_peer)) 
	{ 
		cs_log_dbg(D_READER, "ECM from peer %04X blocked", requesting_peer);
		return -1;		
	}			   

	ECM_REQUEST *er;
	if(!(er = get_ecmtask())) { return -1; }

	struct gbox_ecm_request_ext *ere;
	if(!cs_malloc(&ere, sizeof(struct gbox_ecm_request_ext)))
	{
		NULLFREE(er);
		return -1;
	}

	uchar *ecm = data + 18; //offset of ECM in gbx message

	er->src_data = ere;                
	gbox_init_ecm_request_ext(ere);

	er->gbox_ecm_id = peer->gbox.id;

	if(peer->ecm_idx == 100) { peer->ecm_idx = 0; }

	er->idx = peer->ecm_idx++;
	er->ecmlen = SCT_LEN(ecm);

	if(er->ecmlen < 3 || er->ecmlen > MAX_ECM_SIZE || er->ecmlen+18 > n)
		{ NULLFREE(ere); NULLFREE(er); return -1; }

	er->pid = b2i(2, data + 10);
	er->srvid = b2i(2, data + 12);

	if(ecm[er->ecmlen + 5] == 0x05)
		{ er->caid = (ecm[er->ecmlen + 5] << 8); }
	else
		{ er->caid = b2i(2, ecm + er->ecmlen + 5); }

//	ei->extra = data[14] << 8 | data[15];
	memcpy(er->ecm, data + 18, er->ecmlen);
	ere->gbox_peer = b2i(2, ecm + er->ecmlen);
	ere->gbox_version = ecm[er->ecmlen + 2];
	ere->gbox_unknown = ecm[er->ecmlen + 3];
	ere->gbox_type = ecm[er->ecmlen + 4];
	uint32_t caprovid = b2i(4, ecm + er->ecmlen + 5);
	ere->gbox_mypeer = b2i(2, ecm + er->ecmlen + 10);
	ere->gbox_slot = ecm[er->ecmlen + 12];

	diffcheck = gbox_checkcode_recv(cl, data + n - 14);
	//TODO: What do we do with our own checkcode @-7?
	er->gbox_crc = gbox_get_ecmchecksum(&er->ecm[0], er->ecmlen);
	ere->gbox_hops = data[n - 15] + 1;
	memcpy(&ere->gbox_routing_info[0], &data[n - 15 - ere->gbox_hops + 1], ere->gbox_hops - 1);

	er->caid = gbox_get_caid(caprovid);
	er->prid = gbox_get_provid(caprovid);
	cs_log_dbg(D_READER, "<- ECM (distance: %d) from %04X via peer (%s:%d) for SID %04X", ere->gbox_hops, ere->gbox_peer, peer->hostname, cli->port, er->srvid);
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

static uint32_t gbox_get_pending_time(ECM_REQUEST *er, uint16_t peer_id, uint8_t slot)
{
	if (!er) { return 0; }
	
	uint32_t ret_time = 0;
	struct gbox_card_pending *pending = NULL;
	LL_LOCKITER *li = ll_li_create(er->gbox_cards_pending, 0);
	while ((pending = ll_li_next(li)))
	{
		if ((pending->id.peer == peer_id) && (pending->id.slot == slot))
		{
			ret_time = pending->pending_time;
			break;
		}
	}
	ll_li_destroy(li);
	return ret_time;
}

static int32_t gbox_recv_chk(struct s_client *cli, uchar *dcw, int32_t *rc, uchar *data, int32_t n)
{
	if(!cli || gbox_decode_cmd(data) != MSG_CW || n < 44)
    		{ return -1; }
        	
	int i;
	uint16_t id_card = 0;
	struct s_client *proxy;
	if(cli->typ != 'p')
		{ proxy = get_gbox_proxy(cli->gbox_peer_id); }
	else
		{ proxy = cli; }
	if (!proxy || !proxy->reader)
	{
		cs_log("error, gbox_recv_chk, proxy not found");
		return -1;
	}
	proxy->last = time((time_t *)0);
	*rc = 1;
	memcpy(dcw, data + 14, 16);
	uint32_t crc = b2i(4, data + 30);
	char tmp[32];
	cs_log_dbg(D_READER, "-> cws=%s, peer=%04X, ecm_pid=%04X, sid=%04X, crc=%08X, type=%02X, dist=%01X, unkn1=%01X, unkn2=%02X, chid/0x0000/0xffff=%04X",
		cs_hexdump(0, dcw, 32, tmp, sizeof(tmp)), 
		data[10] << 8 | data[11], data[6] << 8 | data[7], data[8] << 8 | data[9], crc, data[41], data[42] & 0x0f, data[42] >> 4, data[43], data[37] << 8 | data[38]);
	struct timeb t_now;             
	cs_ftime(&t_now);
	int64_t cw_time = GBOX_DEFAULT_CW_TIME;
	for(i = 0; i < cfg.max_pending; i++)
	{
		if(proxy->ecmtask[i].gbox_crc == crc)
		{
			id_card = b2i(2, data + 10);
			cw_time = comp_timeb(&t_now, &proxy->ecmtask[i].tps) - gbox_get_pending_time(&proxy->ecmtask[i], id_card, data[36]);
			gbox_add_good_sid(id_card, proxy->ecmtask[i].caid, data[36], proxy->ecmtask[i].srvid, cw_time);
			proxy->reader->currenthops = data[42] & 0x0f;
			gbox_remove_all_bad_sids(&proxy->ecmtask[i], proxy->ecmtask[i].srvid);
			if(proxy->ecmtask[i].gbox_ecm_status == GBOX_ECM_NOT_ASKED || proxy->ecmtask[i].gbox_ecm_status == GBOX_ECM_ANSWERED)
       				{ return -1; }
			proxy->ecmtask[i].gbox_ecm_status = GBOX_ECM_ANSWERED;
			proxy->ecmtask[i].gbox_ecm_id = id_card;
			*rc = 1;
			return proxy->ecmtask[i].idx;
		}
	}
	//late answers from other peers,timing not possible
	gbox_add_good_sid(id_card, data[34] << 8 | data[35], data[36], data[8] << 8 | data[9], GBOX_DEFAULT_CW_TIME);
	cs_log_dbg(D_READER, "no task found for crc=%08x", crc);
	return -1;
}

static int8_t gbox_cw_received(struct s_client *cli, uchar *data, int32_t n)
{
	int32_t rc = 0, i = 0, idx = 0;
	uchar dcw[16];
	
	idx = gbox_recv_chk(cli, dcw, &rc, data, n);
	if(idx < 0) { return -1; }  // no dcw received
	if(!idx) { idx = cli->last_idx; }
	cli->reader->last_g = time((time_t *)0); // for reconnect timeout
	for(i = 0; i < cfg.max_pending; i++)
	{
		if(cli->ecmtask[i].idx == idx)
		{
			cli->pending--;
			casc_check_dcw(cli->reader, i, rc, dcw);
			return 0;
		}
	}
	return -1;
}

int32_t gbox_cmd_switch(struct s_client *proxy, uchar *data, int32_t n)
{
	if (!data || !proxy) { return -1; }
	uint16_t cmd = gbox_decode_cmd(data);
	switch(cmd)
	{
	case MSG_BOXINFO:
		cs_log("-> BOXINFO from %s",username(proxy));	
		gbox_send_hello(proxy, GBOX_STAT_HELLOR);
		break;
	case MSG_GOODBYE:
		cs_log("-> goodbye message from %s",username(proxy));	
		//needfix what to do after Goodbye?
		//suspect: we get goodbye as signal of SID not found
		break;
	case MSG_UNKNWN:
		cs_log("-> MSG_UNKNWN 48F9 from %s", username(proxy));	  
		break;
	case MSG_GSMS_1:
		if (!cfg.gsms_dis)
		{
			cs_log("-> MSG_GSMS_1 from %s", username(proxy));
			gbox_send_gsms_ack(proxy,1);
			write_gsms_msg(proxy, data +4, data[3], data[2]);
		}
		else
		{
			gsms_unavail();
		}
 		break;
	case MSG_GSMS_2:
		if (!cfg.gsms_dis)
		{
			cs_log("-> MSG_GSMS_2 from %s", username(proxy));
			gbox_send_gsms_ack(proxy,2);
			write_gsms_msg(proxy, data +16, data[14], data[15]);
		}
		else
		{
			gsms_unavail();
		}
		break;
	case MSG_GSMS_ACK_1:
		if (!cfg.gsms_dis)
		{
			cs_log("-> MSG_GSMS_ACK_1 from %s", username(proxy));
			write_gsms_ack(proxy,1);
		}
		else
		{
			gsms_unavail();
		}
		break;
	case MSG_GSMS_ACK_2:
		if (!cfg.gsms_dis)
		{
			cs_log("-> MSG_GSMS_ACK_2 from %s", username(proxy));
			write_gsms_ack(proxy,2);
		} 
		else
		{
			gsms_unavail();
		}
		break;
	case MSG_HELLO1:
	case MSG_HELLO:
		if (gbox_cmd_hello(proxy, data, n) < 0)
			{ return -1; }
		break;
	case MSG_CW:
		gbox_cw_received(proxy, data, n);
		break;
	case MSG_CHECKCODE:
		gbox_checkcode_recv(proxy, data + 10);
		break;
	case MSG_ECM:
		gbox_incoming_ecm(proxy, data, n);
		break;
	default:
		cs_log("-> unknown command %04X received from %s", cmd, username(proxy));
		cs_log_dump_dbg(D_READER, data, n, "unknown data received (%d bytes):", n);
	} // end switch
	if ((time(NULL) - last_stats_written) > STATS_WRITE_TIME)
	{ 
		gbox_write_stats();
		last_stats_written = time(NULL);
	}
	return 0;
}

static void gbox_local_cards(struct s_reader *reader, TUNTAB *ttab)
{
	int32_t i;
	uint32_t prid = 0;
	int8_t slot = 0;
#ifdef MODULE_CCCAM
	LL_ITER it, it2;
	struct cc_card *card = NULL;
	struct cc_data *cc;
	uint32_t checksum = 0;
	uint16_t cc_peer_id = 0;
	struct cc_provider *provider;
	uint8_t *node1 = NULL;
	uint8_t min_reshare = 0;
	gbox_delete_cards(GBOX_DELETE_WITH_TYPE, GBOX_CARD_TYPE_CCCAM);
#endif	
	gbox_delete_cards(GBOX_DELETE_WITH_ID, local_gbox.id);
	struct s_client *cl;
	cs_readlock(__func__, &clientlist_lock);
	for(cl = first_client; cl; cl = cl->next)
	{
		if(cl->typ == 'r' && cl->reader && cl->reader->card_status == 2)
		{
			slot = gbox_next_free_slot(local_gbox.id);
			//SECA, Viaccess and Cryptoworks have multiple providers
			if(caid_is_seca(cl->reader->caid) || caid_is_viaccess(cl->reader->caid) || caid_is_cryptoworks(cl->reader->caid))
			{
				for(i = 0; i < cl->reader->nprov; i++)
				{
					prid = cl->reader->prid[i][1] << 16 |
						   cl->reader->prid[i][2] << 8 | cl->reader->prid[i][3];
					gbox_add_card(local_gbox.id, gbox_get_caprovid(cl->reader->caid, prid), slot, reader->gbox_reshare, 0, GBOX_CARD_TYPE_LOCAL, NULL);
				}
			}
			else
			{ 
				gbox_add_card(local_gbox.id, gbox_get_caprovid(cl->reader->caid, 0), slot, reader->gbox_reshare, 0, GBOX_CARD_TYPE_LOCAL, NULL); 
				
				//Check for Betatunnel on gbox account in oscam.user
				if (chk_is_betatunnel_caid(cl->reader->caid) == 1 && ttab->ttdata && cl->reader->caid == ttab->ttdata[0].bt_caidto)
				{
					//For now only first entry in tunnel tab. No sense in iteration?
					//Add betatunnel card to transmitted list
					gbox_add_card(local_gbox.id, gbox_get_caprovid(ttab->ttdata[0].bt_caidfrom, 0), slot, reader->gbox_reshare, 0, GBOX_CARD_TYPE_BETUN, NULL);
					cs_log_dbg(D_READER, "gbox created betatunnel card for caid: %04X->%04X", ttab->ttdata[0].bt_caidfrom, cl->reader->caid);
				}
			}
		}   //end local readers
#ifdef MODULE_CCCAM
		if((cfg.cc_reshare > -1) && (reader->gbox_cccam_reshare) && cl->typ == 'p' && cl->reader && cl->reader->typ == R_CCCAM && cl->cc)
		{
			cc = cl->cc;
			it = ll_iter_create(cc->cards);
			while((card = ll_iter_next(&it)))
			{
				//calculate gbox id from cc node
				node1 = ll_has_elements(card->remote_nodes);
				checksum = ((node1[0] ^ node1[7]) << 8) |
						((node1[1] ^ node1[6]) << 24) |
						(node1[2] ^ node1[5]) |
						((node1[3] ^ node1[4]) << 16);
				cc_peer_id = ((((checksum >> 24) & 0xFF) ^((checksum >> 8) & 0xFF)) << 8 |
							  (((checksum >> 16) & 0xFF) ^(checksum & 0xFF)));
				slot = gbox_next_free_slot(cc_peer_id);
				min_reshare = cfg.cc_reshare;
				if (card->reshare < min_reshare)
					{ min_reshare = card->reshare; }				
				min_reshare++; //strange CCCam logic. 0 means direct peers
				if (reader->gbox_cccam_reshare < min_reshare)
					{ min_reshare = reader->gbox_cccam_reshare; }
				if(caid_is_seca(card->caid) || caid_is_viaccess(card->caid) || caid_is_cryptoworks(card->caid))
				{
					it2 = ll_iter_create(card->providers);
					while((provider = ll_iter_next(&it2)))
						{ gbox_add_card(cc_peer_id, gbox_get_caprovid(card->caid, provider->prov), slot, min_reshare, card->hop, GBOX_CARD_TYPE_CCCAM, NULL); }
				}
				else
					{ gbox_add_card(cc_peer_id, gbox_get_caprovid(card->caid, 0), slot, min_reshare, card->hop, GBOX_CARD_TYPE_CCCAM, NULL); }
			}
		}   //end cccam
#endif
	} //end for clients
	cs_readunlock(__func__, &clientlist_lock);

	if (cfg.gbox_proxy_cards_num > 0) 
	{ 
		for (i = 0; i < cfg.gbox_proxy_cards_num; i++) 
		{
			slot = gbox_next_free_slot(local_gbox.id);
			gbox_add_card(local_gbox.id, cfg.gbox_proxy_card[i], slot, reader->gbox_reshare, 0, GBOX_CARD_TYPE_PROXY, NULL);
			if ((cfg.gbox_proxy_card[i] >> 24) == 0x05)
			{
				cs_log_dbg(D_READER,"add proxy card:  slot %d %04lX:%06lX",slot, (cfg.gbox_proxy_card[i] >> 16) & 0xFFF0, cfg.gbox_proxy_card[i] & 0xFFFFF);
			} else
			{
				cs_log_dbg(D_READER,"add proxy card:  slot %d %04lX:%06lX",slot, cfg.gbox_proxy_card[i] >> 16, cfg.gbox_proxy_card[i] & 0xFFFF);
			}	
		}
	}  // end add proxy reader cards
	gbox_write_local_cards_info();
} //end add local gbox cards

//returns -1 in case of error, 1 if authentication was performed, 0 else
static int8_t gbox_check_header(struct s_client *cli, struct s_client *proxy, uchar *data, int32_t l)
{
	struct gbox_peer *peer = NULL;	
	if (proxy) { peer = proxy->gbox; }

	char tmp[0x50];
	int32_t n = l;
	uint8_t authentication_done = 0;
	uint32_t my_received_pw = 0;
	uint32_t peer_received_pw = 0;
	cs_log_dump_dbg(D_READER, data, n, "-> encrypted data (%d bytes):", n);

	if(gbox_decode_cmd(data) == MSG_HELLO1)
		{ cs_log("test cs2gbox"); }
	else
		{ gbox_decrypt(data, n, local_gbox.password); }

	cs_log_dump_dbg(D_READER, data, n, "-> decrypted data (%d bytes):", n);
	//verify my pass received
	my_received_pw = b2i(4, data + 2);
	if (my_received_pw == local_gbox.password)
	{
		cs_log_dbg(D_READER, "-> data, peer : %04x   data: %s", cli->gbox_peer_id, cs_hexdump(0, data, l, tmp, sizeof(tmp)));

		if (gbox_decode_cmd(data) != MSG_CW)
		{
			if (cli->gbox_peer_id == NO_GBOX_ID)
			{
				if (gbox_auth_client(cli, b2i(4, data + 6)) < 0)
				{ 
					cs_log_dbg(D_READER, "Authentication failed. Please check user in oscam.server and oscam.user");
					return -1;
				}
				authentication_done = 1;
				proxy = get_gbox_proxy(cli->gbox_peer_id);
				gbox_local_cards(proxy->reader, &cli->ttab);
				peer = proxy->gbox;
			}
			if (!peer) { return -1; }
			peer_received_pw = b2i(4, data + 6);
			if (peer_received_pw != peer->gbox.password)
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
	else if (gbox_decode_cmd(data) == MSG_GSMS_1 || gbox_decode_cmd(data) == MSG_GSMS_ACK_1 ) 
	{
		// MSG_GSMS_1 dont have passw and would fail. Just let them pass through for processing later
	}
	else
	{
		cs_log("ATTACK ALERT from IP %s", cs_inet_ntoa(cli->ip));
		cs_log("received data, data: %s", cs_hexdump(0, data, n, tmp, sizeof(tmp)));
		return -1;
		//continue; // next client
	}
	if (!proxy) { return -1; }

	if (!IP_EQUAL(cli->ip, proxy->ip))
	{ 
		cs_log("Received IP %s did not match previous IP %s. Try to reconnect.", cs_inet_ntoa(cli->ip), cs_inet_ntoa(proxy->ip));
		gbox_reconnect_client(cli->gbox_peer_id); 
		return -1;	
	}
	if(!peer) { return -1; }

	return authentication_done;
}

static int32_t gbox_recv(struct s_client *cli, uchar *buf, int32_t l)
{
	uchar data[RECEIVE_BUFFER_SIZE];
	int32_t n = l, tmp;
	int8_t ret = 0;

	if(!cli->udp_fd || !cli->is_udp || cli->typ != 'c')
		{ return -1; }
	
	n = recv_from_udpipe(buf);		
	if (n < MIN_GBOX_MESSAGE_LENGTH || n >= RECEIVE_BUFFER_SIZE) //protect against too short or too long messages
		{ return -1; }
			
	struct s_client *proxy = get_gbox_proxy(cli->gbox_peer_id);
			
	memcpy(&data[0], buf, n);

	ret = gbox_check_header(cli, proxy, &data[0], n);
	if (ret < 0) { return -1; }
	
	//in case of new authentication the proxy gbox can now be found 
	if (ret) { proxy = get_gbox_proxy(cli->gbox_peer_id); } 	

	if (!proxy) { return -1; }	
		
	cli->last = time((time_t *)0);
	//clients may timeout - attach to peer's gbox/reader
	cli->gbox = proxy->gbox; //point to the same gbox as proxy
	cli->reader = proxy->reader; //point to the same reader as proxy
	struct gbox_peer *peer = proxy->gbox;
				
	cs_writelock(__func__, &peer->lock);
	tmp = gbox_cmd_switch(proxy, data, n);
	cs_writeunlock(__func__, &peer->lock);
	
	if(tmp < 0)
		{ return -1; }
				
	//clients may timeout - dettach from peer's gbox/reader
	cli->gbox = NULL;
	cli->reader = NULL;
	return 0;	
}

static void gbox_send_dcw(struct s_client *cl, ECM_REQUEST *er)
{
	if (!cl || !er) { return; }

	struct s_client *cli = get_gbox_proxy(cl->gbox_peer_id);
	if (!cli || !cli->gbox) { return; }
	struct gbox_peer *peer = cli->gbox;

	if(er->rc >= E_NOTFOUND)
	{
		cs_log_dbg(D_READER, "unable to decode!");
		return;
	}

	uchar buf[60];
	memset(buf, 0, sizeof(buf));

	struct gbox_ecm_request_ext *ere = er->src_data;

	gbox_message_header(buf, MSG_CW , peer->gbox.password, 0);
	i2b_buf(2, er->pid, buf + 6);		//PID
	i2b_buf(2, er->srvid, buf + 8);		//SrvID
	i2b_buf(2, ere->gbox_mypeer, buf + 10);	//From peer
	buf[12] = (ere->gbox_slot << 4) | (er->ecm[0] & 0x0f); //slot << 4 | even/odd
	buf[13] = er->caid >> 8;		//CAID first byte
	memcpy(buf + 14, er->cw, 16);		//CW
	i2b_buf(4, er->gbox_crc, buf + 30);	//CRC
	i2b_buf(2, er->caid, buf + 34);		//CAID
	buf[36] = ere->gbox_slot;  		//Slot
	if (buf[34] == 0x06)			//if irdeto
		{ i2b_buf(2, er->chid, buf + 37); }	//CHID
	else
	{
		if (local_gbox.minor_version == 0x2A)
		{
			buf[37] = 0xff;		//gbox.net sends 0xff
			buf[38] = 0xff;		//gbox.net sends 0xff
		}
		else
		{
			buf[37] = 0;		//gbox sends 0
			buf[38] = 0;		//gbox sends 0
		}	
	}
	i2b_buf(2, ere->gbox_peer, buf + 39);	//Target peer
	if (er->rc == E_CACHE1 || er->rc == E_CACHE2 || er->rc == E_CACHEEX)
		{ buf[41] = 0x03; }		//cache
	else
		{ buf[41] = 0x01; }		//card, emu, needs probably further investigation
	buf[42] = 0x30;				//1st nibble unknown / 2nd nibble distance
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

	cs_log_dbg(D_READER, "<- CW (distance: %d) to %04X via %s/%d", ere->gbox_hops, ere->gbox_peer, cli->reader->label, cli->port);
}

void *gbox_rebroadcast_thread(struct gbox_rbc_thread_args *args)
{
	if (!args) { return NULL; }
	
	struct s_client *cli = args->cli;
	ECM_REQUEST *er = args->er;
	uint32_t waittime = args->waittime;

	//NEEDFIX currently the next line avoids a second rebroadcast 
	if (!is_valid_client(cli)) { return NULL; }
	
	SAFE_MUTEX_LOCK(&cli->thread_lock);
	cli->thread_active = 1;
	SAFE_SETSPECIFIC(getclient, cli);
	set_thread_name(__func__);
	cli->thread_active = 0;
	SAFE_MUTEX_UNLOCK(&cli->thread_lock);
	
	cs_sleepms(waittime);
	if (!cli || cli->kill || !cli->gbox || !er) { return NULL; }
	SAFE_MUTEX_LOCK(&cli->thread_lock);
	cli->thread_active = 1;

	struct gbox_peer *peer = cli->gbox;

	struct timeb t_now, tbc;             
	cs_ftime(&t_now);

	tbc = er->tps;
	add_ms_to_timeb_diff(&tbc, cfg.ctimeout);
	int32_t time_to_timeout = (int32_t) comp_timeb(&tbc, &t_now);

	//ecm is not answered yet and still chance to get CW
	if (er->rc >= E_NOTFOUND && time_to_timeout > GBOX_DEFAULT_CW_TIME)
	{
 		cs_writelock(__func__, &peer->lock);
		gbox_send_ecm(cli, er);
 		cs_writeunlock(__func__, &peer->lock);
	}
	cli->thread_active = 0;
	SAFE_MUTEX_UNLOCK(&cli->thread_lock);	

	return NULL;
}

static int32_t gbox_send_ecm(struct s_client *cli, ECM_REQUEST *er)
{
	if(!cli || !er || !cli->reader)
		{ return -1; }

	if(!cli->gbox || !cli->reader->tcp_connected)
	{
		cs_log_dbg(D_READER, "%s server not init!", cli->reader->label);
		write_ecm_answer(cli->reader, er, E_NOTFOUND, 0x27, NULL, NULL);
		return -1;
	}

	struct gbox_peer *peer = cli->gbox;
	int32_t cont_1;

	if(!peer->filtered_cards)
	{
		cs_log_dbg(D_READER, "%s NO CARDS!", cli->reader->label);
		write_ecm_answer(cli->reader, er, E_NOTFOUND, E2_CCCAM_NOCARD, NULL, NULL);
		return -1;
	}

	if(!peer->online)
	{
		cs_log_dbg(D_READER, "peer is OFFLINE!");
		write_ecm_answer(cli->reader, er, E_NOTFOUND, 0x27, NULL, NULL);
		//      gbox_send_hello(cli,0);
		return -1;
	}

	if(er->gbox_ecm_status == GBOX_ECM_ANSWERED)
		{ cs_log_dbg(D_READER, "%s replied to this ecm already", cli->reader->label); }

	if(er->gbox_ecm_status == GBOX_ECM_NOT_ASKED)
		{ er->gbox_cards_pending = ll_create("pending_gbox_cards"); }

	if(er->gbox_ecm_id == peer->gbox.id)
	{
		cs_log_dbg(D_READER, "%s provided ecm", cli->reader->label);
		write_ecm_answer(cli->reader, er, E_NOTFOUND, 0x27, NULL, NULL);
		return 0;
	}

	uchar send_buf_1[1024];
	int32_t len2;

	if(!er->ecmlen) { return 0; }

	len2 = er->ecmlen + 18;
	er->gbox_crc = gbox_get_ecmchecksum(&er->ecm[0], er->ecmlen);

	memset(send_buf_1, 0, sizeof(send_buf_1));

	uint8_t cont_card_1 = 0;
        uint8_t max_ecm_reached = 0;
        uint32_t current_avg_card_time = 0;        
        
	gbox_message_header(send_buf_1, MSG_ECM , peer->gbox.password, local_gbox.password);

	i2b_buf(2, er->pid, send_buf_1 + 10);
	i2b_buf(2, er->srvid, send_buf_1 + 12);
	send_buf_1[14] = 0x00;
	send_buf_1[15] = 0x00;

	send_buf_1[16] = cont_card_1;
	send_buf_1[17] = 0x00;

	memcpy(send_buf_1 + 18, er->ecm, er->ecmlen);

	i2b_buf(2, local_gbox.id, send_buf_1 + len2);

	send_buf_1[len2 + 2] = gbox_get_my_vers();
	send_buf_1[len2 + 3] = 0x00;
	send_buf_1[len2 + 4] = gbox_get_my_cpu_api();

	uint32_t caprovid = gbox_get_caprovid(er->caid, er->prid);
	i2b_buf(4, caprovid, send_buf_1 + len2 + 5);

	send_buf_1[len2 + 9] = 0x00;
	cont_1 = len2 + 10;

	cont_card_1 = gbox_get_cards_for_ecm(&send_buf_1[0], len2 + 10, cli->reader->gbox_maxecmsend, er, &current_avg_card_time, peer->gbox.id);
	if (cont_card_1 == cli->reader->gbox_maxecmsend)
		{ max_ecm_reached = 1; }
	cont_1 += cont_card_1 * 3;
	
	if(!cont_card_1 && er->gbox_ecm_status == GBOX_ECM_NOT_ASKED)
	{
		cs_log_dbg(D_READER, "no valid card found for CAID: %04X PROVID: %04X", er->caid, er->prid);
		write_ecm_answer(cli->reader, er, E_NOTFOUND, E2_CCCAM_NOCARD, NULL, NULL);
		return -1;
	}
	if(cont_card_1)
	{
		send_buf_1[16] = cont_card_1;

		//Hops
		send_buf_1[cont_1] = 0;
		cont_1++;		

		memcpy(&send_buf_1[cont_1], gbox_get_checkcode(), 7);
		cont_1 = cont_1 + 7;
		memcpy(&send_buf_1[cont_1], peer->checkcode, 7);
		cont_1 = cont_1 + 7;

		cs_log_dbg(D_READER, "gbox sending ecm for %04X@%06X:%04X to %d cards -> %s", er->caid, er->prid , er->srvid, cont_card_1, cli->reader->label);
		uint32_t i = 0;
		struct gbox_card_pending *pending = NULL;
		struct timeb t_now;             
		cs_ftime(&t_now);
		for (i = 0; i < cont_card_1; i++)
		{	 			
			if(!cs_malloc(&pending, sizeof(struct gbox_card_pending)))
			{
				cs_log("Can't allocate gbox card pending");
				return -1;
			}
			pending->id.peer = (send_buf_1[len2+10+i*3] << 8) | send_buf_1[len2+11+i*3];
			pending->id.slot = send_buf_1[len2+12+i*3];
			pending->pending_time = comp_timeb(&t_now, &er->tps);
			ll_append(er->gbox_cards_pending, pending);		
			cs_log_dbg(D_READER, "gbox card %d: ID: %04X, Slot: %02X", i+1, (send_buf_1[len2+10+i*3] << 8) | send_buf_1[len2+11+i*3], send_buf_1[len2+12+i*3]); 
		}
	
		LL_LOCKITER *li = ll_li_create(er->gbox_cards_pending, 0);
		while ((pending = ll_li_next(li)))
			{ cs_log_dbg(D_READER, "Pending Card ID: %04X Slot: %02X Time: %d", pending->id.peer, pending->id.slot, pending->pending_time); }
		ll_li_destroy(li);
	
		if(er->gbox_ecm_status > GBOX_ECM_NOT_ASKED)
			{ er->gbox_ecm_status++; }
		else 
		{
			if(max_ecm_reached)
				{ er->gbox_ecm_status = GBOX_ECM_SENT; }
			else
				{ er->gbox_ecm_status = GBOX_ECM_SENT_ALL; }
			cli->pending++;		
		}	  	
		gbox_send(cli, send_buf_1, cont_1);
		cli->reader->last_s = time((time_t *) 0);
	
		if(er->gbox_ecm_status < GBOX_ECM_ANSWERED)
		{ 
			//Create thread to rebroacast ecm after time
			struct gbox_rbc_thread_args args;
			args.cli = cli;
			args.er = er;
			if ((current_avg_card_time > 0) && (cont_card_1 == 1))
			{
				args.waittime = current_avg_card_time + (current_avg_card_time / 2);
				if (args.waittime < GBOX_MIN_REBROADCAST_TIME)
				{ args.waittime = GBOX_MIN_REBROADCAST_TIME; }
			}
			else
				{ args.waittime = GBOX_REBROADCAST_TIMEOUT; }
			cs_log_dbg(D_READER, "Creating rebroadcast thread with waittime: %d", args.waittime);
			int32_t ret = start_thread("rebroadcast", (void *)gbox_rebroadcast_thread, &args, NULL, 1);
			if(ret)
			{
				return -1;
			}
		}
		else
			{ er->gbox_ecm_status--; }
	}	
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
	local_gbox.password = 0;
	local_gbox.minor_version = gbox_get_my_vers();
	local_gbox.cpu_api = gbox_get_my_cpu_api();
	init_gbox_cards();

	if(!cfg.gbox_my_password || strlen(cfg.gbox_my_password) != 8) { return; }

	local_gbox.password = a2i(cfg.gbox_my_password, 4);
	cs_log_dbg(D_READER, "gbox my password: %s:", cfg.gbox_my_password);

	local_gbox.id = gbox_convert_password_to_id(local_gbox.password);
	if (local_gbox.id == NO_GBOX_ID)
	{
		cs_log("invalid local gbox id: %04X", local_gbox.id);
	}
	last_stats_written = time(NULL);
	gbox_write_version();
	local_gbox_initialized = 1;
}

static int32_t gbox_client_init(struct s_client *cli)
{
	if (!cli || cli->typ != 'p' || !cli->reader)
	{ 
		cs_log("error, wrong call to gbox_proxy_init!");
		return -1; 	
	}

	if (!local_gbox_initialized)
		{ init_local_gbox(); }

	if(!cfg.gbx_port[0] || cfg.gbx_port[0] > 65535)
	{
		cs_log("error, no/invalid port=%d configured in oscam.conf!",
			   cfg.gbx_port[0] ? cfg.gbx_port[0] : 0);
		return -1;
	}
	
	if(!cfg.gbox_hostname || strlen(cfg.gbox_hostname) > 128)
	{
		cs_log("error, no/invalid hostname '%s' configured in oscam.conf!",
			   cfg.gbox_hostname ? cfg.gbox_hostname : "");
		return -1;
	}

	if(!local_gbox.id)
	{
		cs_log("error, no/invalid password '%s' configured in oscam.conf!",
			   cfg.gbox_my_password ? cfg.gbox_my_password : "");
		return -1;
	}

	if(!cs_malloc(&cli->gbox, sizeof(struct gbox_peer)))
		{ return -1; }

	struct s_reader *rdr = cli->reader;
	struct gbox_peer *peer = cli->gbox;

	memset(peer, 0, sizeof(struct gbox_peer));

	peer->gbox.password = a2i(rdr->r_pwd, 4);
	cs_log_dbg(D_READER, "gbox peer password: %s:", rdr->r_pwd);

	peer->gbox.id = gbox_convert_password_to_id(peer->gbox.password);	
	if (get_gbox_proxy(peer->gbox.id) || peer->gbox.id == NO_GBOX_ID || peer->gbox.id == local_gbox.id)
	{
		cs_log("error, double/invalid gbox id: %04X", peer->gbox.id);	
		return -1;
	}
	cs_lock_create(__func__, &peer->lock, "gbox_lock", 5000);

	gbox_reinit_peer(peer);	

	cli->gbox_peer_id = peer->gbox.id;	

	cli->pfd = 0;
	cli->crypted = 1;

	rdr->card_status = CARD_NEED_INIT;
	rdr->tcp_connected = 0;

	set_null_ip(&cli->ip);

	if((cli->udp_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
	{
		cs_log("socket creation failed (errno=%d %s)", errno, strerror(errno));
		cs_disconnect_client(cli);
	}

	int32_t opt = 1;
	setsockopt(cli->udp_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	set_so_reuseport(cli->udp_fd);

	set_socket_priority(cli->udp_fd, cfg.netprio);

	memset((char *)&cli->udp_sa, 0, sizeof(cli->udp_sa));

	if(!hostResolve(rdr))
		{ return 0; }

	cli->port = rdr->r_port;
	SIN_GET_FAMILY(cli->udp_sa) = AF_INET;
	SIN_GET_PORT(cli->udp_sa) = htons((uint16_t)rdr->r_port);
	hostname2ip(cli->reader->device, &SIN_GET_ADDR(cli->udp_sa));

	cs_log("proxy %s (fd=%d, peer id=%04X, my id=%04X, my hostname=%s, peer's listen port=%d)",
		   rdr->device, cli->udp_fd, peer->gbox.id, local_gbox.id, cfg.gbox_hostname, rdr->r_port);

	cli->pfd = cli->udp_fd;

	gbox_send_hello(cli, GBOX_STAT_HELLOL);

	if(!cli->reader->gbox_maxecmsend)
		{ cli->reader->gbox_maxecmsend = DEFAULT_GBOX_MAX_ECM_SEND; }

	if(!cli->reader->gbox_maxdist)
		{ cli->reader->gbox_maxdist = DEFAULT_GBOX_MAX_DIST; }

	//value > DEFAULT_GBOX_RESHARE not allowed in gbox network
	if(!cli->reader->gbox_reshare || cli->reader->gbox_reshare > DEFAULT_GBOX_RESHARE)
		{ cli->reader->gbox_reshare = DEFAULT_GBOX_RESHARE; }

	if(!cli->reader->gbox_cccam_reshare || cli->reader->gbox_cccam_reshare > DEFAULT_GBOX_RESHARE)
		{ cli->reader->gbox_cccam_reshare = DEFAULT_GBOX_RESHARE; }

	start_sms_sender();
	
	return 0;
}

static void gbox_s_idle(struct s_client *cl)
{
	uint32_t time_since_last;
	struct s_client *proxy = get_gbox_proxy(cl->gbox_peer_id);
	struct gbox_peer *peer;

	if (proxy && proxy->gbox)
	{ 
		if (llabs(proxy->last - time(NULL)) > llabs(cl->lastecm - time(NULL)))
			{ time_since_last = llabs(cl->lastecm - time(NULL)); } 
		else { time_since_last = llabs(proxy->last - time(NULL)); }
		if (time_since_last > (HELLO_KEEPALIVE_TIME*3) && cl->gbox_peer_id != NO_GBOX_ID)	
		{
			//gbox peer apparently died without saying goodbye
			peer = proxy->gbox;
			cs_writelock(__func__, &peer->lock);
			cs_log_dbg(D_READER, "time since last proxy activity in sec: %d => taking gbox peer offline",time_since_last);
			gbox_reinit_proxy(proxy);
			cs_writeunlock(__func__, &peer->lock);
		}
	
		time_since_last = llabs(cl->lastecm - time(NULL));
		if (time_since_last > HELLO_KEEPALIVE_TIME && cl->gbox_peer_id != NO_GBOX_ID)
		{
			peer = proxy->gbox;
			cs_writelock(__func__, &peer->lock);
			cs_log_dbg(D_READER, "time since last ecm in sec: %d => trigger keepalive hello",time_since_last);
			if (!peer->online)
				{ gbox_send_hello(proxy, GBOX_STAT_HELLOL); }
			else
				{ gbox_send_hello(proxy, GBOX_STAT_HELLOS); }
			cs_writeunlock(__func__, &peer->lock);
		}	
	}	
	//prevent users from timing out
	cs_log_dbg(D_READER, "client idle prevented: %s", username(cl));
	cl->last = time((time_t *)0);
}

static int8_t gbox_send_peer_good_night(struct s_client *proxy)
{
	uchar outbuf[64];
	int32_t hostname_len = 0;
	if (cfg.gbox_hostname)
		hostname_len = strlen(cfg.gbox_hostname);
	int32_t len = hostname_len + 22;
	if(proxy->gbox && proxy->typ == 'p')
	{
		struct gbox_peer *peer = proxy->gbox;
		struct s_reader *rdr = proxy->reader;
		if (peer->online)
		{
			gbox_message_header(outbuf, MSG_HELLO, peer->gbox.password, local_gbox.password);
			outbuf[10] = 0x01;
			outbuf[11] = 0x80;
			memset(&outbuf[12], 0xff, 7);
			outbuf[19] = gbox_get_my_vers();
			outbuf[20] = gbox_get_my_cpu_api();
			memcpy(&outbuf[21], cfg.gbox_hostname, hostname_len);
			outbuf[21 + hostname_len] = hostname_len;
			cs_log("<- good night to %s:%d id: %04X", rdr->device, rdr->r_port, peer->gbox.id);
			gbox_compress(outbuf, len, &len);
			gbox_send(proxy, outbuf, len);
			gbox_reinit_proxy(proxy);
		}
	}
	return 0;
}

void gbox_send_good_night(void)
{
	gbox_free_cardlist();
	struct s_client *cli;
	cs_readlock(__func__, &clientlist_lock);
	for(cli = first_client; cli; cli = cli->next)
	{
		if(cli->gbox && cli->typ == 'p')
			{ gbox_send_peer_good_night(cli); }
	}
	cs_readunlock(__func__, &clientlist_lock);
}                                                    
/*
void gbox_send_goodbye(uint16_t boxid) //to implement later
{
	uchar outbuf[15];
	struct s_client *cli;
	cs_readlock(__func__, &clientlist_lock);
	for (cli = first_client; cli; cli = cli->next)
	{
		if(cli->gbox && cli->typ == 'p')
		{
			struct gbox_peer *peer = cli->gbox;
			if (peer->online && boxid == peer->gbox.id)
			{	
				gbox_message_header(outbuf, MSG_GOODBYE, peer->gbox.password, local_gbox.password);
				cs_log("gbox send goodbye to boxid: %04X", peer->gbox.id);
				gbox_send(cli, outbuf, 0xA);
			}
		}
	}
	cs_readunlock(__func__, &clientlist_lock);
}

void gbox_send_HERE_query (uint16_t boxid)	//gbox.net send this cmd
{
	uchar outbuf[30];
	int32_t hostname_len = strlen(cfg.gbox_hostname);
	struct s_client *cli;
	cs_readlock(__func__, &clientlist_lock);
	for (cli = first_client; cli; cli = cli->next)
	{
		if(cli->gbox && cli->typ == 'p')
		{
			struct gbox_peer *peer = cli->gbox;
			if (peer->online && boxid == peer->gbox.id)
			{	
				gbox_message_header(outbuf, MSG_HERE, peer->gbox.password, local_gbox.password);
				outbuf[0xA] = gbox_get_my_vers();
				outbuf[0xB] = gbox_get_my_cpu_api();
				memcpy(&outbuf[0xC], cfg.gbox_hostname, hostname_len);
				cs_log("gbox send 'HERE?' to boxid: %04X", peer->gbox.id);
				gbox_send(cli, outbuf, hostname_len + 0xC);
			}
		}
	}
	cs_readunlock(__func__, &clientlist_lock);
}
//This is most likely the same as MSG_HERE. Don't know what would be the difference
static void gbox_send_boxinfo(struct s_client *cli)
{
	struct gbox_peer *peer = cli->gbox;
	uchar outbuf[256];
	int32_t hostname_len = strlen(cfg.gbox_hostname);

	gbox_message_header(outbuf, MSG_BOXINFO, peer);
	outbuf[0xA] = local_gbox.minor_version;
	outbuf[0xB] = local_gbox.type;
	memcpy(&outbuf[0xC], cfg.gbox_hostname, hostname_len);
	gbox_send(cli, outbuf, hostname_len + 0xC);
}
*/
void module_gbox(struct s_module *ph)
{
	int32_t i;
	for(i = 0; i < CS_MAXPORTS; i++)
	{
		if(!cfg.gbx_port[i]) { break; }
		ph->ptab.nports++;
		ph->ptab.ports[i].s_port = cfg.gbx_port[i];
	}
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

	ph->s_idle = gbox_s_idle;
}
#endif
