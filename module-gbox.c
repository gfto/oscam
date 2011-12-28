#include "globals.h"
#ifdef MODULE_GBOX
#include <pthread.h>
//#define _XOPEN_SOURCE 600
#include <time.h>
#include <sys/time.h>

#include "module-datastruct-llist.h"
#include "algo/minilzo.h"

char file_gbox_ver[64]     = "/var/tmp/gbox_oscam.ver";
char file_share_info[64]   = "/tmp/cardgbox_1.info";
uchar gbox_hiversion       = 0x02;
uchar gbox_loversion       = 0x2d;
uchar gbox_type_dvb       = 0x53;

enum {
  MSG_ECM = 0x445c,
  MSG_CW = 0x4844,
  MSG_HELLO = 0xddab,
  MSG_HELLO1 = 0x4849,
  MSG_CHECKCODE = 0x41c0,
  MSG_GOODBYE = 0x9091,
  MSG_GSMS_ACK = 0x9098,
  MSG_GSMS = 0xff0,
  MSG_BOXINFO = 0xa0a1
};

struct gbox_card {
  uint16_t peer_id;
  uint16_t caid;
  uint32_t provid;
  uint32_t provid_1;
  int32_t slot;
  int32_t dist;
  int32_t lvl;
};

struct gbox_peer {
  uint16_t id;
  uchar key[4];
  uchar ver;
  uchar type;
  LLIST *cards;
  uchar checkcode[7];
  uchar *hostname;
  int32_t online;
  int32_t fail_count;
  int32_t hello_count;
  int32_t hello_cont_1;
  int32_t hello_cont_2;
  int32_t goodbye_cont;
  uchar ecm_idx;
};

struct gbox_data {
  uint16_t id;
  uchar checkcode[7];
  uchar key[4];
  uchar ver;
  uchar type;
  uint16_t exp_seq; // hello seq
  int32_t hello_expired;
  int32_t hello_initial;
  uchar cws[16];
  struct gbox_peer peer;
  CS_MUTEX_LOCK lock;
  uchar buf[1024];
  pthread_mutex_t peer_online_mutex;
  pthread_cond_t  peer_online_cond;
  LLIST *local_cards;
};

struct gbox_ecm_info {
  uint16_t peer,
	   peer_cw,
           caid,
           extra;
  uchar version,
        type,
        slot,
        unknwn1,
        unknwn2,
        ncards;
  uchar checksums[14];
};

////////////////////////////////////////////////////////////////////////////////
// GBOX BUFFER ENCRYPTION/DECRYPTION (thanks to dvbcrypt@gmail.com)
////////////////////////////////////////////////////////////////////////////////

unsigned char Lookup_Table[0x40] = {
  0x25,0x38,0xD4,0xCD,0x17,0x7A,0x5E,0x6C,0x52,0x42,0xFE,0x68,0xAB,0x3F,0xF7,0xBE,
  0x47,0x57,0x71,0xB0,0x23,0xC1,0x26,0x6C,0x41,0xCE,0x94,0x37,0x45,0x04,0xA2,0xEA,
  0x07,0x58,0x35,0x55,0x08,0x2A,0x0F,0xE7,0xAC,0x76,0xF0,0xC1,0xE6,0x09,0x10,0xDD,
  0xC5,0x8D,0x2E,0xD9,0x03,0x9C,0x3D,0x2C,0x4D,0x41,0x0C,0x5E,0xDE,0xE4,0x90,0xAE
  };


void gbox_encrypt8(unsigned char *buffer, unsigned char *pass)
{
  int passcounter;
  int bufcounter;
  unsigned char temp;

  for(passcounter=0; passcounter<4; passcounter++)
    for(bufcounter=7; bufcounter>=0; bufcounter--)
    {
      temp = ( buffer[bufcounter]>>2);
      temp = pass[3];
      pass[3] = (pass[3]/2)+(pass[2]&1)*0x80;
      pass[2] = (pass[2]/2)+(pass[1]&1)*0x80;
      pass[1] = (pass[1]/2)+(pass[0]&1)*0x80;
      pass[0] = (pass[0]/2)+(temp   &1)*0x80;
      buffer[(bufcounter+1) & 7] = buffer[ (bufcounter+1) & 7 ] - Lookup_Table[ (buffer[bufcounter]>>2) & 0x3F ];
      buffer[(bufcounter+1) & 7] = Lookup_Table[ ( buffer[bufcounter] - pass[(bufcounter+1) & 3] ) & 0x3F ] ^ buffer[ (bufcounter+1) & 7 ];
      buffer[(bufcounter+1) & 7] = buffer[ (bufcounter+1) & 7 ] - pass[(bufcounter & 3)];
    }
}

void gbox_decrypt8(unsigned char *buffer,unsigned char *pass)
{
 unsigned char temp;
 int bufcounter;
 int passcounter;
  for( passcounter=3; passcounter>=0; passcounter--) 
  for( bufcounter=0; bufcounter<=7; bufcounter++) {
    buffer[(bufcounter+1)&7] = pass[bufcounter&3] + buffer[(bufcounter+1)&7];
    temp = buffer[bufcounter] -  pass[(bufcounter+1)&3];
    buffer[(bufcounter+1)&7] = Lookup_Table[temp &0x3F] ^ buffer[(bufcounter+1)&7];
    temp = buffer[bufcounter] >> 2;
    buffer[(bufcounter+1)&7] =  Lookup_Table[temp & 0x3F] + buffer[(bufcounter+1)&7];

    temp = pass[0] & 0x80;
    pass[0] = ( (pass[1]&0x80)>>7 ) + (pass[0]<<1);
    pass[1] = ( (pass[2]&0x80)>>7 ) + (pass[1]<<1);
    pass[2] = ( (pass[3]&0x80)>>7 ) + (pass[2]<<1);
    pass[3] = ( temp>>7 ) + (pass[3]<<1);
  }

}

void gbox_decryptB(unsigned char *buffer, int bufsize, uchar *localkey)
{
  int counter;
  gbox_encrypt8(&buffer[bufsize-9], localkey);
  gbox_decrypt8(buffer, localkey);
  for (counter=bufsize-2; counter>=0; counter--)
    buffer[counter] = buffer[counter+1] ^ buffer[counter];
}

void gbox_encryptB(unsigned char *buffer, int bufsize, uchar *key)
{
 int counter;
  for (counter=0; counter<(bufsize-1); counter++)
    buffer[counter] = buffer[counter+1] ^ buffer[counter];
  gbox_encrypt8(buffer, key);
  gbox_decrypt8(&buffer[bufsize-9], key);
}

void gbox_encryptA(unsigned char *buffer, unsigned char *pass)
{
  int counter;
  unsigned char temp;
  for (counter=0x1F; counter>=0; counter--) {
    temp = pass[3]&1; 
    pass[3] = ((pass[2]&1)<<7) + (pass[3]>>1);
    pass[2] = ((pass[1]&1)<<7) + (pass[2]>>1);
    pass[1] = ((pass[0]&1)<<7) + (pass[1]>>1);
    pass[0] = (temp<<7) + (pass[0]>>1);
    temp = ( pass[(counter+1)&3] ^ buffer[counter&7] ) >> 2;
    buffer[(counter+1)&7] = Lookup_Table[temp & 0x3F]*2  +  buffer[  (counter+1) & 7 ];
    temp = buffer[counter&7] - pass[(counter+1) & 3];
    buffer[(counter+1)&7] = Lookup_Table[temp & 0x3F] ^ buffer[(counter+1)&7];
    buffer[(counter+1)&7] = pass[counter&3] + buffer[(counter+1)&7];
  }
}

void gbox_decryptA(unsigned char *buffer, unsigned char *pass)
{
  int counter;
  unsigned char temp;
  for (counter=0; counter<=0x1F; counter++) {
    buffer[(counter+1)&7] = buffer[(counter+1)&7] - pass[counter&3];
    temp = buffer[counter&7] - pass[(counter+1)&3];
    buffer[(counter+1)&7] = Lookup_Table[temp&0x3F] ^ buffer[(counter+1)&7];
    temp = ( pass[ (counter+1) & 3] ^ buffer[counter & 7] ) >> 2;
    buffer[(counter+1) & 7] = buffer[(counter+1)&7] - Lookup_Table[temp & 0x3F]*2;
    temp = pass[0]&0x80;
    pass[0] = ((pass[1]&0x80)>>7) + (pass[0]<<1);
    pass[1] = ((pass[2]&0x80)>>7) + (pass[1]<<1);
    pass[2] = ((pass[3]&0x80)>>7) + (pass[2]<<1);
    pass[3] = (temp>>7) + (pass[3]<<1);
  }
}

void gbox_encrypt(uchar *buffer, int bufsize, uchar *key)
{
	gbox_encryptA(buffer, key);
	gbox_encryptB(buffer, bufsize, key);
}

void gbox_decrypt(uchar *buffer, int bufsize, uchar *localkey)
{
	gbox_decryptB(buffer, bufsize, localkey);
	gbox_decryptA(buffer, localkey);
}

static void gbox_compress(struct gbox_data *UNUSED(gbox), uchar *buf, int32_t unpacked_len, int32_t *packed_len)
{
	  unsigned char *tmp = malloc(0x40000);
	  unsigned char *tmp2 = malloc(0x40000);

	  unpacked_len -= 12;
	  memcpy(tmp2, buf + 12, unpacked_len);

  lzo_init();

  lzo_voidp wrkmem = malloc(unpacked_len * 0x1000);
  cs_debug_mask(D_READER, "gbox: wrkmem = %p", wrkmem);
 lzo_uint pl = 0;
  if (lzo1x_1_compress(tmp2, unpacked_len, tmp, &pl, wrkmem) != LZO_E_OK)
    cs_log("gbox: compression failed!");

  memcpy(buf + 12, tmp, pl);
  pl += 12;

  free(tmp);
  free(tmp2);
  free(wrkmem);

  *packed_len = pl;
}

static void gbox_decompress(struct gbox_data *UNUSED(gbox), uchar *buf, int32_t *unpacked_len)
{
  uchar *tmp;

  if(!cs_malloc(&tmp,0x40000, -1)) return;
  int err;
  int len = *unpacked_len - 12;
  *unpacked_len = 0x40000;

  lzo_init();
  cs_debug_mask(D_READER, "decompressing %d bytes",len);
  if ((err=lzo1x_decompress_safe(buf + 12, len, tmp, (lzo_uint *)unpacked_len, NULL)) != LZO_E_OK)
    cs_debug_mask(D_READER, "gbox: decompression failed! errno=%d", err);

  memcpy(buf + 12, tmp, *unpacked_len);
  *unpacked_len += 12;
  free(tmp);
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

static void gbox_calc_checkcode(struct gbox_data *gbox)
{
    gbox->checkcode[0] = 0x00;
    gbox->checkcode[1] = 0x03;
    gbox->checkcode[2] = 0x04;
    gbox->checkcode[3] = 0x30;
    gbox->checkcode[4] = 0x01;  // reader number
    gbox->checkcode[5] = 0x25;
    gbox->checkcode[6] = 0x88;
}

uint32_t gbox_get_ecmchecksum(ECM_REQUEST *er)
{

  uint8_t checksum[4];
  int32_t counter;

  uchar ecm[255];
  memcpy(ecm, er->ecm, er->l);

  checksum[3] = ecm[0];
  checksum[2] = ecm[1];
  checksum[1] = ecm[2];
  checksum[0] = ecm[3];

  for (counter=1; counter < (er->l/4) - 4; counter++) {
    checksum[3] ^= ecm[counter*4];
    checksum[2] ^= ecm[counter*4+1];
    checksum[1] ^= ecm[counter*4+2];
    checksum[0] ^= ecm[counter*4+3];
  }

  return checksum[3] << 24 | checksum[2] << 16 | checksum[1] << 8 | checksum[0];
}


////////////////////////////////////////////////////////////////////////////////
// WRITE OUTPUT FILES
////////////////////////////////////////////////////////////////////////////////
void write_share_info()
{ 
  int32_t cart_cont=0;
  int32_t i = 0;
   uchar hostname1[30];

  FILE *fhandle;
  gbox_card_conter_total=0;
  fhandle=fopen(file_share_info, "wt");
  if (fhandle==0) {
  //  debug("couldn't open %s\n",file_share_onl);
    return;
  }

        struct s_client *cl;
	for (i=0, cl=first_client; cl ; cl=cl->next, i++) {
			if (cl->ctyp==6) {
			struct s_reader *rdr = cl->reader;
			struct gbox_data *gbox = cl->gbox;
		  	struct gbox_card *card;
			
			memcpy(hostname1," ",  30-sizeof(gbox->peer.hostname));

		if ((cl->ctyp == 6) && (rdr->card_status==CARD_INSERTED) &&  (cl->typ == 'p')){
		cl->card_conter_peer=0;cl->gbox_card_d1=0;
 			LL_ITER it = ll_iter_create(gbox->peer.cards);
  				while ((card = ll_iter_next(&it))) {
	fprintf(fhandle,"CardID %4d at %s%s Card %08X Sl:%2d Lev:%2d dist:%2d id:%04X\n", cart_cont, gbox->peer.hostname,hostname1,card->provid_1, card->slot, card->lvl, card->dist, card->peer_id);
if(card->dist==1)cl->gbox_card_d1++;
cl->card_conter_peer++;
cart_cont++;
}//fin ll_iter_next
////ll_iter_release(it);
gbox_card_conter_total=cart_cont;
}//fin R_GBOX
}//fin typ
}//fin cl->next
fclose(fhandle);
return;
}

void write_gbox_ver()
{
	FILE *fhandle = fopen(file_gbox_ver, "wt");
	if (fhandle==0) {
		cs_log("couldn't open %s\n",file_gbox_ver);
		return;
	}
	fprintf(fhandle,"%02X.%02X\n",gbox_hiversion,gbox_loversion);
	fclose(fhandle);
}

/*
static void gbox_handle_gsms(uint16_t peerid, char *gsms)
{
	cs_log("gbox: gsms received from peer %04x: %s", peerid, gsms);

	if (strlen(cfg.gbox_gsms_path)) {
		FILE *f = fopen(cfg.gbox_gsms_path, "a");
		if (f) {
			f//printf(f, "FROM %04X: %s\n", peerid, gsms);
			fclose(f);
		}
		else
			cs_log("gbox: error writing to file! (path=%s)", cfg.gbox_gsms_path);
	}
}
*/

static void gbox_expire_hello(struct s_client *cli)
{
   struct gbox_data *gbox = cli->gbox;
cs_sleepms(3000);
      gbox->hello_expired = 0;  gbox->peer.hello_count = 0;
}

/* static void gbox_wait_for_response(struct s_client *cli)
{
	//printf("gbox: enter gbox_wait_for_response()\n");
	//cs_debug_mask(D_READER, "gbox: enter gbox_wait_for_response()");
	struct gbox_data *gbox = cli->gbox;
	struct timespec ts;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	ts.tv_sec = tv.tv_sec;
	ts.tv_nsec = tv.tv_usec * 1000;
	ts.tv_sec += 5;

	pthread_mutex_lock (&gbox->peer_online_mutex);
	if (pthread_cond_timedwait(&gbox->peer_online_cond, &gbox->peer_online_mutex, &ts) == ETIMEDOUT) {
		gbox->peer.fail_count++;
		//printf("gbox: wait timed-out, fail_count=%d\n", gbox->peer.fail_count);
#define GBOX_FAIL_COUNT 1
		if (gbox->peer.fail_count >= GBOX_FAIL_COUNT) {
			gbox->peer.online = 0;
			//printf("gbox: fail_count >= %d, peer is offline\n", GBOX_FAIL_COUNT);
		}
		//cs_debug_mask(D_READER, "gbox: wait timed-out, fail_count=%d\n", gbox->peer.fail_count);
	} else {
		gbox->peer.fail_count = 0;
		//printf("gbox: cond posted, peer is online\n");
	}
	pthread_mutex_unlock (&gbox->peer_online_mutex);

	//cs_debug_mask(D_READER, "gbox: exit gbox_wait_for_response()");
	//printf("gbox: exit gbox_wait_for_response()\n");
} */

static void gbox_send(struct s_client *cli, uchar *buf, int32_t l)
{
  struct gbox_data *gbox = cli->gbox;

  cs_ddump_mask(D_READER, buf, l, "gbox: decrypted data send (%d bytes):", l);
//  cs_ddump_mask(D_READER, gbox->key, 4, "gbox: key before encrypt:");

  gbox_encrypt(buf, l, gbox->peer.key);
  sendto(cli->udp_fd, buf, l, 0, (struct sockaddr *)&cli->udp_sa, sizeof(cli->udp_sa));

//  cs_ddump_mask(D_READER, gbox->key, 4, "gbox: key after encrypt:");
  cs_ddump_mask(D_READER, buf, l, "gbox: encrypted data send (%d bytes):", l);

//  pthread_t t;
//  pthread_create(&t, NULL, (void *)gbox_wait_for_response, cli);
}

static void gbox_send_boxinfo(struct s_client *cli)
{
  struct gbox_data *gbox = cli->gbox;

  int32_t len;
  uchar buf[256];

  int32_t hostname_len = strlen(cfg.gbox_hostname);

  gbox_code_cmd(buf, MSG_BOXINFO);
  memcpy(buf + 2, gbox->peer.key, 4);
  memcpy(buf + 6, gbox->key, 4);
  buf[10] = gbox->peer.ver;
  buf[11] = 0x10;
  memcpy(buf + 12, cfg.gbox_hostname, hostname_len);

  len = 12 + hostname_len;

 gbox_send(cli, buf, 11);
}

static void gbox_send_goodbye(struct s_client *cli)
{
  struct gbox_data *gbox = cli->gbox;

  uchar buf[20];

  buf[0] = 0x90;
  buf[1] = 0x91;
  memcpy(buf + 2, gbox->peer.key, 4);
  memcpy(buf + 6, gbox->key, 4);
//  cs_debug_mask(D_READER, "gbox: gbox_send_boxinfo : %s", cs_hexdump(0, buf, 10, tmp, sizeof(tmp)));
  gbox_send(cli, buf, 11);
}
/* static void gbox_send_goodbye(struct s_client *cli)
{
  struct gbox_data *gbox = cli->gbox;

 uchar buf[20];

 gbox_code_cmd(buf, MSG_GOODBYE);
 memcpy(buf + 2, gbox->peer.key, 4);
 memcpy(buf + 6, gbox->key, 4);

 gbox_send(cli, buf, 11);
} */

static void gbox_send_hello(struct s_client *cli)
{
  struct gbox_data *gbox = cli->gbox;
gbox_calc_checkcode(gbox); 
  	int32_t len;	
  	int32_t index=12; 
  	int32_t nbcards=0; 
        int32_t i;
	uchar buf[2048];
	in_addr_t addr = cli->ip;
 	char card_reshare;
	int32_t ok = check_ip(cfg.http_allowed, addr) ? 1 : 0;	
	int32_t hostname_len = strlen(cfg.gbox_hostname);



  // TODO build local card list
  if (!gbox->local_cards)
    gbox->local_cards = ll_create("local_cards");
  else
    ll_clear_data(gbox->local_cards);


  int8_t slot = 0;

// send local card 
	for (i = 0; i < cfg.num_locals; i++) {
	struct gbox_card *c;
          if(!cs_malloc(&c,sizeof(struct gbox_card), -1)) continue;
	   c->provid = cfg.gbox_carte[i];
	   c->peer_id=gbox->id;c->slot = ++slot;
			if (!ok){
			c->dist = 1;
			}
			else{
			c->dist = 0;c->peer_id=gbox->peer.id+1;
			}
          ll_append(gbox->local_cards, c);
}
  // currently this will only work for initialised local cards or single remote cards
  struct s_client *cl;
  for (cl=first_client; cl; cl=cl->next) {
    struct s_reader *rdr = cl->reader;
    if (rdr) {

      if (rdr->card_status == CARD_INSERTED) {
        int32_t i;int8_t caid_ok;
        for (i = 0; i < rdr->nprov; i++) {
          struct gbox_card *c;
          if(!cs_malloc(&c,sizeof(struct gbox_card), -1)) continue;

		if(rdr->caid == 0X500){
		caid_ok = rdr->caid  >> 8;
		c->provid = caid_ok << 24 | rdr->prid[i][1] << 16 | rdr->prid[i][2] << 8 | rdr->prid[i][3];
		}else c->provid = rdr->caid << 16 | rdr->prid[i][2] << 8 | rdr->prid[i][3];
		c->peer_id=gbox->id;c->slot = ++slot;c->dist=1;
          	ll_append(gbox->local_cards, c);
        }	
		// if rdr = gbox reshar card
		if (cl->ctyp==6) {
			struct gbox_data *gbox_1 = cl->gbox;
		  	struct gbox_card *card_g;
		if (strcmp(cli->reader->label, cl->reader->label)) {
		cs_log("gbox: peer send card : %s  to: %s  ",cl->reader->label,cli->reader->label);
 			LL_ITER it = ll_iter_create(gbox_1->peer.cards);
  				while ((card_g = ll_iter_next(&it))) {
			 struct gbox_card *c;
          		 if(!cs_malloc(&c,sizeof(struct gbox_card), -1)) continue;
			c->peer_id = card_g->peer_id;
			c->slot = card_g->slot ;
			if (!ok){
			c->dist = card_g->dist;
			}
			else{
			c->dist = 1;
			}
			c->provid = card_g->provid_1;
         		ll_append(gbox->local_cards, c);
				}//fin ll_iter_nextcli->reader->label
		}
		}//fin typ
      }
    }			
  }
  gbox->peer.hello_count=0;
 if(ll_count(gbox->local_cards) ==0) goto nolocal;
  len = 22 + hostname_len + ll_count(gbox->local_cards) * 9;

  memset(buf, 0, sizeof(buf));



  gbox_code_cmd(buf, MSG_HELLO);
  memcpy(buf + 2, gbox->peer.key, 4);
  memcpy(buf + 6, gbox->key, 4);
  buf[10] = 0x00;//gbox->hello_initial ^ 1;  // initial HELLO = 0, subsequent = 1
  buf[11] = gbox->peer.hello_count;    // TODO this needs adjusting to allow for packet splitting

  uchar *ptr = buf + 11;
				if(cfg.gbox_reshare > 5)
					card_reshare=(5*0x10);
 				else
					card_reshare=(cfg.gbox_reshare*0x10);	

  LL_ITER it = ll_iter_create(gbox->local_cards);
  struct gbox_card *card;
  while ((card = ll_iter_next(&it))) {
    card->lvl=card_reshare + card->dist;
    *(++ptr) = card->provid >> 24;
    *(++ptr) = card->provid >> 16;
    *(++ptr) = card->provid >> 8;
    *(++ptr) = card->provid & 0xff;
    *(++ptr) = 1;
    *(++ptr) = card->slot;
    *(++ptr) = card->lvl;
    *(++ptr) = card->peer_id >> 8;
    *(++ptr) = card->peer_id & 0xff;nbcards++;
	if(nbcards == 100) {
  len = 22 + hostname_len + 900;
	break;}
  }

  gbox_calc_checkcode(gbox);
if (gbox->peer.hello_count==0) {
  memcpy(++ptr, gbox->checkcode, 7);
  ptr += 7;
  *ptr =gbox_loversion;
  *(++ptr) = gbox_type_dvb;
  memcpy(++ptr, cfg.gbox_hostname, hostname_len);
  *(ptr + hostname_len) = hostname_len;
}
 cs_log("gbox: send hello total cards  %d ",ll_count(gbox->local_cards));
  gbox_compress(gbox, buf, len, &len);

  cs_ddump_mask(D_READER, buf, len, "send hello, compressed (len=%d):", len);

  gbox_send(cli, buf, len);
  gbox->peer.hello_count++;



nolocal:
 //  memset(buf, 0, sizeof(buf));                         //  modif by leloup
  buf[0] = MSG_HELLO >> 8;
  buf[1] = MSG_HELLO & 0xff;
  memcpy(buf + 2, gbox->peer.key, 4);
  memcpy(buf + 6, gbox->key, 4);
  buf[10] = 0x00; 
  buf[11] = 0x80 | gbox->peer.hello_count; 
  len=index; 
if (gbox->peer.hello_count==0) {
  index=12;
  memcpy(buf + index, gbox->checkcode, 7);
  index=index+7;
  buf[index] = gbox_loversion;
  index++;
  buf[index] = gbox_type_dvb;
  index++;
  memcpy(buf + index, cfg.gbox_hostname, hostname_len);
  buf[index + hostname_len] = hostname_len;
 len=index + hostname_len + 1;
}
 //cs_log("gbox: send  hello : %s",cs_hexdump(0, buf, len, tmp, sizeof(tmp)));
  gbox_compress(gbox, buf, len, &len);	// TODO: remove _re
  gbox_send(cli, buf, len);
  gbox->peer.hello_count = 0;
}

static void * Gbox_server(struct s_client *cli, uchar *b, int32_t l)
{
  return 0;
}
static int32_t gbox_recv(struct s_client *cli, uchar *b, int32_t l)
{
  struct gbox_data *gbox = cli->gbox;
  char tmp[33];int32_t i;
  if(cfg.maxdist == 0)cfg.maxdist=3;
  if (!gbox)
	  return -1;

  uchar *data = gbox->buf;
  int32_t n;

  //pthread_mutex_lock (&gbox->peer_online_mutex);
 // gbox->peer.online = 1;
  //pthread_cond_signal(&gbox->peer_online_cond);
 // pthread_mutex_unlock (&gbox->peer_online_mutex);

  cs_writelock(&gbox->lock);

  struct sockaddr_in r_addr;
  socklen_t lenn = sizeof(struct sockaddr_in);
  if ((n = recvfrom(cli->udp_fd, data, sizeof(gbox->buf), 0, (struct sockaddr *)&r_addr, &lenn)) < 8) {
	  cs_log("gbox: invalid recvfrom!!!");
    	cs_writeunlock(&gbox->lock);
    	return -1;
  }

   cs_ddump_mask(D_READER, data, n, "gbox: encrypted data recvd (%d bytes):", n);
  cs_ddump_mask(D_READER, gbox->key, 4, "gbox: key before decrypt:");

	if ((data[0]==0x48)&&(data[1]==0x49))
	cs_log("test cs2gbox");
	else
  	gbox_decrypt(data, n, gbox->key);

  cs_ddump_mask(D_READER, gbox->key, 4, "gbox: key after decrypt:");
  cs_ddump_mask(D_READER, data, n, "gbox: decrypted data recvd (%d bytes):", n);

  memcpy(b, data, l);


 if (data[2]==gbox->key[0] && data[3]==gbox->key[1] && data[4]==gbox->key[2] && data[5]==gbox->key[3]) {
	cs_debug_mask(D_READER,"resev data peer : %04x   data: %s",gbox->peer.id,cs_hexdump(0, data, l, tmp, sizeof(tmp)));
}else  if (data[2]==gbox->peer.key[0] && data[3]==gbox->peer.key[1] && data[4]==gbox->peer.key[2] && data[5]==gbox->peer.key[3]) {
		  cs_log("gbox: INTRUDER ALERT (peer key)! %s   |  %s",cs_hexdump(0, data+6, 4, tmp, sizeof(tmp)),cs_hexdump(0, gbox->peer.key,4, tmp, sizeof(tmp)));

		   cs_add_violation_by_ip((uint)cli->ip, cli->reader->l_port, cli->account->usr);

		  cs_writeunlock(&gbox->lock);
		  return -1;
	  } else {
    cs_log("gbox: INTRUDER ALERT!");
    cs_log("resev data peer : %04x   data: %s",gbox->peer.id,cs_hexdump(0, data, n, tmp, sizeof(tmp)));
	gbox_send_boxinfo(cli);
	 return -1;
  }
//    cs_log("resev data peer : %04x   data: %s",gbox->peer.id,cs_hexdump(0, data, n, tmp, sizeof(tmp)));
  switch (gbox_decode_cmd(data)) {

    case MSG_BOXINFO:
			gbox->peer.hello_count=0;
			gbox_send_boxinfo(cli);
			break;

    case MSG_GOODBYE:

			if(gbox->peer.goodbye_cont==5){
				gbox->peer.goodbye_cont=0;
				gbox->peer.hello_count=0;
				gbox_send_hello(cli);
			
			}else
			gbox->peer.goodbye_cont++;				
			break;
    case MSG_HELLO1:
    case MSG_HELLO:
      {

	//gbox->peer.online = 1;

        int32_t payload_len = n;


	if ((data[0]==0x48)&&(data[1]==0x49)){
        cs_ddump_mask(D_READER, data, payload_len, "gbox: decompressed data (%d bytes):", payload_len);
	}else{
        gbox_decompress(gbox, data, &payload_len);
        cs_ddump_mask(D_READER, data, payload_len, "gbox: decompressed data (%d bytes):", payload_len);
	}



	int32_t ncards_in_msg = 0;

	if ((data[0x0B] == 0) | ((data[0x0A] == 1) && (data[0x0B] == 0x80))){

          if (gbox->peer.cards) ll_destroy_data(gbox->peer.cards);
          gbox->peer.cards = ll_create("peer.cards");


	}


          int32_t checkcode_len = 7;
          int32_t hostname_len = data[payload_len - 1];
          int32_t footer_len = hostname_len + 2;

			uchar *ptr =0;
			if ((data[0]==0x48)&&(data[1]==0x49))
          		ptr = data + 11;
			else
	 		ptr = data + 12;

          while (ptr < data + payload_len - footer_len - checkcode_len - 1) {

            uint16_t caid;uint32_t provid;uint32_t provid1;

		if(ptr[0]==0x05){ 
		caid = ptr[0] << 8;
		provid =  ptr[1] << 16 | ptr[2] << 8 | ptr[3];
		}
		else {
		caid = ptr[0] << 8 | ptr[1];
		provid =  0x00 << 16 | ptr[2] << 8 | ptr[3];
		}
		provid1 =  ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];

            int32_t ncards = ptr[4];


            ptr += 5;

            
            for (i = 0; i < ncards; i++) {
              struct gbox_card *card; 
	          if(!cs_malloc(&card,sizeof(struct gbox_card), -1)) continue; 

              card->caid = caid;
              card->provid = provid;
              card->provid_1 = provid1;
              card->slot = ptr[0];
              card->dist = ptr[1] & 0xf;
              card->lvl = ptr[1] >> 4;
              card->peer_id = ptr[2] << 8 | ptr[3];
              ptr += 4;

	

		if(cfg.maxdist >= card->dist){
              ll_append(gbox->peer.cards, card);
              ncards_in_msg++;
              cs_debug_mask(D_READER,"   card: caid=%04x, provid=%06x, slot=%d, level=%d, dist=%d, peer=%04x"
                , card->caid, card->provid, card->slot, card->lvl, card->dist, card->peer_id);
		}

              cli->reader->tcp_connected = 2; //we have card
        //      cli->reader->card_status = CARD_INSERTED;
            }
          }


	if ((data[0x0B] == 0) | (data[0x0B] == 0X80)) {
	  NULLFREE(gbox->peer.hostname);

		if(!cs_malloc(&gbox->peer.hostname,hostname_len + 1, -1)){ 
 	              cs_writeunlock(&gbox->lock);
 	                return -1;
 	          } 



          memcpy(gbox->peer.hostname, data + payload_len - 1 - hostname_len, hostname_len);
          gbox->peer.hostname[hostname_len] = '\0';

          memcpy(gbox->peer.checkcode, data + payload_len - footer_len - checkcode_len - 1, checkcode_len);
          gbox->peer.ver = data[payload_len - footer_len - 1];
	  cli->gbox_ver = data[payload_len - footer_len - 1];
          gbox->peer.type = data[payload_len - footer_len];

	}



		if (data[0x0B]&0x80){
			if (!data[0x0A]){ 
				gbox->peer.hello_count = 0;
				gbox_send_hello(cli);
			}

		if(gbox->hello_expired < 3){
			gbox->hello_expired++;
			gbox_send_hello(cli);
		}
		else { 
			gbox_expire_hello(cli);	
			gbox->peer.hello_cont_2=1;
			cli->ctyp = 6;
			gbox->peer.online = 1;
            for (i = 1; i < 6; i++) 
		 cli->grp|=(((uint64_t)1)<<(i-1));
		

                cli->reader->tcp_connected = 2; //we have card
                cli->reader->card_status = CARD_INSERTED;write_share_info();
		 }
		}
					
        
      }
	 	     
      break;
    case MSG_CW:
 		memcpy(gbox->cws, data + 14, 16);
    	break;
    case MSG_CHECKCODE:
    	memcpy(gbox->peer.checkcode, data + 10, 7);
        cs_debug_mask(D_READER, "gbox: received checkcode=%s",  cs_hexdump(0, gbox->peer.checkcode, 7, tmp, sizeof(tmp)));
    		gbox->peer.hello_cont_2=0;
	break;
    /*case MSG_GSMS: // TODO
    	//gbox_handle_gsms(peerid, gsms);
    	break;
    	*/
    case MSG_ECM: //TODO:
    { if(gbox->peer.hello_cont_2==0) break;
      // TODO: This is !!DIRTY!!
    //  cli->typ = 'c';
      cli->ctyp = 6;

   /*   struct s_auth *account;
      int32_t ok=0;
      for (ok=0, account=cfg.account; (account) && (!ok); account=account->next)
        if( (ok=!strcmp(cli->reader->r_usr, account->usr)) )
          break;
      cs_auth_client(cli, ok ? account : (struct s_auth *)(-1), "gbox");*/
      //Gbox_server(cli, b, l);
      ECM_REQUEST *er;


	 if (!(er=get_ecmtask())){ 
	gbox_send_goodbye(cli);
	break;
  	}

      struct gbox_ecm_info *ei;
      if(!cs_malloc(&ei,sizeof(struct gbox_ecm_info), -1)){
      	cs_writeunlock(&gbox->lock);
      	return -1;
      }
      er->src_data = ei;
      uchar *ecm = data + 18;

      er->idx = gbox->peer.ecm_idx++;
      er->l = ecm[2] + 3;
      er->pid = data[10] << 8 | data[11];
      er->srvid = data[12] << 8 | data[13];
      int32_t adr_caid_1 =data[20] + 26;
  if(data[adr_caid_1] == 0x05)
      er->caid = (data[adr_caid_1]<<8);
  else
      er->caid = (data[adr_caid_1]<<8 | data[adr_caid_1+1]);
      ei->caid = (data[adr_caid_1]<<8 | data[adr_caid_1+1]);
      ei->extra = data[14] << 8 | data[15];
      memcpy(er->ecm, data + 18, er->l);

      er->prid = ecm[er->l + 7] << 8 | ecm[er->l + 8];
      ei->ncards = data[16];
      ei->peer_cw = data[data[0x14]+0x1F] << 8 | data[data[0x14]+0x20];
      ei->peer = ecm[er->l] << 8 | ecm[er->l + 1];
      ei->version = ecm[er->l + 2];
      ei->type = ecm[er->l + 4];
      ei->slot = ecm[er->l + 12];
      ei->unknwn1 = ecm[er->l + 3];
      ei->unknwn2 = ecm[er->l + 13];
      memcpy(ei->checksums, ecm + er->l + 14, 14);

      cs_log("gbox: ecm received, caid=%04x. provid=%x, sid=%04x, len=%d, peer=%04x, ei->peer_cw=%04x,ei->extra=%04x", er->caid, er->prid, er->srvid, er->l, ei->peer,ei->peer_cw,ei->extra);

      get_cw(cli, er);      cli->typ = 'p';
    }
      break;
    default:
      cs_ddump_mask(D_READER, data, n, "gbox: unknown data received (%d bytes):", n);
  }
  cs_writeunlock(&gbox->lock);

  return 0;
}

static void gbox_send_dcw(struct s_client *cli, ECM_REQUEST *er)
{
  struct gbox_data *gbox = cli->gbox;

  if( er->rc >= E_NOTFOUND ) {
    cs_log("gbox: unable to decode!");
    //TODO: send something better back??
    //gbox_send_goodbye(cli);
    return;
  }

  uchar buf[50];
  uint32_t crc = gbox_get_ecmchecksum(er);
  struct gbox_ecm_info *ei =  er->src_data;

  memset(buf, 0, sizeof(buf));

  gbox_code_cmd(buf, MSG_CW);
  memcpy(buf + 2, gbox->peer.key, 4);
  buf[6] = er->pid;
  buf[7] = er->pid;
  buf[8] = er->srvid >> 8;
  buf[9] = er->srvid & 0xff;
  buf[10] = ei->peer_cw >> 8;
  buf[11] = ei->peer_cw & 0xff;
  buf[12] = 0x10 | (er->ecm[0] & 1);
  buf[13] = er->caid >> 8;
  memcpy(buf + 14, er->cw, 16);
  buf[30] = crc >> 24;
  buf[31] = crc >> 16;
  buf[32] = crc >> 8;
  buf[33] = crc & 0xff;

  buf[34] = ei->caid >> 8;
  buf[35] = ei->caid & 0xff;

  buf[36] = ei->ncards;
  buf[37] = ei->extra >> 8;
  buf[38] = ei->extra & 0xff;
  buf[39] = ei->peer >> 8;
  buf[40] = ei->peer;
  buf[41] = ei->slot;
  buf[42] = 0x21;
  buf[43] = ei->unknwn1;
cs_log("Gbox sending cw caid %04x   for id : %04x   peer : %s",ei->caid,ei->peer ,cli->reader->label);
  gbox_send(cli, buf, 45);
}
static void Gbox_server_init(struct s_client * client) {
	client->is_udp = (ph[client->ctyp].type == MOD_CONN_UDP);
}
static int32_t gbox_client_init(struct s_client *cli)
{
	if (!strlen(cfg.gbox_hostname)) {
		cs_log("gbox: error, no hostname configured in oscam.conf!");
		return -1;
	}

	if (strlen(cli->reader->l_pwd) != 8) {
		cs_log("gbox: error, no/invalid password '%s' configured in oscam.conf!", cli->reader->l_pwd);
		return -1;
	}

	if (cli->reader->l_port < 1) {
		cs_log("gbox: no/invalid port configured in oscam.conf!");
		return -1;
	}
	if(!cs_malloc(&cli->gbox,sizeof(struct gbox_data), -1)) return -1;

  struct gbox_data *gbox = cli->gbox;
  struct s_reader *rdr = cli->reader;

  rdr->card_status = CARD_FAILURE;
  rdr->tcp_connected = 0;

  memset(gbox, 0, sizeof(struct gbox_data));
  memset(&gbox->peer, 0, sizeof(struct gbox_peer));

  pthread_mutex_init(&gbox->peer_online_mutex, NULL);
  pthread_cond_init(&gbox->peer_online_cond, NULL);

  uint32_t r_pwd = a2i(rdr->r_pwd, 4);
  uint32_t key = a2i(cli->reader->l_pwd, 4);
  int32_t i;
  for (i = 3; i >= 0; i--) {
	  gbox->peer.key[3 - i] = (r_pwd >> (8 * i)) & 0xff;
	  gbox->key[3 - i] = (key >> (8 * i)) & 0xff;
  }

  cs_ddump_mask(D_READER, gbox->peer.key, 4, "r_pwd: %s:", rdr->r_pwd);
  cs_ddump_mask(D_READER, gbox->key, 4, "cfg.gbox_key: %s:", cli->reader->l_pwd);

  gbox->peer.id = (gbox->peer.key[0] ^ gbox->peer.key[2]) << 8 | (gbox->peer.key[1] ^ gbox->peer.key[3]);

 cli->peer_id[0] = gbox->peer.id >> 8;
 cli->peer_id[1] = gbox->peer.id & 0xff;
  gbox->id = (gbox->key[0] ^ gbox->key[2]) << 8 | (gbox->key[1] ^ gbox->key[3]);
  gbox->ver = gbox_loversion;
  gbox->type = gbox_type_dvb;

  struct sockaddr_in loc_sa;
  cli->pfd=0;
  cli->is_udp = 1;
	cli->ip=0;
	memset((char *)&loc_sa,0,sizeof(loc_sa));
	loc_sa.sin_family = AF_INET;
  loc_sa.sin_addr.s_addr = INADDR_ANY;
  loc_sa.sin_port = htons(rdr->l_port);

  if ((cli->udp_fd=socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP))<0)
   {
        cs_log("socket creation failed (errno=%d %s)", errno, strerror(errno));
        cs_disconnect_client(cli);
  }

  int32_t opt = 1;
  setsockopt(cli->udp_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof (opt));

#ifdef SO_PRIORITY
  if (cfg.netprio)
    setsockopt(cli->udp_fd, SOL_SOCKET, SO_PRIORITY, (void *)&cfg.netprio, sizeof(uintptr_t));
#endif

  if (rdr->l_port>0)
  {
    if (bind(cli->udp_fd, (struct sockaddr *)&loc_sa, sizeof (loc_sa))<0)
    {
      cs_log("bind failed (port=%d, errno=%d %s)", rdr->l_port, errno, strerror(errno));
      close(cli->udp_fd);
        return 1;
    }
  }

  memset((char *)&cli->udp_sa, 0, sizeof(cli->udp_sa));

  if (!hostResolve(rdr))
  	return 1;

  cli->udp_sa.sin_family=AF_INET;
  cli->udp_sa.sin_port=htons((uint16_t)rdr->r_port);

  cs_log("proxy %s:%d (fd=%d, peer id=%04x, my id=%04x, my hostname=%s, listen port=%d)",
    rdr->device, rdr->r_port, cli->udp_fd, gbox->peer.id, gbox->id, cfg.gbox_hostname, rdr->l_port);

    cli->pfd=cli->udp_fd;

  cs_lock_create(&gbox->lock, 5, "gbox_lock");
  gbox->peer.hello_cont_2=0;
  gbox->hello_expired = 0;
  gbox->hello_initial = 1;
  gbox->peer.hello_cont_1=0;
  gbox->peer.online=0;
  gbox->peer.ecm_idx=0;
  gbox_send_hello(cli);

  return 0;
}

static int32_t gbox_recv_chk(struct s_client *cli, uchar *dcw, int32_t *rc, uchar *data, int32_t UNUSED(n))
{
  //struct gbox_data *gbox = cli->gbox;
  char tmp[512];
  if (gbox_decode_cmd(data) == MSG_CW) {
	int i, n;
	*rc = 1;
	memcpy(dcw, data + 14, 16);
	uint32_t crc = data[30] << 24 | data[31] << 16 | data[32] << 8 | data[33];

		cs_log("gbox: received cws=%s, peer=%04x, ecm_pid=%d, sid=%d, crc=%08x",
		cs_hexdump(0, dcw, 16, tmp, sizeof(tmp)), data[10] << 8 | data[11], data[6] << 8 | data[7], data[8] << 8 | data[9], crc);

		for (i=0, n=0; i<CS_MAXPENDING && n == 0; i++) {
			if (cli->ecmtask[i].gbox_crc==crc) {
			        return cli->ecmtask[i].idx;
			}
		}
		cs_debug_mask(D_READER, "gbox: no task found for crc=%08x",crc);
  }

  return -1;
}

static int32_t gbox_send_ecm(struct s_client *cli, ECM_REQUEST *er, uchar *UNUSED(buf))
{
  struct gbox_data *gbox = cli->gbox;
int32_t cont_1;
	if (!gbox || !cli->reader->tcp_connected) {
		cs_debug_mask(D_READER, "gbox: %s server not init!", cli->reader->label);
		write_ecm_answer(cli->reader, er, E_NOTFOUND, 0x27, NULL, NULL);
		return 0;
	}

	if (!ll_count(gbox->peer.cards)) {
		cs_debug_mask(D_READER, "gbox: %s NO CARDS!", cli->reader->label);
		write_ecm_answer(cli->reader, er, E_NOTFOUND, 0x27, NULL, NULL);
		return 0;
	}

	if (gbox->peer.online==0) {
		cs_debug_mask(D_READER, "gbox: peer is OFFLINE!");
		write_ecm_answer(cli->reader, er, E_NOTFOUND, 0x27, NULL, NULL);
		  gbox_send_hello(cli);
		return 0;
	}

  uint16_t ercaid = er->caid;
  uint32_t erprid = er->prid;
if(cfg.maxecmsend == 0)cfg.maxecmsend=3;
  /* TODO: gbox encodes provids differently for several providers, hardcode some sort of mangle table in here? */
  switch (ercaid >> 8) {
	// cryptoworks
	case 0x0d:
		erprid = erprid << 8;
		break;
  }

  uchar send_buf[0x2048];
uchar send_buf_1[0x1024];
  int32_t len, len2;

  if (!er->l) return 0;

  len = er->l + 18;
  len2 = er->l + 18;
  er->gbox_crc = gbox_get_ecmchecksum(er);

  memset(send_buf, 0, sizeof(send_buf));

  LL_ITER it = ll_iter_create(gbox->peer.cards);
  struct gbox_card *card;
int32_t cont_send = 0;
int32_t cont_card_1 = 0;



  send_buf_1[0] = MSG_ECM >> 8;
  send_buf_1[1] = MSG_ECM & 0xff;
  memcpy(send_buf_1 + 2, gbox->peer.key, 4);
  memcpy(send_buf_1 + 6, gbox->key, 4);
  if(er->pid==0){
  send_buf_1[10] = 0x00;//er->pid >> 8;
  send_buf_1[11] = 0x00;//er->pid;
}else{
  send_buf_1[10] = er->pid >> 8;
  send_buf_1[11] = er->pid;
}
  send_buf_1[12] = er->srvid >> 8;
  send_buf_1[13] = er->srvid;
  send_buf_1[14] = 0x00;
  send_buf_1[15] = 0x00;

  send_buf_1[16] = cont_card_1;
  send_buf_1[17] = 0x00;

  memcpy(send_buf_1 + 18, er->ecm, er->l);

  send_buf_1[len2] = gbox->id >> 8;
  send_buf_1[len2+1] = gbox->id;
  send_buf_1[len2+2] = gbox_loversion;
  send_buf_1[len2+3] = 0x00;
  send_buf_1[len2+4] = gbox_type_dvb;

  send_buf_1[len2+5] = er->caid >> 8;
  if(send_buf_1[len2+5] == 0x05)
  send_buf_1[len2+6] = er->prid >> 16;
  else
  send_buf_1[len2+6] = er->caid & 0xFF;

  send_buf_1[len2+7] = 0x00;
  send_buf_1[len2+8] = 0x00;
  send_buf_1[len2+9] = 0x00;
  cont_1 =len2+10;


while ((card = ll_iter_next(&it))) {

if (card->caid == er->caid && card->provid == er->prid) {
      send_buf_1[cont_1] = card->peer_id >> 8;
      send_buf_1[cont_1+1] = card->peer_id;
      send_buf_1[cont_1+2] = card->slot;
	cont_1=cont_1+3;cont_card_1++;
cont_send++;
if(cont_send == cfg.maxecmsend)break;
 }

}			


  //ll_iter_release(it);
  //    send_buf_1[cont_1] = 0x01;++cont_1;
if(cont_card_1 == 0)  return 0;
    send_buf_1[16] = cont_card_1;

      memcpy(&send_buf_1[cont_1], gbox->checkcode, 7);
	cont_1=cont_1+7;
      memcpy(&send_buf_1[cont_1], gbox->peer.checkcode, 7);
    cont_1=cont_1+7;

 //
 cs_log("Gbox sending ecm for %06x : %s",er->prid ,cli->reader->label);
//cs_debug_mask(D_READER,"gbox: peer id %04x Gbox sending ecm for %06x account->usr : %s  ip: %s  port: %d ",gbox->peer.id,er->prid,cli->account->usr,cs_inet_ntoa(cli->ip),cli->port);

++cont_1;
  gbox_send(cli, send_buf_1, cont_1);
  
 memset(send_buf_1, 0, sizeof(send_buf_1));
		
  return 0;
}

static int32_t gbox_send_emm(EMM_PACKET *UNUSED(ep))
{
  // emms not yet supported

  return 0;
}

void module_gbox(struct s_module *ph)
{
  cs_strncpy(ph->desc, "gbox", sizeof(ph->desc));
  ph->num=R_GBOX;
  ph->type=MOD_CONN_UDP;
  ph->listenertype = LIS_GBOX;
  ph->logtxt = ", crypted";

  ph->s_ip=cfg.cc_srvip;
  ph->s_handler=Gbox_server;
  ph->s_init=Gbox_server_init;


  ph->multi=1;
  ph->send_dcw=gbox_send_dcw;

  ph->recv=gbox_recv;
  ph->c_multi=1;
  ph->c_init=gbox_client_init;
  ph->c_recv_chk=gbox_recv_chk;
  ph->c_send_ecm=gbox_send_ecm;
  ph->c_send_emm=gbox_send_emm;
}
#endif

