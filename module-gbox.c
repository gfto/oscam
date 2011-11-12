#include "globals.h"
#ifdef MODULE_GBOX
#include <pthread.h>
//#define _XOPEN_SOURCE 600
#include <time.h>
#include <sys/time.h>

#include "module-datastruct-llist.h"
#include "algo/minilzo.h"

enum {
  MSG_ECM = 0x445c,
  MSG_CW = 0x4844,
  MSG_HELLO = 0xddab,
  MSG_CHECKCODE = 0x41c0,
  MSG_GOODBYE = 0x9091,
  MSG_GSMS_ACK = 0x9098,
  MSG_GSMS = 0xff0,
  MSG_BOXINFO = 0xa0a1
};

struct gbox_card {
  uint16_t peer_id;
  uint32_t provid;
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
           extra;
  uchar version,
        type,
        slot,
        unknwn1,
        unknwn2,
        ncards;
  uchar checksums[14];
};

#pragma GCC diagnostic ignored "-Wunused-parameter" 

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

static void gbox_compress(struct gbox_data *gbox, uchar *buf, int32_t unpacked_len, int32_t *packed_len)
{
  unsigned char *tmp, *tmp2;
  *packed_len = 0;
  if(!cs_malloc(&tmp,0x40000, -1)) return;
 	if(!cs_malloc(&tmp2,0x40000, -1)){
 		free(tmp);
 		return;
 	}

  unpacked_len -= 12;
  memcpy(tmp2, buf + 12, unpacked_len);

  lzo_init();

  char work[16384];
  lzo_voidp wrkmem = &work;
  if(!cs_malloc(&tmp2,unpacked_len * 0x1000, -1)){
 		free(tmp);
 		free(tmp2);
 		return;
 	}
  cs_debug_mask(D_READER, "gbox: wrkmem = %p", wrkmem);
  lzo_uint pl = 0;
  if (lzo1x_1_compress(tmp2, unpacked_len, tmp, &pl, wrkmem) != LZO_E_OK)
    cs_log("gbox: compression failed!");

  memcpy(buf + 12, tmp, pl);
  pl += 12;

  free(tmp);
  free(tmp2);

  *packed_len = pl;
}

static void gbox_decompress(struct gbox_data *gbox, uchar *buf, int32_t *unpacked_len)
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
  memcpy(gbox->checkcode, "\x15\x30\x2\x4\x19\x19\x66", 7); /* no local cards */

  int32_t slot = 0;

  // for all local cards do:
  LL_ITER it = ll_iter_create(gbox->local_cards);
  struct gbox_card *card;
  while ((card = ll_iter_next(&it))) {
    gbox->checkcode[0] ^= card->provid >> 24;
    gbox->checkcode[1] ^= card->provid >> 16;
    gbox->checkcode[2] ^= card->provid >> 8;
    gbox->checkcode[3] ^= card->provid & 0xff;
    gbox->checkcode[4] = ++slot;
    gbox->checkcode[5] = gbox->peer.id >> 8;
    gbox->checkcode[6] = gbox->peer.id & 0xff;
  }
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
  //printf("gbox: enter gbox_expire_hello()\n");
  struct gbox_data *gbox = cli->gbox;

  pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;
  pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

  struct timespec ts;
  struct timeval tv;
  gettimeofday(&tv, NULL);
  ts.tv_sec = tv.tv_sec;
  ts.tv_nsec = tv.tv_usec * 1000;
  ts.tv_sec += 5;

  pthread_mutex_lock (&mut);
  if (pthread_cond_timedwait(&cond, &mut, &ts) == ETIMEDOUT) {
    //printf("gbox: hello expired!\n");
    gbox->hello_expired = 0;
  }
  pthread_mutex_unlock (&mut);
  //printf("gbox: exit gbox_expire_hello()\n");
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

  // TODO build local card list
  if (!gbox->local_cards)
    gbox->local_cards = ll_create("local_cards");
  else
    ll_clear_data(gbox->local_cards);

  // currently this will only work for initialised local cards or single remote cards
  struct s_client *cl;
  for (cl=first_client; cl; cl=cl->next) {
    struct s_reader *rdr = cl->reader;
    if (rdr) {
      if (rdr->card_status == CARD_INSERTED) {
        int32_t i;
        for (i = 0; i < rdr->nprov; i++) {
          struct gbox_card *c;
          if(!cs_malloc(&c,sizeof(struct gbox_card), -1)) continue;
          c->provid = rdr->caid << 16 | rdr->prid[i][0] << 8 | rdr->prid[i][1];
          ll_append(gbox->local_cards, c);
        }
      }
    }
  }

  int32_t len;
  uchar buf[4096];

  int32_t hostname_len = strlen(cfg.gbox_hostname);

  len = 22 + hostname_len + ll_count(gbox->local_cards) * 9;

  memset(buf, 0, sizeof(buf));

  gbox_code_cmd(buf, MSG_HELLO);
  memcpy(buf + 2, gbox->peer.key, 4);
  memcpy(buf + 6, gbox->key, 4);
  buf[10] = gbox->hello_initial ^ 1;  // initial HELLO = 0, subsequent = 1
  buf[11] = 0x80;    // TODO this needs adjusting to allow for packet splitting

  uchar *ptr = buf + 11;

  int8_t slot = 0;
  LL_ITER it = ll_iter_create(gbox->local_cards);
  struct gbox_card *card;
  while ((card = ll_iter_next(&it))) {
    card->slot = ++slot;
    *(++ptr) = card->provid >> 24;
    *(++ptr) = card->provid >> 16;
    *(++ptr) = card->provid >> 8;
    *(++ptr) = card->provid & 0xff;
    *(++ptr) = 1;
    *(++ptr) = card->slot;
    *(++ptr) = 0x41;  // TODO card->lvl << 4 | card->dist & 0xf
    *(++ptr) = gbox->id >> 8;
    *(++ptr) = gbox->id & 0xff;
  }

  gbox_calc_checkcode(gbox);
  memcpy(++ptr, gbox->checkcode, 7);
  ptr += 7;
  *ptr = 0x73;
  *(++ptr) = 0x10;
  memcpy(++ptr, cfg.gbox_hostname, hostname_len);
  *(ptr + hostname_len) = hostname_len;

  cs_ddump_mask(D_READER, buf, len, "send hello (len=%d):", len);

  gbox_compress(gbox, buf, len, &len);

  cs_ddump_mask(D_READER, buf, len, "send hello, compressed (len=%d):", len);

  if (++gbox->peer.hello_count == 2) gbox->peer.hello_count = 0;
  gbox->hello_initial = 0;

  gbox_send(cli, buf, len);
}

static int32_t gbox_recv(struct s_client *cli, uchar *b, int32_t l)
{
  struct gbox_data *gbox = cli->gbox;
  char tmp[33];

  if (!gbox)
	  return -1;

  uchar *data = gbox->buf;
  int32_t n;

  pthread_mutex_lock (&gbox->peer_online_mutex);
  gbox->peer.online = 1;
  pthread_cond_signal(&gbox->peer_online_cond);
  pthread_mutex_unlock (&gbox->peer_online_mutex);

  cs_writelock(&gbox->lock);

  struct sockaddr_in r_addr;
  socklen_t lenn = sizeof(struct sockaddr_in);
  if ((n = recvfrom(cli->udp_fd, data, sizeof(gbox->buf), 0, (struct sockaddr *)&r_addr, &lenn)) < 8) {
	  cs_log("gbox: invalid recvfrom!!!");
    	cs_writeunlock(&gbox->lock);
    	return -1;
  }

  cs_ddump_mask(D_READER, data, n, "gbox: encrypted data recvd (%d bytes):", n);
 // cs_ddump_mask(D_READER, gbox->key, 4, "gbox: key before decrypt:");

  gbox_decrypt(data, n, gbox->key);

//  cs_ddump_mask(D_READER, gbox->key, 4, "gbox: key after decrypt:");
  cs_ddump_mask(D_READER, data, n, "gbox: decrypted data recvd (%d bytes):", n);

  memcpy(b, data, l);

  if (!memcmp(data + 2, gbox->key, 4)) {
	  if (memcmp(data + 6, gbox->peer.key, 4) && gbox_decode_cmd(data) != MSG_CW) {
		  cs_log("gbox: INTRUDER ALERT (peer key)!");

		  cs_add_violation_by_ip((uint)cli->ip, cfg.gbox_port, cli->account->usr);

		  cs_writeunlock(&gbox->lock);
		  return -1;
	  }
  } else {
    cs_log("gbox: INTRUDER ALERT!");

    cs_add_violation_by_ip((uint)cli->ip, cfg.gbox_port, cli->account->usr);

    cs_writeunlock(&gbox->lock);
	  return -1;
  }

  switch (gbox_decode_cmd(data)) {
    case MSG_HELLO:
      {
        int32_t ip_clien_gbox = cs_inet_addr(cli->reader->device);
        cli->ip = ip_clien_gbox;
	if (!gbox->peer.online) {
	  gbox_send_boxinfo(cli);
	}
        gbox->peer.online = 1;

        int32_t payload_len = n;

        gbox_decompress(gbox, data, &payload_len);
        cs_ddump_mask(D_READER, data, payload_len, "gbox: decompressed data (%d bytes):", payload_len);

        if (!data[10]) {
	  gbox->exp_seq = 0;
          gbox->hello_expired = 1;
        }

        int32_t seqno = data[11] & 0x7f;
        int32_t final = data[11] & 0x80;

        int32_t ncards_in_msg = 0;

        if (seqno != gbox->exp_seq) return -1;

        int32_t orig_card_count = ll_count(gbox->peer.cards);

        if (seqno == 0) {

          gbox->exp_seq++;

          if (gbox->peer.cards) ll_destroy_data(gbox->peer.cards);
          gbox->peer.cards = ll_create("peer.cards");

          int32_t checkcode_len = 7;
          int32_t hostname_len = data[payload_len - 1];
          int32_t footer_len = hostname_len + 2;

          // add cards to card list
          uchar *ptr = data + 12;
          while (ptr < data + payload_len - footer_len - checkcode_len - 1) {
            uint32_t provid = ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];
            int32_t ncards = ptr[4];

            ptr += 5;

            int32_t i;
            for (i = 0; i < ncards; i++) {
              struct gbox_card *card;
              if(!cs_malloc(&card,sizeof(struct gbox_card), -1)) continue;

              card->provid = provid;
              card->slot = ptr[0];
              card->dist = ptr[1] & 0xf;
              card->lvl = ptr[1] >> 4;
              card->peer_id = ptr[2] << 8 | ptr[3];

              ptr += 4;

              ll_append(gbox->peer.cards, card);

              ncards_in_msg++;

              cs_debug_mask(D_READER, "   card: provid=%08x, slot=%d, level=%d, dist=%d, peer=%04x", card->provid, card->slot, card->lvl, card->dist, card->peer_id);

              cli->reader->tcp_connected = 2; //we have card
              cli->reader->card_status = CARD_INSERTED;
            }
          }

          NULLFREE(gbox->peer.hostname);
          if(!cs_malloc(&gbox->peer.hostname,hostname_len + 1, -1)){
          	cs_writeunlock(&gbox->lock);
          	return -1;
          }
          memcpy(gbox->peer.hostname, data + payload_len - 1 - hostname_len, hostname_len);
          gbox->peer.hostname[hostname_len] = '\0';
	  cs_debug_mask(D_READER, "    peer hostname: %s", gbox->peer.hostname);

          memcpy(gbox->peer.checkcode, data + payload_len - footer_len - checkcode_len - 1, checkcode_len);
          gbox->peer.ver = data[payload_len - footer_len - 1];
          gbox->peer.type = data[payload_len - footer_len];
        } else {
          // add cards to card list
          uchar *ptr = data + 12;
          while (ptr < data + payload_len - 1) {
            uint32_t provid = ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];
            int32_t ncards = ptr[4];

            ptr += 5;

            int32_t i;
            for (i = 0; i < ncards; i++) {
              struct gbox_card *card;
              if(!cs_malloc(&card,sizeof(struct gbox_card), -1)) continue;

              card->provid = provid;
              card->slot = ptr[0];
              card->dist = ptr[1] & 0xf;
              card->lvl = ptr[1] >> 4;
              card->peer_id = ptr[2] << 8 | ptr[3];

              ptr += 4;

              ll_append(gbox->peer.cards, card);

              ncards_in_msg++;

              cs_debug_mask(D_READER, "   card: provid=%08x, slot=%d, level=%d, dist=%d, peer=%04x", card->provid, card->slot, card->lvl, card->dist, card->peer_id);
            }
          }
        }

        if (final) gbox->exp_seq = 0;
        // write_sahre_info() // TODO

        cs_log("gbox: received hello %d%s, %d providers from %s, version=2.%02X, checkcode=%s",
        		seqno, final ? " (final)" : "", ncards_in_msg, gbox->peer.hostname, gbox->peer.ver, cs_hexdump(0, gbox->peer.checkcode, 7, tmp, sizeof(tmp)));

        if (!ll_count(gbox->peer.cards))
        	  cli->reader->tcp_connected = 1;

        if (orig_card_count != ll_count(gbox->peer.cards))
          gbox->hello_expired = 1;

        if (final) {
          if (gbox->hello_expired) {
            gbox->hello_expired = 0;
            gbox_send_hello(cli);

            pthread_t t;
            pthread_create(&t, NULL, (void *)gbox_expire_hello, cli);
          }
        }
      }
      break;
    case MSG_BOXINFO:
      gbox_send_hello(cli);
      break;
    case MSG_CW:
    	break;
    case MSG_CHECKCODE:
    	memcpy(gbox->peer.checkcode, data + 10, 7);
        cs_debug_mask(D_READER, "gbox: received checkcode=%s",  cs_hexdump(0, gbox->peer.checkcode, 7, tmp, sizeof(tmp)));
    	break;
    /*case MSG_GSMS: // TODO
    	//gbox_handle_gsms(peerid, gsms);
    	break;
    	*/
    case MSG_ECM: //TODO:
    {
      // TODO: This is !!DIRTY!!
      cli->typ = 'c';
      cli->ctyp = 6;

      struct s_auth *account;
      int32_t ok=0;
      for (ok=0, account=cfg.account; (account) && (!ok); account=account->next)
        if( (ok=!strcmp(cli->reader->r_usr, account->usr)) )
          break;
      cs_auth_client(cli, ok ? account : (struct s_auth *)(-1), "gbox");

      ECM_REQUEST *er = get_ecmtask();

      struct gbox_ecm_info *ei;
      if(!cs_malloc(&ei,sizeof(struct gbox_ecm_info), -1)){
      	cs_writeunlock(&gbox->lock);
      	return -1;
      }
      er->src_data = ei;

      cli->typ = 'r';

      static uchar ecm_idx = 0;
      uchar *ecm = data + 18;

      er->idx = ++ecm_idx;
      er->l = ecm[2] + 3;
      er->pid = data[10] << 8 | data[11];
      er->srvid = data[12] << 8 | data[13];
      ei->extra = data[14] << 8 | data[15];
      memcpy(er->ecm, data + 18, er->l);

      ei->ncards = data[16];

      ei->peer = ecm[er->l] << 8 | ecm[er->l + 1];
      ei->version = ecm[er->l + 2];
      ei->type = ecm[er->l + 4];
      er->caid = ecm[er->l + 5] << 8 | ecm[er->l + 6];
      er->prid = ecm[er->l + 7] << 8 | ecm[er->l + 8];
      ei->slot = ecm[er->l + 12];
      ei->unknwn1 = ecm[er->l + 3];
      ei->unknwn2 = ecm[er->l + 13];
      memcpy(ei->checksums, ecm + er->l + 14, 14);

      cs_log("gbox: ecm received, caid=%04x. provid=%x, sid=%04x, len=%d, peer=%04x", er->caid, er->prid, er->srvid, er->l, ei->peer);
      get_cw(cli, er);
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

  uchar buf[45];
  uint32_t crc = gbox_get_ecmchecksum(er);
  struct gbox_ecm_info *ei =  er->src_data;

  memset(buf, 0, sizeof(buf));

  gbox_code_cmd(buf, MSG_CW);
  memcpy(buf + 2, gbox->peer.key, 4);
  buf[6] = er->pid;
  buf[7] = er->pid;
  buf[8] = er->srvid >> 8;
  buf[9] = er->srvid & 0xff;
  buf[10] = gbox->id >> 8;
  buf[11] = gbox->id & 0xff;
  buf[12] = 0x10 | (er->ecm[0] & 1);
  buf[13] = er->caid >> 8;
  memcpy(buf + 14, er->cw, 16);
  buf[30] = crc >> 24;
  buf[31] = crc >> 16;
  buf[32] = crc >> 8;
  buf[33] = crc & 0xff;
  buf[34] = er->caid >> 8;
  buf[35] = er->caid & 0xff;
  buf[36] = ei->ncards;
  buf[37] = ei->extra >> 8;
  buf[38] = ei->extra & 0xff;
  buf[39] = ei->peer;
  buf[40] = ei->peer;
  buf[41] = er->pid >> 8;
  buf[42] = er->pid & 0xff;
  buf[43] = ei->unknwn1;

  gbox_send(cli, buf, 45);
}

static int32_t gbox_client_init(struct s_client *cli)
{
	if (!strlen(cfg.gbox_hostname)) {
		cs_log("gbox: error, no hostname configured in oscam.conf!");
		return -1;
	}

	if (strlen(cfg.gbox_key) != 8) {
		cs_log("gbox: error, no/invalid password '%s' configured in oscam.conf!", cfg.gbox_key);
		return -1;
	}

	if (cfg.gbox_port < 1) {
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
  uint32_t key = a2i(cfg.gbox_key, 4);
  int32_t i;
  for (i = 3; i >= 0; i--) {
	  gbox->peer.key[3 - i] = (r_pwd >> (8 * i)) & 0xff;
	  gbox->key[3 - i] = (key >> (8 * i)) & 0xff;
  }

  cs_ddump_mask(D_READER, gbox->peer.key, 4, "r_pwd: %s:", rdr->r_pwd);
  cs_ddump_mask(D_READER, gbox->key, 4, "cfg.gbox_key: %s:", cfg.gbox_key);

  gbox->peer.id = (gbox->peer.key[0] ^ gbox->peer.key[2]) << 8 | (gbox->peer.key[1] ^ gbox->peer.key[3]);
  gbox->id = (gbox->key[0] ^ gbox->key[2]) << 8 | (gbox->key[1] ^ gbox->key[3]);
  gbox->ver = 0x99;
  gbox->type = 0x32;

  struct sockaddr_in loc_sa;
  cli->pfd=0;
  cli->is_udp = 1;
	cli->ip=0;
	memset((char *)&loc_sa,0,sizeof(loc_sa));
	loc_sa.sin_family = AF_INET;
  loc_sa.sin_addr.s_addr = INADDR_ANY;
  loc_sa.sin_port = htons(cfg.gbox_port);

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

  if (cfg.gbox_port>0)
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
    rdr->device, rdr->r_port, cli->udp_fd, gbox->peer.id, gbox->id, cfg.gbox_hostname, cfg.gbox_port);

    cli->pfd=cli->udp_fd;

  cs_lock_create(&gbox->lock, 5, "gbox_lock");

  gbox->hello_expired = 1;
  gbox->hello_initial = 1;

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

		cs_debug_mask(D_READER, "gbox: received cws=%s, peer=%04x, ecm_pid=%d, sid=%d, crc=%08x",
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

static int32_t gbox_send_ecm(struct s_client *cli, ECM_REQUEST *er, uchar *buf)
{
  struct gbox_data *gbox = cli->gbox;

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

	if (!gbox->peer.online) {
		cs_debug_mask(D_READER, "gbox: peer is OFFLINE!");
		write_ecm_answer(cli->reader, er, E_NOTFOUND, 0x27, NULL, NULL);
		return 0;
	}

  uint16_t ercaid = er->caid;
  uint32_t erprid = er->prid;

  /* TODO: gbox encodes provids differently for several providers, hardcode some sort of mangle table in here? */
  switch (ercaid >> 8) {
	// cryptoworks
	case 0x0d:
		erprid = erprid << 8;
		break;
  }

  uchar send_buf[0x2048], *ptr;

  if (!er->l) return -1;
  er->gbox_crc = gbox_get_ecmchecksum(er);

  memset(send_buf, 0, sizeof(send_buf));

  gbox_code_cmd(send_buf, MSG_ECM);
  memcpy(send_buf + 2, gbox->peer.key, 4);
  memcpy(send_buf + 6, gbox->key, 4);
  send_buf[10] = er->pid >> 8;
  send_buf[11] = er->pid;
  send_buf[12] = er->srvid >> 8;
  send_buf[13] = er->srvid;

/*  send_buf[14] = er->idx>>8;
  send_buf[15] = er->idx;
  send_buf[16] = 0; // number of cards
  send_buf[17] = 0; // distance */
  
  memcpy(send_buf + 18, er->ecm, er->l);
  ptr = send_buf + 18 + er->l;
  *(ptr) = gbox->id >> 8;
  *(++ptr) = gbox->id;
  *(++ptr) = gbox->ver;
  ptr++;
  *(++ptr) = gbox->type;
  *(++ptr) = ercaid >> 8;
  *(++ptr) = erprid >> 16;
  *(++ptr) = erprid >> 8;
  *(++ptr) = erprid;
  ptr++;

  LL_ITER it = ll_iter_create(gbox->peer.cards);
  struct gbox_card *card;
  while ((card = ll_iter_next(&it))) {
    //if (card->caid == ercaid && card->provid == er->prid) {
    if (card->provid >> 16 == (ercaid) && (card->provid & 0xffff) == erprid) {
      *(++ptr) = card->peer_id >> 8;
      *(++ptr) = card->peer_id;
      *(++ptr) = card->slot;
      send_buf[16]++;
    }
  }

  if (!send_buf[16]) {
		cs_debug_mask(D_READER, "gbox: %s no suitable card found for %04x:%08x, discarding ecm", cli->reader->label, ercaid, erprid);
		write_ecm_answer(cli->reader, er, E_NOTFOUND, 0x27, NULL, NULL);

		return 0;
  }

  memcpy(++ptr, gbox->checkcode, 7);
  ptr += 7;
  memcpy(ptr, gbox->peer.checkcode, 7);

  gbox_send(cli, send_buf, ptr + 7 - send_buf);

  return 0;
}

static int32_t gbox_send_emm(EMM_PACKET *ep)
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

