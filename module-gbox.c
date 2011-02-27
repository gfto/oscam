#include "globals.h"
#ifdef MODULE_GBOX
#include <pthread.h>
//#define _XOPEN_SOURCE 600
#include <semaphore.h>
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
  uint16 peer_id;
  uint16 provid;
  int slot;
  int dist;
  int lvl;
};

struct gbox_peer {
  uint16 id;
  uchar key[4];
  uchar ver;
  uchar type;
  LLIST *cards;
  uchar checkcode[7];
  uchar *hostname;
  int online;
  int fail_count;
  int hello_count;
};

struct gbox_data {
  uint16 id;
  uchar checkcode[7];
  uchar key[4];
  uchar ver;
  uchar type;
  int ecm_idx;
  int hello_expired;
  uchar cws[16];
  struct gbox_peer peer;
  pthread_mutex_t lock;
  uchar buf[1024];
  sem_t sem;
};

static const uchar sbox[] = {
  0x25, 0x38, 0xd4, 0xcd, 0x17, 0x7a, 0x5e, 0x6c,
  0x52, 0x42, 0xfe, 0x68, 0xab, 0x3f, 0xf7, 0xbe,
  0x47, 0x57, 0x71, 0xb0, 0x23, 0xc1, 0x26, 0x6c,
  0x41, 0xce, 0x94, 0x37, 0x45, 0x04, 0xa2, 0xea,
  0x07, 0x58, 0x35, 0x55, 0x08, 0x2a, 0x0f, 0xe7,
  0xac, 0x76, 0xf0, 0xc1, 0xe6, 0x09, 0x10, 0xdd,
  0xc5, 0x8d, 0x2e, 0xd9, 0x03, 0x9c, 0x3d, 0x2c,
  0x4d, 0x41, 0x0c, 0x5e, 0xde, 0xe4, 0x90, 0xae
};

static int gbox_decode_cmd(uchar *buf)
{
  return buf[0] << 8 | buf[1];
}

static void gbox_calc_checkcode(struct gbox_data *gbox)
{
  memcpy(gbox->checkcode, "\x15\x30\x2\x4\x19\x19\x66", 7);	/* no local cards */

  // for all local cards do:
  /*
    gbox->checkcode[0] ^= provid << 24;
    gbox->checkcode[1] ^= provid << 16;
    gbox->checkcode[2] ^= provid << 8;
    gbox->checkcode[3] ^= provid & 0xff;
    gbox->checkcode[4] ^= slot;  // reader number
    gbox->checkcode[5] ^= gbox->id << 8;
    gbox->checkcode[6] ^= gbox->id & 0xff;
  */
}

uint32_t ecm_getcrc(ECM_REQUEST *er, int ecmlen)
{

  uint8 checksum[4];
  int counter;

  uchar ecm[0xFF];
  memcpy(ecm, er->ecm, er->l);

  checksum[3]= ecm[0];
  checksum[2]= ecm[1];
  checksum[1]= ecm[2];
  checksum[0]= ecm[3];

  for (counter=1; counter< (ecmlen/4) - 4; counter++) {
    checksum[3] ^=ecm[counter*4];
    checksum[2] ^=ecm[counter*4+1];
    checksum[1] ^=ecm[counter*4+2];
    checksum[0] ^=ecm[counter*4+3];
  }

  return checksum[3] << 24 | checksum[2]<<16 | checksum[1]<<8 | checksum[0];
}

static void gbox_encrypt_stage1(uchar *buf, int l, uchar *key)
{
  int i;

  for (i = 31; i >= 0; i--) {
    uchar tmp;

    tmp = key[3];
    int j;
    for (j = 3; j > 0; j--)
      key[j] = (key[j - 1] << 7) + (key[j] >> 1);
    key[0] = (tmp << 7) + (key[0] >> 1);

    buf[i + 1 - ((i + 1) & 0xf8)] += sbox[((key[i + 1 - ((i + 1) & 0xfc)] ^ buf[i - (i & 0xf8)]) >> 2) & 0x3f] * 2;
    buf[i + 1 - ((i + 1) & 0xf8)] ^= sbox[(buf[i - (i & 0xf8)] - key[i + 1 - ((i + 1) & 0xfc)]) & 0x3f];
    buf[i + 1 - ((i + 1) & 0xf8)] += key[i - (i & 0xfc)];
  }
}

static void gbox_encrypt_stage2(uchar *buf, int l, uchar *key)
{
  int i, j;

  for (i = 0; i < 4; i++)
    for (j = 7; j >= 0; j--) {
      uchar tmp;

      tmp = key[3];
      int k;
      for (k = 3; k > 0; k--)
        key[k] = (key[k - 1] << 7) + (key[k] >> 1);
      key[0] = (tmp << 7) + (key[0] >> 1);

      buf[(j + 1) & 7] -= sbox[(buf[j] >> 2) & 0x3f];
      buf[(j + 1) & 7] ^= sbox[(buf[j] - key[(j + 1) & 3]) & 0x3f];
      buf[(j + 1) & 7] -= key[j & 3];
    }
}

static void gbox_decrypt_stage1(uchar *buf, int l, uchar *key)
{
  int i;

  for (i = 0; i < 32; i++) {
    uchar tmp;

    buf[i + 1 - ((i + 1) & 0xf8)] -= key[i - (i & 0xfc)];
    buf[i + 1 - ((i + 1) & 0xf8)] ^= sbox[(buf[i - (i & 0xf8)] - key[i + 1 - ((i + 1) & 0xfc)]) & 0x3f];
    buf[i + 1 - ((i + 1) & 0xf8)] -= sbox[((key[i + 1 - ((i + 1) & 0xfc)] ^ buf[i - (i & 0xf8)]) >> 2) & 0x3f] * 2;

    tmp = key[0];
    int j;
    for (j = 0; j < 3; j++)
      key[j] = ((key[j + 1] & 0x80) >> 7) + (key[j] * 2);
    key[3] = ((tmp & 0x80) >> 7) + (key[3] * 2);
  }
}

static void gbox_decrypt_stage2(uchar *buf, int l, uchar *key)
{
  int i, j;

  for (i = 3; i >= 0; i--)
    for (j = 0; j < 8; j++) {
      uchar tmp;

      buf[(j + 1) & 7] += key[j & 3];
      buf[(j + 1) & 7] ^= sbox[(buf[j] - key[(j + 1) & 3]) & 0x3f];
      buf[(j + 1) & 7] += sbox[(buf[j] >> 2) & 0x3f];

      tmp = key[0];
      int k;
      for (k = 0; k < 3; k++)
        key[k] = ((key[k + 1] & 0x80) >> 7) + (key[k] * 2);
      key[3] = ((tmp & 0x80) >> 7) + (key[3] * 2);
    }
}

static void gbox_encrypt(uchar *buf, int l, uchar *key)
{
  int i;
  uchar tmp_key[4];

  memcpy(tmp_key, key, 4);

  gbox_encrypt_stage1(buf, l, tmp_key);

  for (i = 0; i < l - 2; i++)
    buf[i] ^= buf[i + 1];

  gbox_encrypt_stage2(buf, l, tmp_key);
  gbox_decrypt_stage2(buf + l - 9, 9, tmp_key);
}

static void gbox_decrypt(uchar *buf, int l, uchar *key)
{
  uchar tmp_key[4];

  memcpy(tmp_key, key, 4);

  gbox_encrypt_stage2(buf + l - 9, 9, tmp_key);
  gbox_decrypt_stage2(buf, l, tmp_key);

  int i;
  for (i = l - 2; i >= 0; i--) {
    buf[i] ^= buf[i + 1];
}

  gbox_decrypt_stage1(buf, l, tmp_key);
}

static void gbox_compress(struct gbox_data *gbox, uchar *buf, int unpacked_len, int *packed_len)
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

static void gbox_decompress(struct gbox_data *gbox, uchar *buf, int *unpacked_len)
{
  uchar tmp[2048];

  int len = buf[12] - 13;

  lzo_init();
  if (lzo1x_decompress(buf + 12, len, tmp, (lzo_uint *)unpacked_len, NULL) != LZO_E_OK)
    cs_debug_mask(D_READER, "gbox: decompression failed!");

  memcpy(buf + 12, tmp, *unpacked_len);
  *unpacked_len += 12;
}

/*
static void gbox_handle_gsms(ushort peerid, char *gsms)
{
	cs_log("gbox: gsms received from peer %04x: %s", peerid, gsms);

	if (strnlen(cfg.gbox_gsms_path, sizeof(cfg.gbox_gsms_path))) {
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

  sem_t sem;
  sem_init(&sem, 0 , 1);

  struct timespec ts;
  struct timeval tv;
  gettimeofday(&tv, NULL);
  ts.tv_sec = tv.tv_sec;
  ts.tv_nsec = tv.tv_usec * 1000;
  ts.tv_sec += 30;

  sem_wait(&sem);
  if (sem_timedwait(&sem, &ts) == -1) {
    if (errno == ETIMEDOUT) {
      //printf("gbox: hello expired!\n");
      gbox->hello_expired = 0;
    }
  }

  //printf("gbox: exit gbox_expire_hello()\n");
}

static void gbox_wait_for_response(struct s_client *cli)
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

	//sem_wait(&gbox->sem);
	if (sem_timedwait(&gbox->sem, &ts) == -1) {
		if (errno == ETIMEDOUT) {
			gbox->peer.fail_count++;
			//printf("gbox: sem wait timed-out, fail_count=%d\n", gbox->peer.fail_count);
#define GBOX_FAIL_COUNT 1
			if (gbox->peer.fail_count >= GBOX_FAIL_COUNT) {
				gbox->peer.online = 0;
				//printf("gbox: fail_count >= %d, peer is offline\n", GBOX_FAIL_COUNT);
			}
			//cs_debug_mask(D_READER, "gbox: sem wait timed-out, fail_count=%d\n", gbox->peer.fail_count);
		}
	} else {
		gbox->peer.fail_count = 0;
		//printf("gbox: sem posted, peer is online\n");
	}
	//cs_debug_mask(D_READER, "gbox: sem posted, peer is online");

	//cs_debug_mask(D_READER, "gbox: exit gbox_wait_for_response()");
	//printf("gbox: exit gbox_wait_for_response()\n");
}

static void gbox_send(struct s_client *cli, uchar *buf, int l)
{
  struct gbox_data *gbox = cli->gbox;

  cs_ddump_mask(D_READER, buf, l, "gbox: decrypted data sent (%d bytes):", l);
  cs_ddump_mask(D_READER, gbox->key, 4, "gbox: key before encrypt:");

  gbox_encrypt(buf, l, gbox->peer.key);
  sendto(cli->udp_fd, buf, l, 0, (struct sockaddr *)&cli->udp_sa, sizeof(cli->udp_sa));

  cs_ddump_mask(D_READER, gbox->key, 4, "gbox: key after encrypt:");
  cs_ddump_mask(D_READER, buf, l, "gbox: encrypted data sent (%d bytes):", l);

  pthread_t t;
  pthread_create(&t, NULL, (void *)gbox_wait_for_response, cli);
}

static void gbox_send_boxinfo(struct s_client *cli)
{
  struct gbox_data *gbox = cli->gbox;

  int len;
  uchar buf[4096];

  int hostname_len = strnlen(cfg.gbox_hostname, sizeof(cfg.gbox_hostname) - 1);

  buf[0] = 0xA0;
  buf[1] = 0xA1;
  memcpy(buf + 2, gbox->peer.key, 4);
  memcpy(buf + 6, gbox->key, 4);
  buf[10] = gbox->peer.ver;
  buf[11] = 0x10;
  memcpy(buf + 12, cfg.gbox_hostname, hostname_len);

  len = 12 + hostname_len;

  gbox_send(cli, buf, len);
}

static void gbox_send_hello(struct s_client *cli)
{
  struct gbox_data *gbox = cli->gbox;

  int len;
  uchar buf[4096];

  int hostname_len = strnlen(cfg.gbox_hostname, sizeof(cfg.gbox_hostname) - 1);

  len = 22 + hostname_len;

  memset(buf, 0, sizeof(buf));

  gbox_calc_checkcode(gbox);

  buf[0] = MSG_HELLO >> 8;
  buf[1] = MSG_HELLO & 0xff;
  memcpy(buf + 2, gbox->peer.key, 4);
  memcpy(buf + 6, gbox->key, 4);
  buf[10] = gbox->peer.hello_count;
  buf[11] = 0x80;    // todo this needs adjusting if local card support is added

  memcpy(buf + 12, gbox->checkcode, 7);
  buf[19] = 0x73;
  buf[20] = 0x10;
  memcpy(buf + 21, cfg.gbox_hostname, hostname_len);
  buf[21 + hostname_len] = hostname_len;

  cs_ddump_mask(D_READER, buf, len, "send hello (len=%d):", len);

  gbox_compress(gbox, buf, len, &len);	// TODO: remove _re

  cs_ddump_mask(D_READER, buf, len, "send hello, compressed (len=%d):", len);

  if (++gbox->peer.hello_count == 2) gbox->peer.hello_count = 0;

  gbox_send(cli, buf, len);
}

static int gbox_recv(struct s_client *cli, uchar *b, int l)
{
  struct gbox_data *gbox = cli->gbox;

  if (!gbox)
	  return -1;

  uchar *data = gbox->buf;
  int n;

  sem_post(&gbox->sem);
  gbox->peer.online = 1;

  pthread_mutex_lock(&gbox->lock);

  unsigned int r_addr_len = 0;
  struct sockaddr_in r_addr;
  if ((n = recvfrom(cli->udp_fd, data, sizeof(gbox->buf), 0, (struct sockaddr *)&r_addr, &r_addr_len)) < 8) {
	  cs_log("gbox: invalid recvfrom!!!");
    	pthread_mutex_unlock(&gbox->lock);
    	return -1;
  }

  cs_ddump_mask(D_READER, data, n, "gbox: encrypted data recvd (%d bytes):", n);
  cs_ddump_mask(D_READER, gbox->key, 4, "gbox: key before decrypt:");

  gbox_decrypt(data, n, gbox->key);

  cs_ddump_mask(D_READER, gbox->key, 4, "gbox: key after decrypt:");
  cs_ddump_mask(D_READER, data, n, "gbox: decrypted data recvd (%d bytes):", n);

  memcpy(b, data, l);

  if (!memcmp(data + 2, gbox->key, 4)) {
	  if (memcmp(data + 6, gbox->peer.key, 4) && gbox_decode_cmd(data) != MSG_CW) {
		  cs_log("gbox: INTRUDER ALERT (peer key)!");

		  cs_add_violation((uint)cli->ip);

		  pthread_mutex_unlock(&gbox->lock);
		  return -1;
	  }
  } else {
    cs_log("gbox: INTRUDER ALERT!");

    cs_add_violation((uint)cli->ip);

    pthread_mutex_unlock(&gbox->lock);
	  return -1;
  }

  switch (gbox_decode_cmd(data)) {
    case MSG_HELLO:
      {
        static int exp_seq = 0;

        int payload_len = n;

        gbox_decompress(gbox, data, &payload_len);
        cs_ddump_mask(D_READER, data, payload_len, "gbox: decompressed data (%d bytes):", payload_len);

        int seqno = data[11] & 0x7f;
        int final = data[11] & 0x80;

        int ncards_in_msg = 0;

        if (seqno != exp_seq) return -1;

        if (seqno == 0) {
          exp_seq++;

          if (gbox->peer.cards) ll_destroy_data(gbox->peer.cards);
          gbox->peer.cards = ll_create();

          int checkcode_len = 7;
          int hostname_len = data[payload_len - 1];
          int footer_len = hostname_len + 2;

          // add cards to card list
          uchar *ptr = data + 12;
          while (ptr < data + payload_len - footer_len - checkcode_len - 1) {
            uint32 provid = ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];
            int ncards = ptr[4];

            ptr += 5;

            int i;
            for (i = 0; i < ncards; i++) {
              struct gbox_card *card = malloc(sizeof(struct gbox_card));

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
          gbox->peer.hostname = malloc(hostname_len + 1);
          memcpy(gbox->peer.hostname, data + payload_len - 1 - hostname_len, hostname_len);
          gbox->peer.hostname[hostname_len] = '\0';

          memcpy(gbox->peer.checkcode, data + payload_len - footer_len - checkcode_len - 1, checkcode_len);
          gbox->peer.ver = data[payload_len - footer_len - 1];
          gbox->peer.type = data[payload_len - footer_len];
        } else {
          // add cards to card list
          uchar *ptr = data + 12;
          while (ptr < data + payload_len - 1) {
            uint32 provid = ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];
            int ncards = ptr[4];

            ptr += 5;

            int i;
            for (i = 0; i < ncards; i++) {
              struct gbox_card *card = malloc(sizeof(struct gbox_card));

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

        if (final) exp_seq = 0;

        cs_log("gbox: received hello %d%s, %d providers from %s, version=2.%02X, checkcode=%s",
        		seqno, final ? " (final)" : "", ncards_in_msg, gbox->peer.hostname, gbox->peer.ver, cs_hexdump(0, gbox->peer.checkcode, 7));

        if (!ll_count(gbox->peer.cards))
        	  cli->reader->tcp_connected = 1;

        if (final) {
          if (gbox->hello_expired) {
            gbox->hello_expired = 0;
            gbox_send_hello(cli);

            pthread_t t;
            pthread_create(&t, NULL, (void *)gbox_expire_hello, cli);
          }
          gbox_send_boxinfo(cli);
        }
      }
      break;
    case MSG_CW:
    	memcpy(gbox->cws, data + 14, 16);

    	cs_debug_mask(D_READER, "gbox: received cws=%s, peer=%04x, ecm_pid=%d, sid=%d",
        		data[10] << 8 | data[11], data[6] << 8 | data[7], data[8] << 8 | data[9], cs_hexdump(0, gbox->cws, 16));
    	break;
    case MSG_CHECKCODE:
    	memcpy(gbox->peer.checkcode, data + 10, 7);
        cs_debug_mask(D_READER, "gbox: received checkcode=%s",  cs_hexdump(0, gbox->peer.checkcode, 7));
    	break;
    /*case MSG_GSMS:
    	//gbox_handle_gsms(peerid, gsms);
    	break;
    	*/
    case MSG_ECM: //TODO:
      break;
    default:
      cs_ddump_mask(D_READER, data, n, "gbox: unknown data received (%d bytes):", n);
  }
  pthread_mutex_unlock(&gbox->lock);

  return 0;
}

static void gbox_send_dcw(struct s_client *cli, ECM_REQUEST *er)
{
  // TODO
}

static int gbox_client_init(struct s_client *cli)
{
	if (!strnlen(cfg.gbox_hostname, sizeof(cfg.gbox_hostname) - 1)) {
		cs_log("gbox: error, no hostname configured in oscam.conf!");
		return -1;
	}

	if (strnlen(cfg.gbox_key, sizeof(cfg.gbox_key) - 1) != 8) {
		cs_log("gbox: error, no/invalid password configured in oscam.conf!");
		return -1;
	}

	if (cfg.gbox_port < 1) {
		cs_log("gbox: no/invalid port configured in oscam.conf!");
		return -1;
	}

  cli->gbox = malloc(sizeof(struct gbox_data));

  struct gbox_data *gbox = cli->gbox;
  struct s_reader *rdr = cli->reader;

  sem_init(&gbox->sem, 0 , 1);

  rdr->card_status = CARD_FAILURE;
  rdr->tcp_connected = 0;

  memset(gbox, 0, sizeof(struct gbox_data));
  memset(&gbox->peer, 0, sizeof(struct gbox_peer));

  ulong r_pwd = a2i(rdr->r_pwd, 4);
  ulong key = a2i(cfg.gbox_key, 4);
  int i;
  for (i = 3; i >= 0; i--) {
	  gbox->peer.key[3 - i] = (r_pwd >> (8 * i)) & 0xff;
	  gbox->key[3 - i] = (key >> (8 * i)) & 0xff;
  }

  cs_ddump_mask(D_READER, gbox->peer.key, 4, "r_pwd: %s:", rdr->r_pwd);
  cs_ddump_mask(D_READER, gbox->key, 4, "cfg.gbox_key: %s:", cfg.gbox_key);

  gbox->peer.id = (gbox->peer.key[0] ^ gbox->peer.key[2]) << 8 | (gbox->peer.key[1] ^ gbox->peer.key[3]);
  gbox->id = (gbox->key[0] ^ gbox->key[2]) << 8 | (gbox->key[1] ^ gbox->key[3]);
  gbox->ver = 0x30;
  gbox->type = 0x32;

  struct sockaddr_in loc_sa;
  struct protoent *ptrp;
  int p_proto;

  cli->pfd=0;

  cli->is_udp = 1;

	if ((ptrp=getprotobyname("udp")))
		p_proto=ptrp->p_proto;
	else
		p_proto=(cli->is_udp) ? 17 : 6;

	cli->ip=0;
	memset((char *)&loc_sa,0,sizeof(loc_sa));
	loc_sa.sin_family = AF_INET;
  loc_sa.sin_addr.s_addr = INADDR_ANY;
  loc_sa.sin_port = htons(cfg.gbox_port);

  if ((cli->udp_fd=socket(PF_INET, SOCK_DGRAM, p_proto))<0)
   {
        cs_log("socket creation failed (errno=%d)", errno);
        cs_exit(1);
  }

  int opt = 1;
  setsockopt(cli->udp_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof (opt));

#ifdef SO_PRIORITY
  if (cfg.netprio)
    setsockopt(cli->udp_fd, SOL_SOCKET, SO_PRIORITY, (void *)&cfg.netprio, sizeof(ulong));
#endif

  if (cfg.gbox_port>0)
  {
    if (bind(cli->udp_fd, (struct sockaddr *)&loc_sa, sizeof (loc_sa))<0)
    {
      cs_log("bind failed (port=%d, errno=%d)", rdr->l_port, errno);
      close(cli->udp_fd);
        return 1;
    }
  }

  memset((char *)&cli->udp_sa, 0, sizeof(cli->udp_sa));

  struct hostent *hp;
  hp = gethostbyname(rdr->device);
  memcpy((char *)&cli->udp_sa.sin_addr, (char *)hp->h_addr, hp->h_length);

  cli->udp_sa.sin_family=AF_INET;
  cli->udp_sa.sin_port=htons((u_short)rdr->r_port);

  cs_log("proxy %s:%d (fd=%d, peer id=%04x, my id=%04x, my hostname=%s, listen port=%d)",
    rdr->device, rdr->r_port, cli->udp_fd, gbox->peer.id, gbox->id, cfg.gbox_hostname, cfg.gbox_port);

    cli->pfd=cli->udp_fd;

  pthread_mutex_init(&gbox->lock, NULL);

  gbox->hello_expired = 1;

  gbox_send_hello(cli);

  return 0;
}

static int gbox_recv_chk(struct s_client *cli, uchar *dcw, int *rc, uchar *buf, int UNUSED(n))
{
  struct gbox_data *gbox = cli->gbox;

  if (gbox_decode_cmd(buf) == MSG_CW) {
	  *rc = 1;

	  memcpy(dcw, gbox->cws, 16);

	  return gbox->ecm_idx;
  }

  return -1;
}

static int gbox_send_ecm(struct s_client *cli, ECM_REQUEST *er, uchar *buf)
{
  struct gbox_data *gbox = cli->gbox;

	if (!gbox || !cli->reader->tcp_connected) {
		er->rc = E_RDR_NOTFOUND;
		er->rcEx = 0x27;
		cs_debug_mask(D_READER, "gbox: %s server not init!", cli->reader->label);
		write_ecm_answer(cli->reader, er);

		return 0;
	}

	if (!ll_count(gbox->peer.cards)) {
		er->rc = E_RDR_NOTFOUND;
		er->rcEx = 0x27;
		cs_debug_mask(D_READER, "gbox: %s NO CARDS!", cli->reader->label);
		write_ecm_answer(cli->reader, er);
		return 0;
	}

	if (!gbox->peer.online) {
		er->rc = E_RDR_NOTFOUND;
		er->rcEx = 0x27;
		cs_debug_mask(D_READER, "gbox: peer is OFFLINE!");
		write_ecm_answer(cli->reader, er);
		return 0;
	}

  uchar send_buf[0x2048], *ptr;

  if (!er->l) return -1;

  gbox->ecm_idx = er->idx;

  memset(send_buf, 0, sizeof(send_buf));

  send_buf[0] = MSG_ECM >> 8;
  send_buf[1] = MSG_ECM & 0xff;
  memcpy(send_buf + 2, gbox->peer.key, 4);
  memcpy(send_buf + 6, gbox->key, 4);
  send_buf[10] = er->pid >> 8;
  send_buf[11] = er->pid;
  send_buf[12] = er->srvid >> 8;
  send_buf[13] = er->srvid;
/*  send_buf[14] = er->prid >> 16;
  send_buf[15] = er->prid >> 8;
  send_buf[17] = er->prid;*/
  memcpy(send_buf + 18, er->ecm, er->l);
  ptr = send_buf + 18 + er->l;
  *(ptr) = gbox->id >> 8;
  *(++ptr) = gbox->id;
  *(++ptr) = gbox->ver;
  ptr++;
  *(++ptr) = gbox->type;
  *(++ptr) = er->caid >> 8;
  *(++ptr) = er->prid >> 16;
  *(++ptr) = er->prid >> 8;
  *(++ptr) = er->prid;
  ptr++;

  LL_ITER *it = ll_iter_create(gbox->peer.cards);
  struct gbox_card *card;
  while ((card = ll_iter_next(it))) {
    //if (card->caid == er->caid && card->provid == er->prid) {
    if (card->provid >> 24 == er->caid >> 8 && (card->provid & 0xffffff) == er->prid) {
      *(++ptr) = card->peer_id >> 8;
      *(++ptr) = card->peer_id;
      *(++ptr) = card->slot;
      send_buf[16]++;
    }
    break;
  }
  ll_iter_release(it);

  if (!send_buf[16]) {
		er->rc = E_RDR_NOTFOUND;
		er->rcEx = 0x27;
		cs_debug_mask(D_READER, "gbox: %s no suitable card found, discarding ecm", cli->reader->label);
		write_ecm_answer(cli->reader, er);

		return 0;
  }

  memcpy(++ptr, gbox->checkcode, 7);
  ptr += 7;
  memcpy(ptr, gbox->peer.checkcode, 7);

  gbox_send(cli, send_buf, ptr + 7 - send_buf);

  return 0;
}

static int gbox_send_emm(EMM_PACKET *ep)
{
  // emms not yet supported

  return 0;
}

void module_gbox(struct s_module *ph)
{
  strcpy(ph->desc, "gbox");
  ph->num=R_GBOX;
  ph->type=MOD_CONN_UDP;
  ph->logtxt = ", crypted";

  ph->multi=1;
  ph->watchdog=1;
  ph->send_dcw=gbox_send_dcw;

  ph->recv=gbox_recv;
  ph->c_multi=1;
  ph->c_init=gbox_client_init;
  ph->c_recv_chk=gbox_recv_chk;
  ph->c_send_ecm=gbox_send_ecm;
  ph->c_send_emm=gbox_send_emm;
}
#endif

