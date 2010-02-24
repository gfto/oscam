#include "globals.h"


int g_flag = 0;
/******************************** */
/* LINKED LIST CODE - IF IT'S USEFUL ELSEWHERE, IT SHOULD BE SPLIT OFF INTO linkedlist.h/.c */
/******************************** */

// Simple, doubly linked
// This is thread-safe, so requires pthread. Also expect locking if iterators are not destroyed.

#include <pthread.h>

struct llist_node {
  void *obj;
  struct llist_node *prv;
  struct llist_node *nxt;
};

typedef struct llist {
  struct llist_node *first;
  struct llist_node *last;
  int items;
  pthread_mutex_t lock;
} LLIST;

typedef struct llist_itr {
  LLIST *l;
  struct llist_node *cur;
} LLIST_ITR;

LLIST *llist_create(void);                  // init linked list
void llist_destroy(LLIST *l);               // de-init linked list - frees all objects on the list

void *llist_append(LLIST *l, void *o);       // append object onto bottom of list, returns ptr to obj

void *llist_itr_init(LLIST *l, LLIST_ITR *itr);       // linked list iterator, returns ptr to first obj
//void llist_itr_release(LLIST_ITR *itr);               // release iterator
void *llist_itr_next(LLIST_ITR *itr);                 // iterates, returns ptr to next obj

void *llist_itr_insert(LLIST_ITR *itr, void *o);  // insert object at itr point, iterates to and returns ptr to new obj
void *llist_itr_remove(LLIST_ITR *itr);           // remove obj at itr, iterates to and returns ptr to next obj

int llist_count(LLIST *l);    // returns number of obj in list

/******************************** */

#include <string.h>
#include <stdlib.h>
int cc_cli_init();

LLIST *llist_create(void)
{
  LLIST *l = malloc(sizeof(LLIST));
  bzero(l, sizeof(LLIST));

  pthread_mutex_init(&l->lock, NULL);

  l->items = 0;

  return l;
}

void llist_destroy(LLIST *l)
{
  LLIST_ITR itr;
  void *o = llist_itr_init(l, &itr);
  while (o) {
    free(o);
    o = llist_itr_remove(&itr);
  }
//  llist_itr_release(&itr);
}

void *llist_append(LLIST *l, void *o)
{
  pthread_mutex_lock(&l->lock);
  if (o) {
    struct llist_node *ln = malloc(sizeof(struct llist_node));

    bzero(ln, sizeof(struct llist_node));
    ln->obj = o;

    if (l->last) {
      ln->prv = l->last;
      ln->prv->nxt = ln;
    } else {
      l->first = ln;
    }
    l->last = ln;

    l->items++;
  }
  pthread_mutex_unlock(&l->lock);

  return o;
}

void *llist_itr_init(LLIST *l, LLIST_ITR *itr)
{
 // pthread_mutex_lock(&l->lock);
  if (l->first) {

    bzero(itr, sizeof(LLIST_ITR));
    itr->cur = l->first;
    itr->l = l;

    return itr->cur->obj;
  }

  return NULL;
}
/*
void llist_itr_release(LLIST_ITR *itr)
{
 // pthread_mutex_unlock(&itr->l->lock);
}
*/
void *llist_itr_next(LLIST_ITR *itr)
{
  if (itr->cur->nxt) {
    itr->cur = itr->cur->nxt;
    return itr->cur->obj;
  }

  return NULL;
}

void *llist_itr_remove(LLIST_ITR *itr)  // this needs cleaning - I was lazy
{
  itr->l->items--;
  if ((itr->cur == itr->l->first) && (itr->cur == itr->l->last)) {
    free(itr->cur);
    itr->l->first = NULL;
    itr->l->last = NULL;
    return NULL;
  } else if (itr->cur == itr->l->first) {
    struct llist_node *nxt = itr->cur->nxt;
    free(itr->cur);
    nxt->prv = NULL;
    itr->l->first = nxt;
    itr->cur = nxt;
  } else if (itr->cur == itr->l->last) {
    itr->l->last = itr->cur->prv;
    itr->l->last->nxt = NULL;
    free(itr->cur);
    return NULL;
  } else {
    struct llist_node *nxt = itr->cur->nxt;
    itr->cur->prv->nxt = itr->cur->nxt;
    itr->cur->nxt->prv = itr->cur->prv;
    free(itr->cur);
    itr->cur = nxt;
  }

  return itr->cur->obj;
}

int llist_count(LLIST *l)
{
  return l->items;
}

/******************************** */

#define CC_MAXMSGSIZE 512
#define CC_MAX_PROV   16
#define CC_MAX_ECMS   50  // before reconnect

#define SWAPC(X, Y) do { char p; p = *X; *X = *Y; *Y = p; } while(0)
#define NULLFREE(X) do { if (X) { free(X); X = NULL; } } while(0)

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
    uint16 caid;
    uint8 hop;
    uint8 key[8];     // card serial (for au)
    LLIST *provs;     // providers
    LLIST *badsids;   // sids that have failed to decode
};

struct cc_data {
  struct cc_crypt_block block[2];    // crypto state blocks

  uint8 node_id[8],           // client node id
        peer_node_id[8],      // server node id
        dcw[16];              // control words

  struct cc_card *cur_card;   // ptr to selected card
  LLIST *cards;               // cards list

  uint32 count;
  uint32 ecm_count;
  uint16 cur_sid;

  int last_nok;
  ECM_REQUEST *found;

  unsigned long crc;

  pthread_mutex_t lock;
  pthread_mutex_t ecm_busy;
};

static unsigned int seed;
static uchar fast_rnd()
{
  unsigned int offset = 12923;
  unsigned int multiplier = 4079;

  seed = seed * multiplier + offset;
  return (uchar)(seed % 0xFF);
}

static void cc_init_crypt(struct cc_crypt_block *block, uint8 *key, int len)
{
  int i = 0 ;
  uint8 j = 0;

  for (i=0; i<256; i++) {
    block->keytable[i] = i;
  }

  for (i=0; i<256; i++) {
    j += key[i % len] + block->keytable[i];
    SWAPC(&block->keytable[i], &block->keytable[j]);
  }

  block->state = *key;
  block->counter=0;
  block->sum=0;
}

static void cc_crypt(struct cc_crypt_block *block, uint8 *data, int len, cc_crypt_mode_t mode)
{
  int i;
  uint8 z;

  for (i = 0; i < len; i++) {
    block->counter++;
    block->sum += block->keytable[block->counter];
    SWAPC(&block->keytable[block->counter], &block->keytable[block->sum]);
    z = data[i];
    data[i] = z ^ block->keytable[(block->keytable[block->counter] + block->keytable[block->sum]) & 0xff] ^ block->state;
    if (!mode) z = data[i];
    block->state = block->state ^ z;
  }
}

static void cc_xor(uint8 *buf)
{
  const char cccam[] = "CCcam";
  uint8 i;

  for ( i = 0; i < 8; i++ ) {
    buf[8 + i] = i * buf[i];
    if ( i <= 5 ) {
      buf[i] ^= cccam[i];
    }
  }
}

static void cc_cw_crypt(uint8 *cws)
{
  struct cc_data *cc;
  uint64 node_id;
  uint8 tmp;
  int i;

  if (reader[ridx].cc) {
    cc = reader[ridx].cc;
    node_id = b2ll(8, cc->node_id);
  }
  else {
    cc = client[cs_idx].cc;
    node_id = b2ll(8, cc->peer_node_id);
  }

  for (i = 0; i < 16; i++) {
    tmp = cws[i] ^ (node_id >> (4 * i));
    if (i & 1) tmp = ~tmp;
    cws[i] = (cc->cur_card->id >> (2 * i)) ^ tmp;
  }
}

static void cc_cycle_connection()
{
  reader[ridx].tcp_connected = 0;
  cs_sleepms(200);
  close(pfd);
  client[cs_idx].udp_fd = 0;
  cs_sleepms(100);
  cc_cli_init();
}

static int cc_msg_recv(uint8 *buf)
{
  int len;
  uint8 netbuf[CC_MAXMSGSIZE];
  struct cc_data *cc;

  if (reader[ridx].cc)
    cc = reader[ridx].cc;
  else
    cc = client[cs_idx].cc;

  int handle = client[cs_idx].udp_fd;

  if (handle < 0) return -1;

  len = recv(handle, netbuf, 4, MSG_WAITALL);

  if (!len) return 0;

  if (len != 4) { // invalid header length read
    cs_log("cccam: invalid header length");
    return -1;
  }

  cc_crypt(&cc->block[DECRYPT], netbuf, 4, DECRYPT);
  cs_ddump(netbuf, 4, "cccam: decrypted header:");

  g_flag = netbuf[0];

  if (((netbuf[2] << 8) | netbuf[3]) != 0) {  // check if any data is expected in msg
    if (((netbuf[2] << 8) | netbuf[3]) > CC_MAXMSGSIZE - 2) {
      cs_log("cccam: message too big");
      return -1;
    }

    len = recv(handle, netbuf+4, (netbuf[2] << 8) | netbuf[3], MSG_WAITALL);  // read rest of msg

    if (len != ((netbuf[2] << 8) | netbuf[3])) {
      cs_log("cccam: invalid message length read");
      return -1;
    }

    cc_crypt(&cc->block[DECRYPT], netbuf+4, len, DECRYPT);
    len += 4;
  }

  cs_ddump(netbuf, len, "cccam: full decrypted msg, len=%d:", len);

  memcpy(buf, netbuf, len);
  return len;
}

static int cc_cmd_send(uint8 *buf, int len, cc_msg_type_t cmd)
{
  int n;
  uint8 *netbuf = malloc(len+4);
  struct cc_data *cc;

  if (reader[ridx].cc)
    cc = reader[ridx].cc;
  else
    cc = client[cs_idx].cc;

  bzero(netbuf, len+4);

  if (cmd == MSG_NO_HEADER) {
    memcpy(netbuf, buf, len);
  } else {
    // build command message
    netbuf[0] = g_flag;   // flags??
    netbuf[1] = cmd & 0xff;
    netbuf[2] = len >> 8;
    netbuf[3] = len & 0xff;
    if (buf) memcpy(netbuf+4, buf, len);
    len += 4;
  }

  cs_ddump(netbuf, len, "cccam: send:");
  cc_crypt(&cc->block[ENCRYPT], netbuf, len, ENCRYPT);

  n = send(client[cs_idx].udp_fd, netbuf, len, 0);

  NULLFREE(netbuf);

  return n;
}

static int cc_send_cli_data()
{
  int i;
  struct cc_data *cc = reader[ridx].cc;

  cs_debug("cccam: send client data");

  seed = (unsigned int) time((time_t*)0);
  for( i=0; i<8; i++ ) cc->node_id[i]=fast_rnd();

  uint8 buf[CC_MAXMSGSIZE];
  bzero(buf, CC_MAXMSGSIZE);

  memcpy(buf, reader[ridx].r_usr, sizeof(reader[ridx].r_usr));
  memcpy(buf + 20, cc->node_id, 8 );
  memcpy(buf + 29, reader[ridx].cc_version, sizeof(reader[ridx].cc_version));   // cccam version (ascii)
  memcpy(buf + 61, reader[ridx].cc_build, sizeof(reader[ridx].cc_build));       // build number (ascii)

  cs_log ("cccam: user: %s, version: %s, build: %s", reader[ridx].r_usr, reader[ridx].cc_version, reader[ridx].cc_build);

  i = cc_cmd_send(buf, 20 + 8 + 6 + 26 + 4 + 28 + 1, MSG_CLI_DATA);

  return i;
}

static int cc_send_srv_data()
{
  int i;
  struct cc_data *cc = client[cs_idx].cc;

  cs_debug("cccam: send server data");

  seed = (unsigned int) time((time_t*)0);
  for( i=0; i<8; i++ ) cc->node_id[i]=fast_rnd();

  uint8 buf[CC_MAXMSGSIZE];
  bzero(buf, CC_MAXMSGSIZE);

  memcpy(buf, cc->node_id, 8 );
  memcpy(buf + 8, cfg->cc_version, sizeof(reader[ridx].cc_version));   // cccam version (ascii)
  memcpy(buf + 40, cfg->cc_build, sizeof(reader[ridx].cc_build));       // build number (ascii)

  cs_log ("cccam: version: %s, build: %s", cfg->cc_version, cfg->cc_build);

  return cc_cmd_send(buf, 0x48, MSG_SRV_DATA);
}

static int cc_get_nxt_ecm()
{
  int n, i;
  time_t t;
 // struct cc_data *cc = reader[ridx].cc;

  t=time((time_t *)0);
  for (i = 1, n = 1; i < CS_MAXPENDING; i++)
  {
    if ((t-(ulong)ecmtask[i].tps.time > ((cfg->ctimeout + 500) / 1000) + 1) &&
        (ecmtask[i].rc >= 10))      // drop timeouts
        {
          ecmtask[i].rc=0;
        }

    if (ecmtask[i].rc >= 10) {  // stil active and waiting
      // search for the ecm with the lowest time, this should be the next to go
      if ((!n || ecmtask[n].tps.time-ecmtask[i].tps.time < 0) && &ecmtask[n]) n = i;
    }
  }
  return n;
}

static int cc_send_ecm(ECM_REQUEST *er, uchar *buf)
{
  int n, h = -1;
  struct cc_data *cc = reader[ridx].cc;
  struct cc_card *card;
  LLIST_ITR itr;
  ECM_REQUEST *cur_er;

  if (cc->ecm_count) cc->ecm_count++;

  if (!cc || (pfd < 1)) {
    if (er) {
      er->rc = 0;
      er->rcEx = 0x27;
      cs_log("cccam: server not init!");
      write_ecm_answer(fd_c2m, er);
    }
    return 0;
  }

//  pthread_mutex_lock(&cc->ecm_busy);
  if (pthread_mutex_trylock(&cc->ecm_busy) == EBUSY) {
    cs_debug("cccam: ecm trylock: failed to get lock");
    return 0;
  } else {
    cs_debug("cccam: ecm trylock: got lock");
  }
//  pthread_mutex_lock(&cc->lock);

  if ((n = cc_get_nxt_ecm()) < 0) {
    pthread_mutex_unlock(&cc->ecm_busy);
    pthread_mutex_unlock(&cc->lock);
    return 0;   // no queued ecms
  }
  cur_er = &ecmtask[n];

  if (crc32(0, cur_er->ecm, cur_er->l) == cc->crc) cur_er->rc = 99;
  cc->crc = crc32(0, cur_er->ecm, cur_er->l);

  cs_debug("cccam: ecm crc = 0x%lx", cc->crc);

  if (cur_er->rc == 99) {
    pthread_mutex_unlock(&cc->ecm_busy);
    pthread_mutex_unlock(&cc->lock);
    return 0;   // ecm already sent
  }

  //cc->found = cur_er;

  if (buf) memcpy(buf, cur_er->ecm, cur_er->l);

  cc->cur_card = NULL;
  cc->cur_sid = cur_er->srvid;

  card = llist_itr_init(cc->cards, &itr);

  while (card) {
    if (card->caid == cur_er->caid) {   // caid matches
      int s = 0;

      LLIST_ITR sitr;
      uint16 *sid = llist_itr_init(card->badsids, &sitr);
      while (sid) {
        if (*sid == cc->cur_sid) {
          s = 1;
          break;
        }
        sid = llist_itr_next(&sitr);
      }
//      llist_itr_release(&sitr);

      LLIST_ITR pitr;
      uint8 *prov = llist_itr_init(card->provs, &pitr);
      while (prov && !s) {
        if (b2i(3, prov) == cur_er->prid) {  // provid matches
          if (((h < 0) || (card->hop < h)) && (card->hop <= reader[ridx].cc_maxhop - 1)) {  // card is closer and doesn't exceed max hop
            cc->cur_card = card;
            h = card->hop;  // card has been matched
          }
        }
        prov = llist_itr_next(&pitr);
      }
//      llist_itr_release(&pitr);
    }
    card = llist_itr_next(&itr);
  }
//  llist_itr_release(&itr);

  if (cc->cur_card) {
    uint8 *ecmbuf = malloc(cur_er->l+13);
    bzero(ecmbuf, cur_er->l+13);

    // build ecm message
    ecmbuf[0] = cc->cur_card->caid >> 8;
    ecmbuf[1] = cc->cur_card->caid & 0xff;
    ecmbuf[2] = cur_er->prid >> 24;
    ecmbuf[3] = cur_er->prid >> 16;
    ecmbuf[4] = cur_er->prid >> 8;
    ecmbuf[5] = cur_er->prid & 0xff;
    ecmbuf[6] = cc->cur_card->id >> 24;
    ecmbuf[7] = cc->cur_card->id >> 16;
    ecmbuf[8] = cc->cur_card->id >> 8;
    ecmbuf[9] = cc->cur_card->id & 0xff;
    ecmbuf[10] = cur_er->srvid >> 8;
    ecmbuf[11] = cur_er->srvid & 0xff;
    ecmbuf[12] = cur_er->l & 0xff;
    memcpy(ecmbuf+13, cur_er->ecm, cur_er->l);

    cc->count = cur_er->idx;

    cs_log("cccam: sending ecm for sid %04x to card %08x, hop %d", cur_er->srvid, cc->cur_card->id, cc->cur_card->hop + 1);
    n = cc_cmd_send(ecmbuf, cur_er->l+13, MSG_CW_ECM);      // send ecm

    NULLFREE(ecmbuf);
  } else {
    n = -1;
    cs_log("cccam: no suitable card on server");
    cur_er->rc = 0;
    cur_er->rcEx = 0x27;
    //cur_er->rc = 1;
    //cur_er->rcEx = 0;
    cs_sleepms(100);
    write_ecm_answer(fd_c2m, cur_er);
    //reader[ridx].last_s = reader[ridx].last_g;

    card = llist_itr_init(cc->cards, &itr);
      while (card) {
        if (card->caid == cur_er->caid) {   // caid matches
          LLIST_ITR sitr;
          uint16 *sid = llist_itr_init(card->badsids, &sitr);
          while (sid) {
            if (*sid == cur_er->srvid)
            	sid = llist_itr_remove(&sitr);
            else sid = llist_itr_next(&sitr);
          }
//          llist_itr_release(&sitr);
        }
        card = llist_itr_next(&itr);
      }
//      llist_itr_release(&itr);

      pthread_mutex_unlock(&cc->ecm_busy);
  }

  return 0;
}
/*
static int cc_abort_user_ecms(){
  int n, i;
  time_t t;//, tls;
  struct cc_data *cc = reader[ridx].cc;

  t=time((time_t *)0);
  for (i=1,n=1; i<CS_MAXPENDING; i++)
  {
    if ((t-ecmtask[i].tps.time > ((cfg->ctimeout + 500) / 1000) + 1) &&
        (ecmtask[i].rc>=10))      // drop timeouts
        {
          ecmtask[i].rc=0;
        }
    int td=abs(1000*(ecmtask[i].tps.time-cc->found->tps.time)+ecmtask[i].tps.millitm-cc->found->tps.millitm);
    if (ecmtask[i].rc>=10 && ecmtask[i].cidx==cc->found->cidx && &ecmtask[i]!=cc->found){
          cs_log("aborting idx:%d caid:%04x client:%d timedelta:%d",ecmtask[i].idx,ecmtask[i].caid,ecmtask[i].cidx,td);
          ecmtask[i].rc=0;
          ecmtask[i].rcEx=7;
          write_ecm_answer(fd_c2m, &ecmtask[i]);
        }
  }
  return n;

}
*/

static cc_msg_type_t cc_parse_msg(uint8 *buf, int l)
{
  int ret = buf[1];
  struct cc_data *cc;

  if (reader[ridx].cc)
    cc = reader[ridx].cc;
  else
    cc = client[cs_idx].cc;

  switch (buf[1]) {
  case MSG_CLI_DATA:
    cs_debug("cccam: client data ack");
    break;
  case MSG_SRV_DATA:
    memcpy(cc->peer_node_id, buf+4, 8);
    cs_log("cccam: srv %s running v%s (%s)", cs_hexdump(0, cc->peer_node_id, 8), buf+12, buf+44);
    break;
  case MSG_NEW_CARD:
    {
      int i = 0;
      struct cc_card *card = malloc(sizeof(struct cc_card));

      bzero(card, sizeof(struct cc_card));

      card->provs = llist_create();
      card->badsids = llist_create();
      card->id = b2i(4, buf+4);
      card->caid = b2i(2, buf+12);
      card->hop = buf[14];
      memcpy(card->key, buf+16, 8);

      cs_log("cccam: card %08x added, caid %04x, hop %d, key %s",
          card->id, card->caid, card->hop, cs_hexdump(0, card->key, 8));


      for (i = 0; i < buf[24]; i++) {  // providers
        uint8 *prov = malloc(3);

        memcpy(prov, buf+25+(7*i), 3);
        cs_log("      prov %d, %06x", i+1, b2i(3, prov));

        llist_append(card->provs, prov);
      }


      llist_append(cc->cards, card);
      if (!cc->cur_card) cc->cur_card = card;
    }
    break;
  case MSG_CARD_REMOVED:
  {
    struct cc_card *card;
    LLIST_ITR itr;

    card = llist_itr_init(cc->cards, &itr);
    while (card) {
      if (card->id == b2i(4, buf+4)) {
        cs_debug("cccam: card %08x removed, caid %04x", card->id, card->caid);

        llist_destroy(card->provs);
        llist_destroy(card->badsids);
        free(card);

        card = llist_itr_remove(&itr);
        break;
      } else {
        card = llist_itr_next(&itr);
      }
    }
//    llist_itr_release(&itr);
  }
    break;
  case MSG_CW_NOK1:
  case MSG_CW_NOK2:
    cs_log("cccam: cw nok, sid = %x", cc->cur_sid);

    int f = 0;
    LLIST_ITR itr;
    uint16 *sid = llist_itr_init(cc->cur_card->badsids, &itr);
    while (sid && !f) {
      if (*sid == cc->cur_sid) {
//        llist_itr_release(&itr);
        f = 1;
      }
      sid = llist_itr_next(&itr);
    }
//    llist_itr_release(&itr);

    if (!f) {
      sid = malloc(sizeof(uint16));
      *sid = cc->cur_sid;

      sid = llist_append(cc->cur_card->badsids, sid);
      cs_debug("   added sid block for card %08x", cc->cur_card->id);
    }
    bzero(cc->dcw, 16);
    pthread_mutex_unlock(&cc->ecm_busy);
    cc_send_ecm(NULL, NULL);
    ret = 0;
    break;
  case MSG_CW_ECM:
    if (is_server) {
      ECM_REQUEST *er;

      cc->cur_card = malloc(sizeof(struct cc_card));
      bzero(cc->cur_card, sizeof(struct cc_card));

      cc->cur_card->id = buf[10] << 24 | buf[11] << 16 | buf[12] << 8 | buf[13];

      if ((er=get_ecmtask())) {
        er->caid = b2i(2, buf+4);
        er->srvid = b2i(2, buf+14);
        er->l = buf[16];
        memcpy(er->ecm, buf+17, er->l);
        er->prid = b2i(4, buf+6);
        get_cw(er);
      }
    } else {
      cc_cw_crypt(buf+4);
      memcpy(cc->dcw, buf+4, 16);
      cs_debug("cccam: cws: %s", cs_hexdump(0, cc->dcw, 16));
      cc_crypt(&cc->block[DECRYPT], buf+4, l-4, ENCRYPT); // additional crypto step
      pthread_mutex_unlock(&cc->ecm_busy);
      //cc_abort_user_ecms();
      cc_send_ecm(NULL, NULL);
      ret = 0;
    }
    break;
  case MSG_KEEPALIVE:
    cc_cmd_send(NULL, 0, MSG_KEEPALIVE);
    cs_debug("cccam: keepalive");
    break;
  case MSG_BAD_ECM:
    //cc->ecm_count = 1;
    //cs_log("cccam: cmd 0x05 recvd, commencing ecm count");
    cc_cmd_send(NULL, 0, MSG_BAD_ECM);
    break;
  case MSG_CMD_0B:
    // need to work out algo (reverse) for this...
    cc_cycle_connection();
  default:
    break;
  }

  if (cc->ecm_count > CC_MAX_ECMS) cc_cycle_connection();

  return ret;
}

static int cc_recv_chk(uchar *dcw, int *rc, uchar *buf)
{
  struct cc_data *cc = reader[ridx].cc;

  if (buf[1] == MSG_CW_ECM) {
    memcpy(dcw, cc->dcw, 16);
    cs_debug("cccam: recv chk - MSG_CW %d - %s", cc->count, cs_hexdump(0, dcw, 16));
    *rc = 1;
    return(cc->count);
  } else if ((buf[1] == (MSG_CW_NOK1)) || (buf[1] == (MSG_CW_NOK2))) {
    memset(dcw, 0, 16);
    return *rc = 0;
    return(cc->count);
  }

  return (-1);
}

static void cc_send_dcw(ECM_REQUEST *er)
{
  uchar buf[16];
  struct cc_data *cc;

  bzero(buf, sizeof(buf));

  if(er->rc<=3) {
    cc = client[cs_idx].cc;
    memcpy(buf, er->cw, sizeof(buf));
    cc_cw_crypt(buf);
    NULLFREE(cc->cur_card);
    cs_debug("cccam: send cw: er->cpti=%d", er->cpti);
    cc_cmd_send(buf, 16, MSG_CW_ECM);
    cc_crypt(&cc->block[ENCRYPT], buf, 16, ENCRYPT); // additional crypto step
  } else {
    cs_debug("cccam: send cw NOK: er->cpti=%d!", er->cpti);
    cc_cmd_send(NULL, 0, MSG_CW_NOK1);
  }
}

int cc_recv(uchar *buf, int l)
{
  int n;
  uchar *cbuf;
  struct cc_data *cc;

  if (reader[ridx].cc)
    cc = reader[ridx].cc;
  else
    cc = client[cs_idx].cc;

  if (buf==NULL) return -1;
  cbuf = malloc(l);
  if (cbuf==NULL) return -1;

  memcpy(cbuf, buf, l);   // make a copy of buf

  pthread_mutex_lock(&cc->lock);

  n = cc_msg_recv(cbuf);  // recv and decrypt msg

  cs_ddump(cbuf, n, "cccam: received %d bytes from %s", n, remote_txt());
  client[cs_idx].last = time((time_t *) 0);

  if (n == 0) {
    cs_log("cccam: connection closed to %s", remote_txt());
    n = -1;
  } else if (n < 4) {
    cs_log("cccam: packet to small (%d bytes)", n);
    n = -1;
  } else {
    // parse it and write it back, if we have received something of value
    cc_parse_msg(cbuf, n);
    memcpy(buf, cbuf, l);
  }

  NULLFREE(cbuf);

  pthread_mutex_unlock(&cc->lock);

  if (!is_server && (n==-1)) {
    cs_log("cccam: cycle connection");
    cc_cycle_connection();
    //cs_exit(1);
  }

  return(n);
}

static int cc_cli_connect(void)
{
  int handle, n;
  uint8 data[20];
  uint8 hash[SHA_DIGEST_LENGTH];
  uint8 buf[CC_MAXMSGSIZE];
  char pwd[64];
  struct cc_data *cc;

  if (reader[ridx].cc) NULLFREE(reader[ridx].cc);

  // init internals data struct
  cc = malloc(sizeof(struct cc_data));
  if (cc==NULL) {
    cs_log("cccam: cannot allocate memory");
    return -1;
  }
  reader[ridx].cc = cc;
  bzero(reader[ridx].cc, sizeof(struct cc_data));
  cc->cards = llist_create();

  cc->ecm_count = 0;

  // check cred config
  if(reader[ridx].device[0] == 0 || reader[ridx].r_pwd[0] == 0 ||
     reader[ridx].r_usr[0] == 0 || reader[ridx].r_port == 0)
    return -5;

  // connect
  handle = network_tcp_connection_open();
  if(handle < 0) return -1;

  // get init seed
  if((n = recv(handle, data, 16, MSG_WAITALL)) != 16) {
    cs_log("cccam: server does not return 16 bytes");
    network_tcp_connection_close(handle);
    return -2;
  }
  cs_ddump(data, 16, "cccam: server init seed:");

  cc_xor(data);  // XOR init bytes with 'CCcam'

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

  cc_cmd_send(hash, 20, MSG_NO_HEADER);   // send crypted hash to server

  bzero(buf, sizeof(buf));
  memcpy(buf, reader[ridx].r_usr, strlen(reader[ridx].r_usr));
  cs_ddump(buf, 20, "cccam: username '%s':", buf);
  cc_cmd_send(buf, 20, MSG_NO_HEADER);    // send usr '0' padded -> 20 bytes

  bzero(buf, sizeof(buf));
  bzero(pwd, sizeof(pwd));

  cs_debug("cccam: 'CCcam' xor");
  memcpy(buf, "CCcam", 5);
  strncpy(pwd, reader[ridx].r_pwd, 63);
  cc_crypt(&cc->block[ENCRYPT], (uint8 *)pwd, strlen(pwd), ENCRYPT);
  cc_cmd_send(buf, 6, MSG_NO_HEADER); // send 'CCcam' xor w/ pwd

  if ((n = recv(handle, data, 20, MSG_WAITALL)) != 20) {
    cs_log("cccam: login failed, pwd ack not received (n = %d)", n);
    return -2;
  }
  cc_crypt(&cc->block[DECRYPT], data, 20, DECRYPT);
  cs_ddump(data, 20, "cccam: pwd ack received:");

  if (memcmp(data, buf, 5)) {  // check server response
    cs_log("cccam: login failed, usr/pwd invalid");
    return -2;
  } else {
    cs_debug("cccam: login succeeded");
  }

  reader[ridx].tcp_connected = 1;
  reader[ridx].last_g = reader[ridx].last_s = time((time_t *)0);

  cs_debug("cccam: last_s=%d, last_g=%d", reader[ridx].last_s, reader[ridx].last_g);

  pfd=client[cs_idx].udp_fd;

  if (cc_send_cli_data()<=0) {
    cs_log("cccam: login failed, could not send client data");
    return -3;
  }

  pthread_mutex_init(&cc->lock, NULL);
  pthread_mutex_init(&cc->ecm_busy, NULL);

  reader[ridx].caid[0] = reader[ridx].ftab.filts[0].caid;
  reader[ridx].nprov = reader[ridx].ftab.filts[0].nprids;
  for (n=0; n<reader[ridx].nprov; n++) {
    reader[ridx].prid[n][0] = reader[ridx].ftab.filts[0].prids[n] << 24;
    reader[ridx].prid[n][1] = reader[ridx].ftab.filts[0].prids[n] << 16;
    reader[ridx].prid[n][2] = reader[ridx].ftab.filts[0].prids[n] << 8;
    reader[ridx].prid[n][3] = reader[ridx].ftab.filts[0].prids[n] & 0xff;
  }

  return 0;
}

static void cc_srv_report_cards()
{
  int j;
  uint id = 1, r, k;
  uint8 hop = 0, reshare;
  uint8 buf[CC_MAXMSGSIZE];
  struct cc_data *cc = client[cs_idx].cc;

  reshare = cfg->cc_reshare;

  for (r=0; r<CS_MAXREADER; r++) {
    if (reader[r].caid[0]) {
      bzero(buf, sizeof(buf));

      buf[0] = id >> 24;
      buf[1] = id >> 16;
      buf[2] = id >> 8;
      buf[3] = id & 0xff;
      buf[8] = reader[r].caid[0] >> 8;
      buf[9] = reader[r].caid[0] & 0xff;
      buf[10] = hop;
      buf[11] = reshare;
      buf[20] = reader[r].nprov;

      for (j=0; j<reader[r].nprov; j++) {
        memcpy(buf + 21 + (j*7), reader[r].prid[j]+1, 3);
      }

      buf[21 + (j*7)] = 1;
      memcpy(buf + 22 + (j*7), cc->node_id, 8);

      cc_cmd_send(buf, 30 + (j*7), MSG_NEW_CARD);

      id++;
    }

    if (reader[r].ftab.filts) {
      for (j=0; j<CS_MAXFILTERS; j++) {
        if (reader[r].ftab.filts[j].caid) {
          bzero(buf, sizeof(buf));

          buf[0] = id >> 24;
          buf[1] = id >> 16;
          buf[2] = id >> 8;
          buf[3] = id & 0xff;
          buf[8] = reader[r].ftab.filts[j].caid >> 8;
          buf[9] = reader[r].ftab.filts[j].caid & 0xff;
          buf[10] = hop;
          buf[11] = reshare;
          buf[20] = reader[r].ftab.filts[j].nprids;

          for (k=0; k<reader[r].ftab.filts[j].nprids; k++) {
            buf[21 + (k*7)] = reader[r].ftab.filts[j].prids[k] << 24;
            buf[22 + (k*7)] = reader[r].ftab.filts[j].prids[k] << 16;
            buf[23 + (k*7)] = reader[r].ftab.filts[j].prids[k] << 8;
            buf[24 + (k*7)] = reader[r].ftab.filts[j].prids[k] & 0xff;
          }

          buf[21 + (k*7)] = 1;
          memcpy(buf + 22 + (k*7), cc->node_id, 8);

          cc_cmd_send(buf, 30 + (k*7), MSG_NEW_CARD);

          id++;
        }
      }
    }
  }
}

static int cc_srv_connect()
{
  int i;
  uint seed;
  uint8 buf[CC_MAXMSGSIZE];
  uint8 data[16];
  char usr[20], pwd[20];
  struct s_auth *account;
  struct cc_data *cc;

  bzero(usr, sizeof(usr));
  bzero(pwd, sizeof(pwd));

  if (client[cs_idx].cc) NULLFREE(client[cs_idx].cc);

  // init internals data struct
  cc = malloc(sizeof(struct cc_data));
  if (cc==NULL) {
    cs_log("cccam: cannot allocate memory");
    return -1;
  }

  client[cs_idx].cc = cc;
  bzero(client[cs_idx].cc, sizeof(struct cc_data));

  // calc + send random seed
  seed = (unsigned int) time((time_t*)0);
  for(i=0; i<16; i++ ) data[i]=fast_rnd();
  send(client[cs_idx].udp_fd, data, 16, 0);

  cc_xor(data);  // XOR init bytes with 'CCcam'

  SHA_CTX ctx;
  SHA1_Init(&ctx);
  SHA1_Update(&ctx, data, 16);
  SHA1_Final(buf, &ctx);

  //initialisate crypto states
  /*
  init_crypt(&cc->block[ENCRYPT], buf, 20);
  crypto_state__decrypt(&cc->block[ENCRYPT], data, data2, 16);
  init_crypt(&cc->block[DECRYPT], data2, 16);
  crypto_state__encrypt(&cc->block[DECRYPT], buf, buf2, 20);*/

  cc_init_crypt(&cc->block[ENCRYPT], buf, 20);
  cc_crypt(&cc->block[ENCRYPT], data, 16, DECRYPT);
  cc_init_crypt(&cc->block[DECRYPT], data, 16);
  cc_crypt(&cc->block[DECRYPT], buf, 20, DECRYPT);

  if ((i=recv(pfd, buf, 20, MSG_WAITALL)) == 20) {
    cs_ddump(buf, 20, "cccam: recv:");
    cc_crypt(&cc->block[DECRYPT], buf, 20, DECRYPT);
    cs_ddump(buf, 20, "cccam: hash:");
  } else return -1;

  // receive username
  if ((i=recv(pfd, buf, 20, MSG_WAITALL)) == 20) {
    cc_crypt(&cc->block[DECRYPT], buf, 20, DECRYPT);
    cs_ddump(buf, 20, "cccam: username '%s':", buf);
    strncpy(usr, (char *)buf, sizeof(usr));
  } else return -1;

  for (account=cfg->account; account; account=account->next)
    if (strcmp(usr, account->usr) == 0) {
      strncpy(pwd, account->pwd, sizeof(pwd));
      break;
    }

  // receive passwd / 'CCcam'
  cc_crypt(&cc->block[DECRYPT], (uint8 *)pwd, strlen(pwd), DECRYPT);
  if ((i=recv(pfd, buf, 6, MSG_WAITALL)) == 6) {
    cc_crypt(&cc->block[DECRYPT], buf, 6, DECRYPT);
    cs_ddump(buf, 6, "cccam: pwd check '%s':", buf);
  } else return -1;

  cs_auth_client(account, NULL);
  //cs_auth_client((struct s_auth *)(-1), NULL);

  // send passwd ack
  bzero(buf, 20);
  memcpy(buf, "CCcam\0", 6);
  cs_ddump(buf, 20, "cccam: send ack:");
  cc_crypt(&cc->block[ENCRYPT], buf, 20, ENCRYPT);
  send(pfd, buf, 20, 0);

  // recv cli data
  bzero(buf,sizeof(buf));
  i = cc_msg_recv(buf);
  cs_ddump(buf, i, "cccam: cli data:");
  memcpy(cc->peer_node_id, buf+24, 8);
  cs_log("cccam: client '%s' (%s) running v%s (%s)", buf+4, cs_hexdump(0, cc->peer_node_id, 8), buf+33, buf+65);

  // send cli data ack
  cc_cmd_send(NULL, 0, MSG_CLI_DATA);

  if (cc_send_srv_data()<0) return -1;

  is_server = 1;

  // report cards
  cc_srv_report_cards();

  // check for clienttimeout, if timeout occurs try to send keepalive
  for(;;)
  {
    i=process_input(mbuf, sizeof(mbuf), cfg->cmaxidle);
     
    if (i == -9)
    {
      if (cc_cmd_send(NULL, 0, MSG_KEEPALIVE) > 0)
      {
        cs_debug("cccam: keepalive");
        i = 1;
      }
    }
     
    if (i <= 0)
    {
      break;
    }
  }

  cs_disconnect_client();

  return 0;
}

void cc_srv_init()
{
  pfd=client[cs_idx].udp_fd;
  //cc_auth_client(client[cs_idx].ip);
  cc_srv_connect();
}

int cc_cli_init()
{
  if (!reader[ridx].tcp_connected) {
    static struct sockaddr_in loc_sa;
    struct protoent *ptrp;
    int p_proto;

    pfd=0;
    if (reader[ridx].r_port<=0)
    {
      cs_log("cccam: invalid port %d for server %s", reader[ridx].r_port, reader[ridx].device);
      return(1);
    }
    if( (ptrp=getprotobyname("tcp")) )
      p_proto=ptrp->p_proto;
    else
      p_proto=6;

    client[cs_idx].ip=0;
    memset((char *)&loc_sa,0,sizeof(loc_sa));
    loc_sa.sin_family = AF_INET;
  #ifdef LALL
    if (cfg->serverip[0])
      loc_sa.sin_addr.s_addr = inet_addr(cfg->serverip);
    else
  #endif
      loc_sa.sin_addr.s_addr = INADDR_ANY;
    loc_sa.sin_port = htons(reader[ridx].l_port);

    if ((client[cs_idx].udp_fd=socket(PF_INET, SOCK_STREAM, p_proto))<0)
    {
      cs_log("cccam: Socket creation failed (errno=%d)", errno);
      cs_exit(1);
    }

  #ifdef SO_PRIORITY
    if (cfg->netprio)
      setsockopt(client[cs_idx].udp_fd, SOL_SOCKET, SO_PRIORITY,
                 (void *)&cfg->netprio, sizeof(ulong));
  #endif
    if (!reader[ridx].tcp_ito) {
      ulong keep_alive = reader[ridx].tcp_ito?1:0;
      setsockopt(client[cs_idx].udp_fd, SOL_SOCKET, SO_KEEPALIVE,
      (void *)&keep_alive, sizeof(ulong));
    }

    memset((char *)&client[cs_idx].udp_sa,0,sizeof(client[cs_idx].udp_sa));
    client[cs_idx].udp_sa.sin_family = AF_INET;
    client[cs_idx].udp_sa.sin_port = htons((u_short)reader[ridx].r_port);

    struct hostent *server;
    server = gethostbyname(reader[ridx].device);
    memmove((char *)&client[cs_idx].udp_sa.sin_addr.s_addr, (char *)server->h_addr, server->h_length);

    if (reader[ridx].tcp_rto <= 0) reader[ridx].tcp_rto = 60 * 60 * 10;  // timeout to 10 hours
    cs_debug("cccam: reconnect timeout set to: %d", reader[ridx].tcp_rto);
    if (!reader[ridx].cc_maxhop) reader[ridx].cc_maxhop = 10; // default maxhop to 10 if not configured

    cs_log("cccam: proxy %s:%d cccam v%s (%s), maxhop = %d (fd=%d, ridx=%d)",
            reader[ridx].device, reader[ridx].r_port, reader[ridx].cc_version,
            reader[ridx].cc_build, reader[ridx].cc_maxhop, client[cs_idx].udp_fd, ridx);

    cc_cli_connect();

    return(0);
  }
  return(-1);
}

void cc_cleanup(void)
{

}

void module_cccam(struct s_module *ph)
{
  strcpy(ph->desc, "cccam");
  ph->type=MOD_CONN_TCP;
  ph->logtxt = ", crypted";
  ph->watchdog=1;
  ph->recv=cc_recv;
  ph->cleanup=cc_cleanup;
  ph->c_multi=1;
  ph->c_init=cc_cli_init;
  ph->c_recv_chk=cc_recv_chk;
  ph->c_send_ecm=cc_send_ecm;
  ph->s_ip=cfg->cc_srvip;
  ph->s_handler=cc_srv_init;
  ph->send_dcw=cc_send_dcw;

  static PTAB ptab;
  ptab.ports[0].s_port = cfg->cc_port;
  ph->ptab = &ptab;
  ph->ptab->nports = 1;
}
