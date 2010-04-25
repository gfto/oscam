#include <string.h>
#include <stdlib.h>
#include "globals.h"
#include "module-cccam.h"
#include "module-obj-llist.h"

extern struct s_reader *reader;

int g_flag = 0;


static unsigned int seed;
static uchar fast_rnd()
{
  unsigned int offset = 12923;
  unsigned int multiplier = 4079;

  seed = seed * multiplier + offset;
  return (uchar)(seed % 0xFF);
}

static int cc_cli_init();

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
  cs_sleepms(100);
  close(pfd);
  pfd = 0;
  client[cs_idx].udp_fd = 0;
  cs_sleepms(100);
  cc_cli_init();
}

static int cc_msg_recv(uint8 *buf)
{
  int len;
  uint8 netbuf[CC_MAXMSGSIZE + 4];
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
  uint8 netbuf[len+4];
  struct cc_data *cc;

  if (reader[ridx].cc)
    cc = reader[ridx].cc;
  else
    cc = client[cs_idx].cc;

  memset(netbuf, 0, len+4);

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

  return n;
}

#define CC_DEFAULT_VERSION 1
static void cc_check_version (char *cc_version, char *cc_build, uint32 *cc_max_ecms)
{
  char *version[] = { "2.0.11", "2.1.1", "2.1.2", "2.1.3", "2.1.4", "" };
  char *build[] = { "2892", "2971", "3094", "3165", "3191", "" };
  uint32 max_ecms[] = { -1, -1, 60, 60, 60, 60 };
  int i;
  *cc_max_ecms = 60;
  if (strlen (cc_version) == 0) {
    memcpy (cc_version, version[CC_DEFAULT_VERSION], strlen (version[CC_DEFAULT_VERSION]));
    memcpy (cc_build, build[CC_DEFAULT_VERSION], strlen (build[CC_DEFAULT_VERSION]));
    *cc_max_ecms = max_ecms[CC_DEFAULT_VERSION];
    cs_debug ("cccam: auto version set: %s build: %s", cc_version, cc_build);
    return;
  }

  for (i = 0; strlen (version[i]); i++)
    if (!memcmp (cc_version, version[i], strlen (version[i]))) {
      memcpy (cc_build, build[i], strlen (build[i]));
      *cc_max_ecms = max_ecms[i];
      cs_debug ("cccam: auto build set for version: %s build: %s", cc_version, cc_build);
      break;
    }
}

static int cc_send_cli_data()
{
  int i;
  struct cc_data *cc = reader[ridx].cc;

  cs_debug("cccam: send client data");

  seed = (unsigned int) time((time_t*)0);
  for( i=0; i<8; i++ ) cc->node_id[i]=fast_rnd();

  uint8 buf[CC_MAXMSGSIZE];
  memset(buf, 0, CC_MAXMSGSIZE);

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
  memset(buf, 0, CC_MAXMSGSIZE);

  memcpy(buf, cc->node_id, 8 );
  cc_check_version ((char *) cfg->cc_version, (char *) cfg->cc_build, &cc->max_ecms);
  memcpy(buf + 8, cfg->cc_version, sizeof(reader[ridx].cc_version));   // cccam version (ascii)
  memcpy(buf + 40, cfg->cc_build, sizeof(reader[ridx].cc_build));       // build number (ascii)

  cs_log ("cccam: version: %s, build: %s nodeid: %s", cfg->cc_version, cfg->cc_build, cs_hexdump(0, cc->peer_node_id,8));

  return cc_cmd_send(buf, 0x48, MSG_SRV_DATA);
}

static int cc_get_nxt_ecm()
{
  int n, i;
  time_t t;
 // struct cc_data *cc = reader[ridx].cc;

  t=time(NULL);
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

  if(cc) cc->ecm_count++;

  if (!cc || (pfd < 1)) {
    if (er) {
      er->rc = 0;
      er->rcEx = 0x27;
      cs_log("cccam: server not init!");
      write_ecm_answer(&reader[ridx], fd_c2m, er);
    }
    return -1;
  }

  if (pthread_mutex_trylock(&cc->ecm_busy) == EBUSY) {
    cs_debug("cccam: ecm trylock: failed to get lock");
    return 0;
  } else {
    cs_debug("cccam: ecm trylock: got lock");
  }

  if ((n = cc_get_nxt_ecm()) < 0) {
    pthread_mutex_unlock(&cc->ecm_busy);
    return 0;   // no queued ecms
  }
  cur_er = &ecmtask[n];

  if (crc32(0, cur_er->ecm, cur_er->l) == cc->crc) cur_er->rc = 99;
  cc->crc = crc32(0, cur_er->ecm, cur_er->l);

  cs_debug("cccam: ecm crc = 0x%lx", cc->crc);

  if (cur_er->rc == 99) {
    pthread_mutex_unlock(&cc->ecm_busy);
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
 
      LLIST_ITR pitr;
      uint8 *prov = llist_itr_init(card->provs, &pitr);
      while (prov && !s) {
        if (!cur_er->prid || b2i(3, prov) == cur_er->prid) {  // provid matches
          if (((h < 0) || (card->hop <= h)) && (card->hop <= reader[ridx].cc_maxhop - 1)) {  // card is closer and doesn't exceed max hop
            cc->cur_card = card;
            h = card->hop;  // card has been matched
          }
        }
        prov = llist_itr_next(&pitr);
      }
    }
    card = llist_itr_next(&itr);
  }

  if (cc->cur_card) {
    uint8 ecmbuf[CC_MAXMSGSIZE];
    memset(ecmbuf, 0, CC_MAXMSGSIZE);

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
    reader[ridx].cc_currenthops = cc->cur_card->hop + 1;

    cs_log("cccam: sending ecm for sid %04x to card %08x, hop %d", cur_er->srvid, cc->cur_card->id, cc->cur_card->hop + 1);
    n = cc_cmd_send(ecmbuf, cur_er->l+13, MSG_CW_ECM);      // send ecm

  } else {
    n = -1;
    cs_log("cccam: no suitable card on server");
    cur_er->rc = 0;
    cur_er->rcEx = 0x27;
    //cur_er->rc = 1;
    //cur_er->rcEx = 0;
    cs_sleepms(300);
    write_ecm_answer(&reader[ridx], fd_c2m, cur_er);
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
        }
        card = llist_itr_next(&itr);
      }

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
          write_ecm_answer(&reader[ridx], fd_c2m, &ecmtask[i]);
        }
  }
  return n;

}
*/

//SS: Hack
static void cc_free_card(struct cc_card *card)
{
  if (!card)
    return;

  if (card->provs) 
    llist_destroy(card->provs);
  if (card->badsids)
    llist_destroy(card->badsids);
  free(card);
}

static void freeCaidInfos(LLIST *caid_infos) {
  if (caid_infos) {
    LLIST_ITR itr;
    struct cc_caid_info *caid_info = llist_itr_init(caid_infos, &itr);
    while (caid_info) {
      llist_destroy(caid_info->provs);
      caid_info = llist_itr_remove(&itr);
    }
    llist_destroy(caid_infos);
  }
}

static void cc_free(struct cc_data *cc)
{
  if (!cc)
    return;
  freeCaidInfos(cc->caid_infos);
  
  if (cc->cards) 
  {
    LLIST_ITR itr;
    struct cc_card *card = llist_itr_init(cc->cards, &itr);
    while (card)
    {
      cc_free_card(card);
      card = llist_itr_remove(&itr);
    }
    llist_destroy(cc->cards);
    cc->cards = NULL;
  }
  free(cc);
}

static int checkCaidInfos(int index, long *lastSize)
{
  char fname[40];
  sprintf(fname, "/tmp/caidinfos.%d", index);
  
  struct stat st;
  stat(fname, &st);
  long current_size = st.st_size;
  int result = (current_size != *lastSize);
  cs_debug("checkCaidInfos %d: cur=%ld last=%ld", index, current_size, *lastSize);
  *lastSize = current_size;
  return result;
}

/**
 * Saves caidinfos to /tmp/caidinfos.<readerindex>
 */
static void saveCaidInfos(int index, LLIST *caid_infos) {
  char fname[40];
  sprintf(fname, "/tmp/caidinfos.%d", index);
  FILE *file = fopen(fname, "w");
  LLIST_ITR itr;
  LLIST_ITR itr_prov;
  int caid_count = 0;
  int prov_count = 0;
  struct cc_caid_info *caid_info = llist_itr_init(caid_infos, &itr);
  while (caid_info) {
    fwrite(&caid_info->caid, 1, sizeof(caid_info->caid), file);
    caid_count++;
    int count = 0;    
    uint8 *prov = llist_itr_init(caid_info->provs, &itr_prov);
    while (prov) {
      count++;
      prov = llist_itr_next(&itr_prov);
    }
    fwrite(&count, 1, sizeof(count), file);
    prov = llist_itr_init(caid_info->provs, &itr_prov);
    while (prov) {
      fwrite(prov, 1, 3, file);
      prov = llist_itr_next(&itr_prov);
    }
    prov_count += count;
    
    caid_info = llist_itr_next(&itr);
  }
  fflush(file);
  fclose(file);
  cs_debug("saveCaidInfos %d: CAIDS: %d PROVIDERS: %d", index, caid_count, prov_count);
}

/**
 * Loads caidinfos from /tmp/caidinfos.<readerindex>
 */
static LLIST *loadCaidInfos(int index) {
  char fname[40];
  sprintf(fname, "/tmp/caidinfos.%d", index);
  FILE *file = fopen(fname, "r");
  if (!file)
    return NULL;

  int caid_count = 0;
  int prov_count = 0;
    
  uint16 caid = 0;
  LLIST *caid_infos = llist_create();
  do {
    if (fread(&caid, 1, sizeof(caid), file) <= 1)
      break;
    caid_count++;
    int count = 0;
    if (fread(&count, 1, sizeof(count), file) <= 1)
      break;
    struct cc_caid_info *caid_info = malloc(sizeof(struct cc_caid_info));
    caid_info->caid = caid;
    caid_info->provs = llist_create();
    uint8 *prov;
    while (count > 0) {
      prov = malloc(3);
      if (fread(prov, 1, 3, file) <= 0)
        break;
      llist_append(caid_info->provs, prov);
      count--;
      prov_count++;
    }
    llist_append(caid_infos, caid_info);
  } while (1);
  fclose(file);
  cs_debug("loadCaidInfos %d: CAIDS: %d PROVIDERS: %d", index, caid_count, prov_count);
  return caid_infos;
}

/**
 * Adds a new card to the caid_infos. Only caid/provs are used
 * Return 0 if caid already exists, 1 ist this is a new card or provider
 */
static int add_card_to_caidinfo(struct cc_data *cc, struct cc_card *card)
{
	int doSaveCaidInfos = 0;
	LLIST_ITR itr;
    struct cc_caid_info *caid_info = llist_itr_init(cc->caid_infos, &itr);
    while (caid_info) {
      if (caid_info->caid == card->caid)
        break;
      caid_info = llist_itr_next(&itr);
    }
    if (!caid_info) {
      caid_info = malloc(sizeof(struct cc_caid_info));
      caid_info->caid = card->caid;
      caid_info->provs = llist_create();
      llist_append(cc->caid_infos, caid_info);
      doSaveCaidInfos = 1;
    }
    if (caid_info->hop == 0 || caid_info->hop > card->hop)
    {
      caid_info->hop = card->hop;
      doSaveCaidInfos = 1;
    }

    uint8 *prov_info;
    uint8 *prov_card;
    LLIST_ITR itr_info;
    LLIST_ITR itr_card;
    prov_card = llist_itr_init(card->provs, &itr_card);
    while (prov_card) {
      prov_info = llist_itr_init(caid_info->provs, &itr_info);
      while (prov_info) {
        if (b2i(3, prov_info) == b2i(3, prov_card))
          break;
        prov_info = llist_itr_next(&itr_info);
      }
      if (!prov_info) {
        uint8 *prov_new = malloc(3);
        memcpy(prov_new, prov_card, 3);
        llist_append(caid_info->provs, prov_new);
        doSaveCaidInfos = 1;
      }
      prov_card = llist_itr_next(&itr_card);
    }
    return doSaveCaidInfos;
}

static void rebuild_caidinfos(struct cc_data *cc)
{
  freeCaidInfos(cc->caid_infos);
  cc->caid_infos = llist_create();
  LLIST_ITR itr;
  struct cc_card *card = llist_itr_init(cc->cards, &itr);
  while (card)
  {
	  add_card_to_caidinfo(cc, card);
	  card = llist_itr_next(&itr);
  }
  cc->needs_rebuild_caidinfo = 0;
}

//SS: Hack end

static cc_msg_type_t cc_parse_msg(uint8 *buf, int l)
{
  int ret = buf[1];
  struct cc_data *cc;

  if (reader[ridx].cc)
    cc = reader[ridx].cc;
  else
    cc = client[cs_idx].cc;

  cs_debug("parse_msg=%d", buf[1]);
  
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
      if (buf[14] > reader[ridx].cc_maxhop)
        break;
      struct cc_card *card = malloc(sizeof(struct cc_card));
      if (!card)
        break;

      memset(card, 0, sizeof(struct cc_card));

      card->provs = llist_create();
      card->badsids = llist_create();
      card->id = b2i(4, buf+4);
      card->sub_id = b2i (3, buf + 9);
      card->caid = b2i(2, buf+12);
      card->hop = buf[14];
      memcpy(card->key, buf+16, 8);

      cc->card_count++;
      cs_debug("cccam: card %08x added, caid %04x, hop %d, key %s, count %d",
          card->id, card->caid, card->hop, cs_hexdump(0, card->key, 8), cc->card_count);

      for (i = 0; i < buf[24]; i++) {  // providers
        uint8 *prov = malloc(3);
        if (prov) {
          memcpy(prov, buf+25+(7*i), 3);
          cs_debug("      prov %d, %06x", i+1, b2i(3, prov));

          llist_append(card->provs, prov);
        }
      }
      
      //SS: Hack:
      //Check if we have this card:
      LLIST_ITR itr;
      struct cc_card *old_card = llist_itr_init(cc->cards, &itr);
      while (old_card) {
        if (old_card->id == card->id) { //we already have this card, delete the old one
          cc->card_count--;
          cc_free_card(old_card);
          old_card = llist_itr_remove(&itr);
        }
        else
          old_card = llist_itr_next(&itr);
      }

      llist_append(cc->cards, card);
      if (!cc->cur_card)
        cc->cur_card = card;

      //build own card/provs list:
      cc->needs_rebuild_caidinfo++;
      if (cc->needs_rebuild_caidinfo > CC_CAIDINFO_REBUILD) {
    	rebuild_caidinfos(cc);
    	saveCaidInfos(ridx, cc->caid_infos);      }
      else
      {
    	if (cc->caid_infos && checkCaidInfos(ridx, &cc->caid_size)) {
          freeCaidInfos(cc->caid_infos);
          cc->caid_infos = NULL;
        }
        if (!cc->caid_infos)
          cc->caid_infos = loadCaidInfos(ridx);
        if (!cc->caid_infos)
          cc->caid_infos = llist_create();

        if (add_card_to_caidinfo(cc, card))
          saveCaidInfos(ridx, cc->caid_infos);
      }
      //SS: Hack end
    }
    break;
  case MSG_CARD_REMOVED:
  {
    struct cc_card *card;
    LLIST_ITR itr;

    int found = 0;
    card = llist_itr_init(cc->cards, &itr);
    while (card) {
      if (card->id == b2i(4, buf+4)) {// && card->sub_id == b2i (3, buf + 9)) {
        cc->card_count--;
        cs_debug("cccam: card %08x removed, caid %04x, count %d", card->id, card->caid, cc->card_count);
        found = 1;
        //SS: Fix card free:
        if (card == cc->cur_card)
          cc->cur_card = NULL;
        cc_free_card(card);
        //SS: Fix card free end

        card = llist_itr_remove(&itr);
        break;
      } else {
        card = llist_itr_next(&itr);
      }
    }
    if (!found)
      cs_debug("cccam: card %08x NOT FOUND?!?, caid %04x, count %d", card->id, card->caid, cc->card_count);
    else
      cc->needs_rebuild_caidinfo++;
  }
    break;
  case MSG_CW_NOK1:
  case MSG_CW_NOK2:
    cs_log("cccam: cw nok, sid = %x", cc->cur_sid);

    int f = 0;
    LLIST_ITR itr;
    if (cc->cur_card) {
      uint16 *sid = llist_itr_init(cc->cur_card->badsids, &itr);
      while (sid && !f) {
        if (*sid == cc->cur_sid) {
          f = 1;
        }
        sid = llist_itr_next(&itr);
      }

      if (!f) {
        sid = malloc(sizeof(uint16));
	    if (sid) {
          *sid = cc->cur_sid;

          sid = llist_append(cc->cur_card->badsids, sid);
          cs_debug("   added sid block for card %08x", cc->cur_card->id);
        }
      }
    }
    memset(cc->dcw, 0, 16);
    pthread_mutex_unlock(&cc->ecm_busy);
    cc_send_ecm(NULL, NULL);
    ret = 0;
    break;
  case MSG_CW_ECM:
    if (is_server) {
      ECM_REQUEST *er;

      cc->cur_card = malloc(sizeof(struct cc_card));
      if (!cc->cur_card)
	    break;
      memset(cc->cur_card, 0, sizeof(struct cc_card));

      cc->cur_card->id = buf[10] << 24 | buf[11] << 16 | buf[12] << 8 | buf[13];

      if ((er=get_ecmtask())) 
      {
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
    if (!reader[ridx].cc) {
      cs_debug("cccam: keepalive ack");
    } else { 
      cc_cmd_send(NULL, 0, MSG_KEEPALIVE); 
      cs_debug("cccam: keepalive");
    }
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

  if ((cc->max_ecms > 0) && (cc->ecm_count > cc->max_ecms))
    cc_cycle_connection();

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
  }

  return (-1);
}

static void cc_send_dcw(ECM_REQUEST *er)
{
  uchar buf[16];
  struct cc_data *cc;

  memset(buf, 0, sizeof(buf));

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

  if (reader[ridx].cc) { 
    cc_free(reader[ridx].cc);
    reader[ridx].cc = NULL;
  }

  // init internals data struct
  cc = malloc(sizeof(struct cc_data));
  if (cc==NULL) {
    cs_log("cccam: cannot allocate memory");
    return -1;
  }
  reader[ridx].cc = cc;
  memset(reader[ridx].cc, 0, sizeof(struct cc_data));
  cc->cards = llist_create();

  cc->ecm_count = 0;
  cc->max_ecms = reader[ridx].cc_max_ecms;

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
    network_tcp_connection_close(&reader[ridx], handle);
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

  memset(buf, 0, sizeof(buf));
  memcpy(buf, reader[ridx].r_usr, strlen(reader[ridx].r_usr));
  cs_ddump(buf, 20, "cccam: username '%s':", buf);
  cc_cmd_send(buf, 20, MSG_NO_HEADER);    // send usr '0' padded -> 20 bytes

  memset(buf, 0, sizeof(buf));
  memset(pwd, 0, sizeof(pwd));

  cs_debug("cccam: 'CCcam' xor");
  memcpy(buf, "CCcam", 5);
  strncpy(pwd, reader[ridx].r_pwd, sizeof(pwd)-1);
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
  reader[ridx].card_status = CARD_INSERTED;

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
		reader[ridx].availkeys[n][0] = 1;
    reader[ridx].prid[n][0] = reader[ridx].ftab.filts[0].prids[n] >> 24;
    reader[ridx].prid[n][1] = reader[ridx].ftab.filts[0].prids[n] >> 16;
    reader[ridx].prid[n][2] = reader[ridx].ftab.filts[0].prids[n] >> 8;
    reader[ridx].prid[n][3] = reader[ridx].ftab.filts[0].prids[n] & 0xff;
  }

  return 0;
}

static void cc_srv_report_cards()
{
    int j;
    uint id = 1, r, k;
    uint8 hop = 0, reshare, flt=0;
    uint8 buf[CC_MAXMSGSIZE];
    struct cc_data *cc = client[cs_idx].cc;

    reshare = cfg->cc_reshare;
    if (!reshare) return;
	
    for (r=0; r<CS_MAXREADER; r++)
    {
	flt = 0;
	if (/*!reader[r].caid[0] && */reader[r].ftab.filts)
	{
    	    for (j=0; j<CS_MAXFILTERS; j++)
    	    {
	        if (reader[r].ftab.filts[j].caid)
		{
		    memset(buf, 0, sizeof(buf));
    		    buf[0] = id >> 24;
		    buf[1] = id >> 16;
    		    buf[2] = id >> 8;
    		    buf[3] = id & 0xff;
		    //if (!reader[r].cc_id)
		    {
			buf[6] = 0x49 + r;
			buf[7] = 0x10 + j;
			reader[r].cc_id = b2i(3, buf+5);
		    }
		    //else
			//reader[r].cc_id++;
		    buf[5] = reader[r].cc_id >> 16;
		    buf[6] = reader[r].cc_id >> 8;
		    buf[7] = reader[r].cc_id & 0xFF;
		    buf[8] = reader[r].ftab.filts[j].caid >> 8;
		    buf[9] = reader[r].ftab.filts[j].caid & 0xff;
    		    buf[10] = hop;
		    buf[11] = reshare;
		    buf[20] = reader[r].ftab.filts[j].nprids;
		    //cs_log("Ident CCcam card report caid: %04X readr %s subid: %06X", reader[r].ftab.filts[j].caid, reader[r].label, reader[r].cc_id);
    		    for (k=0; k<reader[r].ftab.filts[j].nprids; k++)
		    {
    			buf[21 + (k*7)] = reader[r].ftab.filts[j].prids[k] >> 16;
    		        buf[22 + (k*7)] = reader[r].ftab.filts[j].prids[k] >> 8;
		        buf[23 + (k*7)] = reader[r].ftab.filts[j].prids[k] & 0xFF;
		        //cs_log("Ident CCcam card report provider: %02X%02X%02X", buf[21 + (k*7)]<<16, buf[22 + (k*7)], buf[23 + (k*7)]);
    		    }
		    buf[21 + (k*7)] = 1;
    		    memcpy(buf + 22 + (k*7), cc->node_id, 8);
/*
		    buf[21 + (k*7)+8] = 1;
    		    memcpy(buf + 22 + (k*7)+8, cc->node_id, 7);//8);
		    cc_cmd_send(buf, 30 + (k*7) + 9, MSG_NEW_CARD);
*/	  
		    cc_cmd_send(buf, 30 + (k*7), MSG_NEW_CARD);
    		    id++;
		    flt = 1;
		}
	    }
	}

	if (!reader[r].caid[0] && !flt)
	{
	    flt = 0;
	    for (j=0; j<CS_MAXCAIDTAB; j++)
	    {
		//cs_log("CAID map CCcam card report caid: %04X cmap: %04X", reader[r].ctab.caid[j], reader[r].ctab.cmap[j]);
		ushort lcaid = reader[r].ctab.caid[j];
		
		if (!lcaid || (lcaid == 0xFFFF))
		    lcaid = reader[r].ctab.cmap[j];
		    
		if (lcaid && (lcaid != 0xFFFF))
	        {
		    memset(buf, 0, sizeof(buf));
    		    buf[0] = id >> 24;
		    buf[1] = id >> 16;
    		    buf[2] = id >> 8;
    		    buf[3] = id & 0xff;
		    //if (!reader[r].cc_id)
		    {
			buf[6] = 0x48 + r;
			buf[7] = 0x63 + j;
			reader[r].cc_id = b2i(3, buf+5);
		    }
		    //else
			//reader[r].cc_id++;
		    buf[5] = reader[r].cc_id >> 16;
		    buf[6] = reader[r].cc_id >> 8;
		    buf[7] = reader[r].cc_id & 0xFF;
		    buf[8] = lcaid >> 8;
		    buf[9] = lcaid & 0xff;
    		    buf[10] = hop;
		    buf[11] = reshare;
		    buf[20] = 1;
		    //cs_log("CAID map CCcam card report caid: %04X nodeid: %s subid: %06X", lcaid, cs_hexdump(0, cc->peer_node_id, 8), reader[r].cc_id);
    		    //buf[21] = 0;
    		    //buf[22] = 0;
		    //buf[23] = 0;
		    buf[21+7] = 1;
    		    memcpy(buf + 22+7, cc->node_id, 8);
		    cc_cmd_send(buf, 30+7, MSG_NEW_CARD);
    		    id++;
	
		    flt = 1;
		}
	    }
	}

	if (reader[r].caid[0] && !flt)
        {
	    //cs_log("tcp_connected: %d card_status: %d ", reader[r].tcp_connected, reader[r].card_status);
	    memset(buf, 0, sizeof(buf));
	    buf[0] = id >> 24;
	    buf[1] = id >> 16;
	    buf[2] = id >> 8;
	    buf[3] = id & 0xff;
	    buf[5] = reader[r].cc_id >> 16;
	    buf[6] = reader[r].cc_id >> 8;
	    buf[7] = reader[r].cc_id & 0xFF;
	    if (!reader[r].cc_id)
	    {
		buf[6] = 0x99;
		buf[7] = 0x63 + r;
	    }
	    buf[8] = reader[r].caid[0] >> 8;
	    buf[9] = reader[r].caid[0] & 0xff;
	    buf[10] = hop;
	    buf[11] = reshare;
	    buf[20] = reader[r].nprov;
	    for (j=0; j<reader[r].nprov; j++)
	    {
		if (reader[r].card_status == CARD_INSERTED)
		    memcpy(buf + 21 + (j*7), reader[r].prid[j]+1, 3);
		else
		    memcpy(buf + 21 + (j*7), reader[r].prid[j], 3);
		//cs_log("Main CCcam card report provider: %02X%02X%02X%02X", buf[21+(j*7)], buf[22+(j*7)], buf[23+(j*7)], buf[24+(j*7)]);
	    }

	    buf[21 + (j*7)] = 1;
	    memcpy(buf + 22 + (j*7), cc->node_id, 8);
	    id++;

	    if ((reader[r].tcp_connected || reader[r].card_status == CARD_INSERTED) /*&& !reader[r].cc_id*/)
	    {
		reader[r].cc_id = b2i(3, buf+5);
		cc_cmd_send(buf, 30 + (j*7), MSG_NEW_CARD);
		//cs_log("CCcam: local card or newcamd reader  %02X report ADD caid: %02X%02X %d %d %s subid: %06X", buf[7], buf[8], buf[9], reader[r].card_status, reader[r].tcp_connected, reader[r].label, reader[r].cc_id);
	    }
	    else
		if ((reader[r].card_status != CARD_INSERTED) && (!reader[r].tcp_connected) && reader[r].cc_id)
		{
		    reader[r].cc_id = 0;
    		    cc_cmd_send(buf, 30 + (j*7), MSG_CARD_REMOVED);
		    //cs_log("CCcam: local card or newcamd reader %02X report REMOVE caid: %02X%02X %s", buf[7], buf[8], buf[9], reader[r].label);
		}
	}
	
	//SS: Hack:
	if (reader[r].typ == R_CCCAM && !flt) {
          if (cc->caid_infos && checkCaidInfos(r, &cc->caid_size)) {
            freeCaidInfos(cc->caid_infos);
            cc->caid_infos = NULL;
          }
          if (!cc->caid_infos)
            cc->caid_infos = loadCaidInfos(r);
          if (cc->caid_infos) {
            LLIST_ITR itr;
            struct cc_caid_info *caid_info = llist_itr_init(cc->caid_infos, &itr);
            while (caid_info) {
              memset(buf, 0, sizeof(buf));
	      buf[0] = id >> 24;
  	      buf[1] = id >> 16;
	      buf[2] = id >> 8;
	      buf[3] = id & 0xff;
  	      buf[5] = reader[r].cc_id >> 16;
	      buf[6] = reader[r].cc_id >> 8;
	      buf[7] = reader[r].cc_id & 0xFF;
	      if (!reader[r].cc_id)
	      {
  	        buf[6] = 0x99;
		buf[7] = 0x63 + r;
	      }
	      buf[8] = caid_info->caid >> 8;
	      buf[9] = caid_info->caid & 0xff;
	      buf[10] = caid_info->hop+1;
	      buf[11] = reshare;
	      int j = 0;
	      LLIST_ITR itr_prov;
	      uint8 *prov = llist_itr_init(caid_info->provs, &itr_prov);
  	      while (prov) {
  	        memcpy(buf + 21 + (j*7), prov, 3);
	        prov = llist_itr_next(&itr_prov);
	        j++;
	      }
	      buf[20] = j;

	      buf[21 + (j*7)] = 1;
	      memcpy(buf + 22 + (j*7), cc->node_id, 8);
	      id++;

              reader[r].cc_id = b2i(3, buf+5);
              cc_cmd_send(buf, 30 + (j*7), MSG_NEW_CARD);
              //cs_log("CCcam: local card or newcamd reader  %02X report ADD caid: %02X%02X %d %d %s subid: %06X", buf[7], buf[8], buf[9], reader[r].card_status, reader[r].tcp_connected, reader[r].label, reader[r].cc_id);
              caid_info = llist_itr_next(&itr);
            }       
	  }
        }
	//SS: Hack end
    }
}

static int cc_srv_connect()
{
  int i;
  ulong cmi;
  uint seed;
  uint8 buf[CC_MAXMSGSIZE];
  uint8 data[16];
  char usr[20], pwd[20];
  struct s_auth *account;
  struct cc_data *cc;

  memset(usr, 0, sizeof(usr));
  memset(pwd, 0, sizeof(pwd));

  //SS: Use last cc data for faster reconnects:
  cc = client[cs_idx].cc;
  if (!cc)
  {
    // init internals data struct
    cc = malloc(sizeof(struct cc_data));
    if (cc==NULL) {
      cs_log("cccam: cannot allocate memory");
      return -1;
    }

    client[cs_idx].cc = cc;
    memset(client[cs_idx].cc, 0, sizeof(struct cc_data));
  }

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

  client[cs_idx].crypted = 1;
  cs_auth_client(account, NULL);
  //cs_auth_client((struct s_auth *)(-1), NULL);

  // send passwd ack
  memset(buf, 0, 20);
  memcpy(buf, "CCcam\0", 6);
  cs_ddump(buf, 20, "cccam: send ack:");
  cc_crypt(&cc->block[ENCRYPT], buf, 20, ENCRYPT);
  send(pfd, buf, 20, 0);

  // recv cli data
  memset(buf, 0, sizeof(buf));
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

  cmi = 0;
  // check for clienttimeout, if timeout occurs try to send keepalive
  for (;;) {
    i=process_input(mbuf, sizeof(mbuf), 10); //cfg->cmaxidle);
    if (i == -9) {
      cc_srv_report_cards();
      cmi += 10;
      if (cmi >= cfg->cmaxidle) {
        cmi = 0;
        if (cc_cmd_send(NULL, 0, MSG_KEEPALIVE) > 0) {
          cs_debug("cccam: keepalive after maxidle is reached");
          i = 1;
        }
      }
    } else if (i <= 0) break;
  }

  cs_disconnect_client();

  return 0;
}

void cc_srv_init()
{
  pfd=client[cs_idx].udp_fd;
  //cc_auth_client(client[cs_idx].ip);
  if (cc_srv_connect() < 0)
    cs_log("cccam:%d failed errno: %d (%s)", __LINE__, errno, strerror(errno));
  cs_exit(1);
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

    cs_resolve();

    if (reader[ridx].tcp_rto <= 0) reader[ridx].tcp_rto = 60 * 60 * 10;  // timeout to 10 hours
    cs_debug("cccam: reconnect timeout set to: %d", reader[ridx].tcp_rto);
    if (!reader[ridx].cc_maxhop) reader[ridx].cc_maxhop = 5; // default maxhop to 5 if not configured
    cc_check_version (reader[ridx].cc_version, reader[ridx].cc_build, &reader[ridx].cc_max_ecms);
    cs_log ("proxy reader: %s (%s:%d) cccam v%s build %s, maxhop: %d", reader[ridx].label,
     reader[ridx].device, reader[ridx].r_port,
     reader[ridx].cc_version, reader[ridx].cc_build, reader[ridx].cc_maxhop);

    return(cc_cli_connect());
  }
  return(-1);
}

void cc_cleanup(void)
{
  cs_debug("cc_cleanup in");
  cc_free(reader[ridx].cc);
  reader[ridx].cc = NULL;
  cc_free(client[cs_idx].cc);
  client[cs_idx].cc = NULL;
  cs_debug("cc_cleanup out");
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
