#include "globals.h"

#define CWS_NETMSGSIZE 272

#define CWS_FIRSTCMDNO 0xe0
typedef enum
{
  MSG_CLIENT_2_SERVER_LOGIN = CWS_FIRSTCMDNO,
  MSG_CLIENT_2_SERVER_LOGIN_ACK,
  MSG_CLIENT_2_SERVER_LOGIN_NAK,
  MSG_CARD_DATA_REQ,
  MSG_CARD_DATA,
  MSG_SERVER_2_CLIENT_NAME,
  MSG_SERVER_2_CLIENT_NAME_ACK,
  MSG_SERVER_2_CLIENT_NAME_NAK,
  MSG_SERVER_2_CLIENT_LOGIN,
  MSG_SERVER_2_CLIENT_LOGIN_ACK,
  MSG_SERVER_2_CLIENT_LOGIN_NAK,
  MSG_ADMIN,
  MSG_ADMIN_ACK,
  MSG_ADMIN_LOGIN,
  MSG_ADMIN_LOGIN_ACK,
  MSG_ADMIN_LOGIN_NAK,
  MSG_ADMIN_COMMAND,
  MSG_ADMIN_COMMAND_ACK,
  MSG_ADMIN_COMMAND_NAK,
  MSG_KEEPALIVE = CWS_FIRSTCMDNO + 0x1d
} net_msg_type_t;

typedef enum
{
  COMMTYPE_CLIENT,
  COMMTYPE_SERVER
} comm_type_t;

#define REQ_SIZE	2
static	uchar	*req=0;
static  int ncd_proto=NCD_AUTO;

static int network_message_send(int handle, uint16 *netMsgId, uint8 *buffer, 
                                int len, uint8 *deskey, comm_type_t commType,
                                ushort sid)
{
  uint8 netbuf[CWS_NETMSGSIZE];
  int head_size;
  head_size = (ncd_proto==NCD_524)?8:12;

  if (len < 3 || len + head_size > CWS_NETMSGSIZE || handle < 0) 
    return -1;
  buffer[1] = (buffer[1] & 0xf0) | (((len - 3) >> 8) & 0x0f);
  buffer[2] = (len - 3) & 0xff;
  memcpy(netbuf+head_size, buffer, len);
  len += head_size;
  if (netMsgId) { 
    switch(commType)
    {
    case COMMTYPE_CLIENT:
      (*netMsgId)++; 
     	break;
    case COMMTYPE_SERVER:
      if( *netMsgId == 0xFFFE ) *netMsgId = 0; // ??? 0xFFFF ?
      break;
    }
    netbuf[2] = (*netMsgId) >> 8; 
    netbuf[3] = (*netMsgId) & 0xff; 
  }
  else 
    netbuf[2] = netbuf[3] = 0;
  memset(netbuf+4, 0, (ncd_proto==NCD_524)?4:8);
  if( sid ) {
    netbuf[(ncd_proto==NCD_524)?6:4] = (uchar)(sid>>8); //sid
    netbuf[(ncd_proto==NCD_524)?7:5] = (uchar)(sid);
  }
  netbuf[0] = (len - 2) >> 8;
  netbuf[1] = (len - 2) & 0xff;
  cs_ddump(netbuf, len, "send %d bytes to %s", len, remote_txt());
  if ((len = des_encrypt(netbuf, len, deskey)) < 0) 
    return -1;
  netbuf[0] = (len - 2) >> 8;
  netbuf[1] = (len - 2) & 0xff;
  return send(handle, netbuf, len, 0);
}

static int network_message_receive(int handle, uint16 *netMsgId, uint8 *buffer, 
                                   uint8 *deskey, comm_type_t commType)
{
  int len, ncd_off, msgid;
  uint8 netbuf[CWS_NETMSGSIZE];
  int returnLen;

  if (!buffer || handle < 0) 
    return -1;
  len = recv(handle, netbuf, 2, 0);
  cs_debug("nmr(): len=%d, errno=%d", len, (len==-1)?errno:0);
  if (!len) {
    cs_debug("nmr: 1 return 0");
    network_tcp_connection_close(handle);
    return 0;
  }
  if (len != 2) {
    cs_debug("nmr: len!=2");
    network_tcp_connection_close(handle);
    return -1;
  }
  if (((netbuf[0] << 8) | netbuf[1]) > CWS_NETMSGSIZE - 2) {
    cs_debug("nmr: 1 return -1");
    return -1;
  }

  len = recv(handle, netbuf+2, (netbuf[0] << 8) | netbuf[1], 0);
  if (!len) {
    cs_debug("nmr: 2 return 0");
    return 0;
  }
  if (len != ((netbuf[0] << 8) | netbuf[1])) {
    cs_debug("nmr: 2 return -1");
    return -1;
  }
  len += 2;
  if ((len = des_decrypt(netbuf, len, deskey)) < 11 ) {  // 15(newcamd525) or 11 ???
    cs_debug("nmr: can't decrypt, invalid des key?");
    sleep(2);
    return -1;
  }
  //cs_ddump(netbuf, len, "nmr: decrypted data, len=%d", len);
  msgid = (netbuf[2] << 8) | netbuf[3];

  if( ncd_proto==NCD_AUTO ) {
    // auto detect
    int l5 = (((netbuf[13] & 0x0f) << 8) | netbuf[14]) + 3;
    int l4 = (((netbuf[9] & 0x0f) << 8) | netbuf[10]) + 3;
    
    if( (l5<=len-12) && ((netbuf[12]&0xF0)==0xE0 || (netbuf[12]&0xF0)==0x80) ) 
      ncd_proto = NCD_525;
    else if( (l4<=len-8) && ((netbuf[8]&0xF0)==0xE0 || (netbuf[9]&0xF0)==0x80) )
      ncd_proto = NCD_524;
    else {
      cs_debug("nmr: 4 return -1");
      return -1;
    }

    cs_debug("nmr: autodetect: newcamd52%d used", (ncd_proto==NCD_525)?5:4);
  }
  
  ncd_off=(ncd_proto==NCD_525)?4:0;

  returnLen = (((netbuf[9+ncd_off] & 0x0f) << 8) | netbuf[10+ncd_off]) + 3;
  if ( returnLen > (len-(8+ncd_off)) ) {
    cs_debug("nmr: 4 return -1");
    return -1;
  }

//  cs_ddump(netbuf, len, "nmr: decrypted data");
  if (netMsgId)
  {
    switch (commType)
    {
    case COMMTYPE_SERVER:
      *netMsgId = msgid;
      break;

    case COMMTYPE_CLIENT:
      //if (*netMsgId != ((netbuf[2] << 8) | netbuf[3])) {
        cs_debug("nmr: netMsgId=%d, from server=%d, ", *netMsgId, msgid );
        //return -2;
      //}
      break;

    default: 
      cs_debug("nmr: 5 return -1");
      return -1;
      break;
    }
  }
  switch(commType)
  {
  case COMMTYPE_SERVER:
    buffer[0]=(ncd_proto==NCD_525)?netbuf[4]:netbuf[6]; // sid
    buffer[1]=(ncd_proto==NCD_525)?netbuf[5]:netbuf[7];
  	break;
  case COMMTYPE_CLIENT:
    buffer[0]=netbuf[2]; // msgid
    buffer[1]=netbuf[3];
    break;
  }
  
  memcpy(buffer+2, netbuf+(8+ncd_off), returnLen);
  return returnLen+2;
}

static void network_cmd_no_data_send(int handle, uint16 *netMsgId, 
                                     net_msg_type_t cmd, uint8 *deskey, 
                                     comm_type_t commType)
{
  uint8 buffer[CWS_NETMSGSIZE];

  buffer[0] = cmd; buffer[1] = 0;
  network_message_send(handle, netMsgId, buffer, 3, deskey, commType, 0);
}

static int network_cmd_no_data_receive(int handle, uint16 *netMsgId, 
                                       uint8 *deskey, comm_type_t commType)
{
  uint8 buffer[CWS_NETMSGSIZE];

  if (network_message_receive(handle, netMsgId, buffer, deskey, commType) != 3+2) 
    return -1;
  return buffer[2];
}

void newcamd_reply_ka()
{
  if( !client[cs_idx].udp_fd )
  {
    cs_debug("invalid client fd=%d", client[cs_idx].udp_fd);
    return;
  }
  cs_debug("send keep_alive");
  network_cmd_no_data_send(client[cs_idx].udp_fd, &client[cs_idx].ncd_msgid, 
                           MSG_KEEPALIVE, client[cs_idx].ncd_skey, 
                           COMMTYPE_SERVER);
}

static int connect_newcamd_server() 
{
  int i;
  uint8 buf[CWS_NETMSGSIZE];
  uint8 keymod[14];
  uint8 *key;
  int handle=0;

  uint32 index;
  uint8 *passwdcrypt;
  uint8 login_answer;
  int bytes_received;

  if(reader[ridx].device[0] == 0 || reader[ridx].r_pwd[0] == 0 || 
     reader[ridx].r_usr[0] == 0 || reader[ridx].r_port == 0)
    return -5;

  // 1. Connect
  //
  handle = network_tcp_connection_open();
  if(handle < 0) return -1;
  
  // 2. Get init sequence
  //
  reader[ridx].ncd_msgid = 0;
  if( read(handle, keymod, sizeof(keymod)) != sizeof(keymod)) {
    cs_log("server does not return 14 bytes");
    network_tcp_connection_close(handle);
    return -2;
  }
  cs_ddump(keymod, 14, "server init sequence:");
  key = des_login_key_get(keymod, reader[ridx].ncd_key, 14);

  // 3. Send login info
  //
  index = 3;
  buf[0] = MSG_CLIENT_2_SERVER_LOGIN;
  buf[1] = 0;
  strcpy((char *)buf+index, reader[ridx].r_usr);
  passwdcrypt = (uint8*)__md5_crypt(reader[ridx].r_pwd, "$1$abcdefgh$");
  index += strlen(reader[ridx].r_usr)+1;
  strcpy((char *)buf+index, (const char *)passwdcrypt);

  //cs_debug("login to server %s:%d user=%s, pwd=%s, len=%d", reader[ridx].device,
  //          reader[ridx].r_port, reader[ridx].r_usr, reader[ridx].r_pwd,
  //          index+strlen(passwdcrypt)+1);
  network_message_send(handle, 0, buf, index+strlen((char *)passwdcrypt)+1, key, 
                       COMMTYPE_CLIENT, 0x8888);

  // 3.1 Get login answer
  //
  login_answer=network_cmd_no_data_receive(handle, &reader[ridx].ncd_msgid, 
                                           key, COMMTYPE_CLIENT);
  if( login_answer == MSG_CLIENT_2_SERVER_LOGIN_NAK )
  {
    cs_log("login failed for user '%s'", reader[ridx].r_usr);
    network_tcp_connection_close(handle);
    return -3;
  }
  if( login_answer != MSG_CLIENT_2_SERVER_LOGIN_ACK ) 
  {
    cs_log("expected MSG_CLIENT_2_SERVER_LOGIN_ACK (%02X), received %02X", 
             MSG_CLIENT_2_SERVER_LOGIN_ACK, login_answer);
    network_tcp_connection_close(handle);
    return -3;
  }

  // 4. Send MSG_CARD_DATE_REQ
  //
  key = des_login_key_get(reader[ridx].ncd_key, passwdcrypt, strlen((char *)passwdcrypt));

  network_cmd_no_data_send(handle, &reader[ridx].ncd_msgid, MSG_CARD_DATA_REQ, 
                           key, COMMTYPE_CLIENT);
  bytes_received = network_message_receive(handle, &reader[ridx].ncd_msgid, buf, 
                                           key, COMMTYPE_CLIENT);
  if( bytes_received < 16 || buf[2] != MSG_CARD_DATA ) {
    cs_log("expected MSG_CARD_DATA (%02X), received %02X", 
             MSG_CARD_DATA, buf[2]);
    network_tcp_connection_close(handle);
    return -4;
  }

  // 5. Parse CAID and PROVID(s)
  //
  reader[ridx].caid[0] = (ushort)((buf[4+2]<<8) | buf[5+2]);
  memcpy(&reader[ridx].hexserial, buf+6+2, 8);
  cs_log("Newcamd Server: %s:%d - UserID: %i", reader[ridx].device, reader[ridx].r_port, buf[3+2]);
  cs_log("CAID: %04X - UA: %02X%02X%02X%02X%02X%02X%02X%02X - Provider # %i", reader[ridx].caid[0], reader[ridx].hexserial[0], reader[ridx].hexserial[1], reader[ridx].hexserial[2], reader[ridx].hexserial[3], reader[ridx].hexserial[4], reader[ridx].hexserial[5], reader[ridx].hexserial[6], reader[ridx].hexserial[7], buf[14+2]);
  reader[ridx].nprov = buf[14+2];
  memset(reader[ridx].prid, 0xff, sizeof(reader[ridx].prid));
  for (i=0; i < reader[ridx].nprov; i++) {
    reader[ridx].availkeys[i][0] = 1;
    reader[ridx].prid[i][0] = buf[15+2+11*i];
    reader[ridx].prid[i][1] = buf[16+2+11*i];
    reader[ridx].prid[i][2] = buf[17+2+11*i];
    memcpy(&reader[ridx].sa[i], buf+22+2+11*i, 4); // the 4 first bytes are not read
    cs_log("Provider ID: %02X%02X%02X - SA: %02X%02X%02X%02X", reader[ridx].prid[i][1],  reader[ridx].prid[i][2], reader[ridx].prid[i][3], reader[ridx].sa[i][0], reader[ridx].sa[i][1], reader[ridx].sa[i][2], reader[ridx].sa[i][3]);
  }
  memcpy(reader[ridx].ncd_skey, key, 16);

  // 6. Set connected info
  //
  reader[ridx].tcp_connected=1;
  reader[ridx].last_g = reader[ridx].last_s = time((time_t *)0);

//  cs_log("last_s=%d, last_g=%d", reader[ridx].last_s, reader[ridx].last_g);
  
  // !!! Only after connect() on client[cs_idx].udp_fd (Linux)
  pfd=client[cs_idx].udp_fd;     

  return 0;
}

static int newcamd_connect()
{
  if (!reader[ridx].tcp_connected && connect_newcamd_server() < 0 ) return 0;
  if (!client[cs_idx].udp_fd) return 0;

  return 1;
}


static int newcamd_send(uchar *buf, int ml, ushort sid)
{
  if( !newcamd_connect() ) return(-1);

  //cs_ddump(buf, ml, "send %d bytes to %s", ml, remote_txt());
  return(network_message_send(client[cs_idx].udp_fd, &reader[ridx].ncd_msgid, 
         buf, ml, reader[ridx].ncd_skey, COMMTYPE_CLIENT, sid));
}

static int newcamd_recv(uchar *buf)
{
  int rc, rs;

  if (is_server)
  {
    rs=network_message_receive(client[cs_idx].udp_fd, 
                               &client[cs_idx].ncd_msgid, buf, 
                               client[cs_idx].ncd_skey, COMMTYPE_SERVER);
  }
  else
  {
    if (!client[cs_idx].udp_fd) return(-1);
    rs=network_message_receive(client[cs_idx].udp_fd, 
                               &reader[ridx].ncd_msgid,buf, 
                               reader[ridx].ncd_skey, COMMTYPE_CLIENT);
  }

  if (rs<5) rc=(-1);
  else rc=rs;

  cs_ddump(buf, rs, "received %d bytes from %s", rs, remote_txt());
  client[cs_idx].last = time((time_t *) 0);

  if( rc==-1 )
  {
  	if (rs > 0)
      cs_log("packet to small (%d bytes)", rs);
    else
      cs_log("Connection closed to %s", remote_txt());
  }
  return(rc);
}

static unsigned int seed;
static uchar fast_rnd() 
{ 
  unsigned int offset = 12923; 
  unsigned int multiplier = 4079; 

  seed = seed * multiplier + offset; 
  return (uchar)(seed % 0xFF); 
}

static FILTER mk_user_au_ftab(int au)
{
  int i,j,found;
  FILTER filt;
  FILTER *pufilt;

  filt.caid = reader[au].caid[0];
  if (filt.caid == 0) filt.caid = client[cs_idx].ftab.filts[0].caid;
  filt.nprids = 0;
  memset(&filt.prids, 0, sizeof(filt.prids));
  pufilt = &client[cs_idx].ftab.filts[0];

  for( i=0; i<reader[au].nprov; i++ )
    filt.prids[filt.nprids++] = b2i(3, &reader[au].prid[i][1]);

  for( i=0; i<pufilt->nprids; i++ )
  {
    for( j=found=0; (!found)&&(j<filt.nprids); j++ )
      if (pufilt->prids[i] == filt.prids[j]) found=1;
    if( !found )
      filt.prids[filt.nprids++] = pufilt->prids[i];
  }

  return filt;
}

static FILTER mk_user_ftab()
{
  FILTER *psfilt = 0;
  FILTER filt;
  int port_idx,i,j,k,c;

  filt.caid = 0;
  filt.nprids = 0;
  memset(&filt.prids, 0, sizeof(filt.prids));

  port_idx = client[cs_idx].port_idx;
  psfilt = &cfg->ncd_ptab.ports[port_idx].ftab.filts[0];

  // 1. CAID
  // search server CAID in client CAID
  for( c=i=0; i<CS_MAXCAIDTAB; i++ )
  {
    int ctab_caid;
    ctab_caid = client[cs_idx].ctab.caid[i]&client[cs_idx].ctab.mask[i];
    if( ctab_caid ) c++;

    if( psfilt->caid==ctab_caid )
    {
      filt.caid=ctab_caid;
      break;
    }
  }
  if( c && !filt.caid )
  {
    cs_log("no valid CAID found in CAID for user '%s'", client[cs_idx].usr);
    return filt;
  }

  // search CAID in client IDENT
  cs_debug("client[%d].%s nfilts=%d, filt.caid=%04X", cs_idx,
           client[cs_idx].usr, client[cs_idx].ftab.nfilts, filt.caid);

  if( !filt.caid && client[cs_idx].ftab.nfilts ) 
  {
    int fcaids;
    for( i=fcaids=0; i<client[cs_idx].ftab.nfilts; i++ )
    {
      ushort ucaid=client[cs_idx].ftab.filts[i].caid;
      if( ucaid ) fcaids++;
      if( ucaid && psfilt->caid==ucaid )
      {
        filt.caid = ucaid;
        break;
      }
    }
    if( fcaids==client[cs_idx].ftab.nfilts && !filt.caid ) 
    { 
      cs_log("no valid CAID found in IDENT for user '%s'", client[cs_idx].usr);
      //cs_disconnect_client();
      return filt;
    }
  }
  // empty client CAID - use server CAID
  if( !filt.caid ) filt.caid=psfilt->caid;

  // 2. PROVID
  if( !client[cs_idx].ftab.nfilts )
  {
    int r, add;
    for (i=0; i<psfilt->nprids; i++) {
      // use server PROVID(s) (and only those which are in user's groups)
      add = 0;
      for (r=0; !add && r<CS_MAXREADER; r++) {
	if (reader[r].grp & client[cs_idx].grp) {
	  if (!reader[r].ftab.nfilts) {
	    if (reader[r].typ & R_IS_NETWORK) add = 1;
	    for (j=0; !add && j<reader[r].nprov; j++)
	      if (b2i(3, &reader[r].prid[j][1]) == psfilt->prids[i]) add = 1;
	  } else {
	    for (j=0; !add && j<reader[r].ftab.nfilts; j++) {
	      ulong rcaid = reader[r].ftab.filts[j].caid;
	      if (!rcaid || rcaid == filt.caid) {
	        for (k=0; !add && k<reader[r].ftab.filts[j].nprids; k++)
	          if (reader[r].ftab.filts[j].prids[k] == psfilt->prids[i]) add = 1;
	      }
	    }
	  }
	}
      }
      if (add) filt.prids[filt.nprids++] = psfilt->prids[i];
    }
    return filt;
  }

  // search in client IDENT
    for( j=0; j<client[cs_idx].ftab.nfilts; j++ )
    {
      ulong ucaid = client[cs_idx].ftab.filts[j].caid;
      cs_debug("client caid #%d: %04X", j, ucaid);
      if( !ucaid || ucaid==filt.caid )
      {
      for (i=0; i<psfilt->nprids; i++)
      {
        cs_debug("search server provid #%d: %06X", i, psfilt->prids[i]);
        if( client[cs_idx].ftab.filts[j].nprids )
        {
          for( k=0; k<client[cs_idx].ftab.filts[j].nprids; k++ )
            if (client[cs_idx].ftab.filts[j].prids[k] == psfilt->prids[i])
              filt.prids[filt.nprids++]=client[cs_idx].ftab.filts[j].prids[k];
        } else {
          filt.prids[filt.nprids++] = psfilt->prids[i];
	  // allow server PROVID(s) if no PROVID(s) specified in IDENT
        }
      }
    }
  }
  
  if( !filt.nprids )
  {
    cs_log("no valid PROVID(s) found in CAID for user '%s'", client[cs_idx].usr);
    //cs_disconnect_client();
  }

  return filt;
}

static void newcamd_auth_client()
{
    int i, ok = 0;
    uchar *usr=NULL, *pwd=NULL;
    struct s_auth *account;
    uchar buf[14];
    uchar *key=0;
    uint8 *passwdcrypt = NULL;
    int au=0;

    // make random 14 bytes
    seed = (unsigned int) time((time_t*)0);
    for( i=0; i<14; i++ ) buf[i]=fast_rnd();

    // send init sequence
    send(client[cs_idx].udp_fd, buf, 14, 0);
    key = des_login_key_get(buf, cfg->ncd_key, 14);
    memcpy(client[cs_idx].ncd_skey, key, 16);
    client[cs_idx].ncd_msgid = 0;

    i=process_input(mbuf, sizeof(mbuf), cfg->cmaxidle);
    if ( i>0 )
        {
        if( mbuf[2] != MSG_CLIENT_2_SERVER_LOGIN )
            {
            cs_debug("expected MSG_CLIENT_2_SERVER_LOGIN (%02X), received %02X", 
            MSG_CLIENT_2_SERVER_LOGIN, mbuf[2]);
            if(req)
                {
                free(req);
                req=0;
                }
            cs_exit(0);
            }
        usr=mbuf+5;
        pwd=usr+strlen((char *)usr)+1;
        //cs_debug("usr=%s,pwd=%s", usr, pwd);
        }
    else
        {
        cs_debug("bad client login request");
        if(req)
            {
            free(req);
            req=0;
            }
        cs_exit(0);
        }

    for (ok=0, account=cfg->account; (usr) && (account) && (!ok); account=account->next) 
        {
        cs_debug("account->usr=%s", account->usr);
        if (strcmp((char *)usr, account->usr) == 0)
            {
            passwdcrypt = (uint8*)__md5_crypt(account->pwd, "$1$abcdefgh$");
            cs_debug("account->pwd=%s", passwdcrypt);
            if (strcmp((char *)pwd, (const char *)passwdcrypt) == 0)
                {
                client[cs_idx].crypted=1;
                cs_auth_client(account, NULL);
                cs_log("user %s authenticated successfully (using client %02X%02X)", usr, mbuf[0], mbuf[1]);
                ok = 1;
                break;
                }
            else
                {
                cs_log("user %s is providing a wrong password (using client %02X%02X)", usr, mbuf[0], mbuf[1]);
                }
            }
        }
	
    if (!ok && !account)
        {
        cs_log("user %s is trying to connect but doesnt exist ! (using client %02X%02X)", usr, mbuf[0], mbuf[1]);
        usr = 0;
        }

    if (ok)
        {
        au = client[cs_idx].au;
        if (au != -1)
            {
            if (cfg->ncd_ptab.ports[client[cs_idx].port_idx].ftab.filts[0].caid != reader[au].caid[0]
                &&  cfg->ncd_ptab.ports[client[cs_idx].port_idx].ftab.filts[0].caid != reader[au].ftab.filts[0].caid)
                {
                cs_log("AU wont be used on this port -> disable AU");
                au = -1;
                }
            else if (reader[au].card_system <= 0 && !(reader[au].typ & R_IS_CASCADING))
                {
                // Init for AU enabled card not finished, reject Client
                ok=0;
                au = -2; // Flag zur Logausgabe
                }
            else
                {
                cs_log("AU flag %d for user %s",au,usr);
                }
            }
        else
            {
            cs_log("AU disabled for user %s",usr);
            }
        }

    network_cmd_no_data_send(client[cs_idx].udp_fd, &client[cs_idx].ncd_msgid, 
              (ok)?MSG_CLIENT_2_SERVER_LOGIN_ACK:MSG_CLIENT_2_SERVER_LOGIN_NAK,
              client[cs_idx].ncd_skey, COMMTYPE_SERVER);

    // we need to add a test to make sure all card reader are ready before allowing more interaction with the user.
    // cfg->ncd_ptab.ports[client[cs_idx].port_idx].ftab.filts[0].caid old the CAID for this port
    // we need to check all ready for a match and check if they are ready
    // if they arent ready, disconnect the user.
    // it will reconnect in a few second.
    
    if (ok) 
        {
        FILTER pufilt_noau;
        FILTER *pufilt = 0;

        key = des_login_key_get(cfg->ncd_key, passwdcrypt, strlen((char *)passwdcrypt));
        memcpy(client[cs_idx].ncd_skey, key, 16);

        i=process_input(mbuf, sizeof(mbuf), cfg->cmaxidle);
        if( i>0 )
            {
            int j,len=15;
            if( mbuf[2] != MSG_CARD_DATA_REQ)
                {
                cs_debug("expected MSG_CARD_DATA_REQ (%02X), received %02X", 
                         MSG_CARD_DATA_REQ, mbuf[2]);
                if(req)
                    {
                    free(req); req=0;
                    }
                cs_exit(0);
                }

            client[cs_idx].ftab.filts[0] = mk_user_ftab();
            pufilt = &client[cs_idx].ftab.filts[0];
            
            if (au != -1)
                {
                unsigned char equal = 1;

                // remember user filter
                memcpy(&pufilt_noau, pufilt, sizeof(FILTER));

                client[cs_idx].ftab.filts[0] = mk_user_au_ftab(au);
                pufilt = &client[cs_idx].ftab.filts[0];

                // check if user filter CAID and PROVID is the same as CAID and PROVID of the AU reader
            
                if ((pufilt->caid != pufilt_noau.caid))
                    {
                    // cs_log("CAID server: %04X, CAID card: %04X, not equal, AU disabled",pufilt_noau.caid,pufilt->caid);
                    // equal = 0;
                    }
            
                for( j=0; equal && j<pufilt_noau.nprids && j<pufilt->nprids; j++)
                    {
                    if (pufilt->prids[j] != pufilt_noau.prids[j])
                        {
                        // cs_log("PROVID%d server: %04X, PROVID%d card: %04X, not equal, AU disabled",j,pufilt_noau.prids[j],j,pufilt->prids[j]);
                        //weird// equal = 0;
                        }
                    }  
                
                if (!equal)
                    {
                    // Not equal -> AU must set to disabled -> set back to user filter
                    memcpy(pufilt, &pufilt_noau, sizeof(FILTER));
                    au = -1;
                    }
                }

            client[cs_idx].ftab.nfilts = 1;
            mbuf[0] = MSG_CARD_DATA;
            mbuf[1] = 0x00;
            mbuf[2] = 0x00;

            // AU always set to true because some clients cannot handle "non-AU"
            // For security reason don't send the real hexserial (see below)
            // if a non-AU-client sends an EMM-request it will be thrown away
            // (see function "newcamd_process_emm")
            //mbuf[3] = 1;
            if( au!=-1 )
                mbuf[3] = 1;
            else
                mbuf[3] = cs_idx+10; // Unique user number

            mbuf[4] = (uchar)(pufilt->caid>>8);
            mbuf[5] = (uchar)(pufilt->caid);
            mbuf[6] = 0x00;
            mbuf[7] = 0x00;

            if (au != -1)
                {
                if (((pufilt->caid >> 8) == 0x17) || ((pufilt->caid >> 8) == 0x06))    // Betacrypt or Irdeto
                    {
                    // only 4 Bytes Hexserial for newcamd clients (Hex Base + Hex Serial)
                    // first 2 Byte always 00
                    mbuf[8]=0x00; //serial only 4 bytes
                    mbuf[9]=0x00; //serial only 4 bytes
                    // 1 Byte Hex Base (see reader-irdeto.c how this is stored in "reader[au].hexserial")
                    mbuf[10]=reader[au].hexserial[3];
                    // 3 Bytes Hex Serial (see reader-irdeto.c how this is stored in "reader[au].hexserial")
                    mbuf[11]=reader[au].hexserial[0];
                    mbuf[12]=reader[au].hexserial[1];
                    mbuf[13]=reader[au].hexserial[2];
                    }
                else if (((pufilt->caid >> 8) == 0x05) || ((pufilt->caid >> 8) == 0x0D))
                    {
                    mbuf[8] = 0x00;
                    mbuf[9] = reader[au].hexserial[0];
                    mbuf[10] = reader[au].hexserial[1];
                    mbuf[11] = reader[au].hexserial[2];
                    mbuf[12] = reader[au].hexserial[3];
                    mbuf[13] = reader[au].hexserial[4];
                    }
                else
                    {
                    mbuf[8] = reader[au].hexserial[0];
                    mbuf[9] = reader[au].hexserial[1];
                    mbuf[10] = reader[au].hexserial[2];
                    mbuf[11] = reader[au].hexserial[3];
                    mbuf[12] = reader[au].hexserial[4];
                    mbuf[13] = reader[au].hexserial[5];
                    }
                }
            else 
                {
                client[cs_idx].au = -1;
                mbuf[8] = 0x00;
                mbuf[9] = 0x00;
                mbuf[10] = 0x00;
                mbuf[11] = 0x00;
                mbuf[12] = 0x00;
                mbuf[13] = 0x00;
                // send "faked" Hexserial to client
                /*
                if (((pufilt->caid >= 0x1700) && (pufilt->caid <= 0x1799))  || // Betacrypt
                ((pufilt->caid >= 0x0600) && (pufilt->caid <= 0x0699)))    // Irdeto 
                    {
                    mbuf[6] = 0x00;
                    mbuf[7] = 0x00;
                    mbuf[8] = 0x00;
                    mbuf[9] = 0x00;
                    mbuf[10] = fast_rnd();
                    mbuf[11] = fast_rnd();
                    mbuf[12] = fast_rnd();
                    mbuf[13] = fast_rnd();
                    }
                 else
                    {
                    mbuf[6] = fast_rnd();
                    mbuf[7] = fast_rnd();
                    mbuf[8] = fast_rnd();
                    mbuf[9] = fast_rnd();
                    mbuf[10] = fast_rnd();
                    mbuf[11] = fast_rnd();
                    mbuf[12] = fast_rnd();
                    mbuf[13] = fast_rnd();
                    }
                */
                }

            mbuf[14] = pufilt->nprids;
            for( j=0; j<pufilt->nprids; j++) 
                {
                if ((pufilt->caid >= 0x0600) && (pufilt->caid <= 0x0699))    // Irdeto
                    {
                    mbuf[15+11*j] = 0;
                    mbuf[16+11*j] = 0;
                    mbuf[17+11*j] = j;
                    }
                else
                    {
                    mbuf[15+11*j] = (uchar)(pufilt->prids[j]>>16);
                    mbuf[16+11*j] = (uchar)(pufilt->prids[j]>>8);
                    mbuf[17+11*j] = (uchar)(pufilt->prids[j]);
                    }
                mbuf[18+11*j] = 0x00;
                mbuf[19+11*j] = 0x00;
                mbuf[20+11*j] = 0x00;
                mbuf[21+11*j] = 0x00;
                if( au!=-1 ) 
                    { // check if user provid from IDENT exists on card
                    int k, found;
                    ulong rprid;
                    found=0;
                    if( pufilt->caid==reader[au].caid[0] )
                        {
                        for( k=0; (k<reader[au].nprov); k++ )
                            {
                            rprid=b2i(3, &reader[au].prid[k][1]);
                            if( rprid==pufilt->prids[j] )
                                {
                                if ((pufilt->caid >= 0x0600) && (pufilt->caid <= 0x0699))    // Irdeto
                                    {
                                    mbuf[22+11*j] = reader[au].prid[k][0];
                                    mbuf[23+11*j] = reader[au].prid[k][1];
                                    mbuf[24+11*j] = reader[au].prid[k][2];
                                    mbuf[25+11*j] = reader[au].prid[k][3];
                                    }
                                else
                                    {
                                    mbuf[22+11*j] = reader[au].sa[k][0];
                                    mbuf[23+11*j] = reader[au].sa[k][1];
                                    mbuf[24+11*j] = reader[au].sa[k][2];
                                    mbuf[25+11*j] = reader[au].sa[k][3];
                                    }
                                found=1;
                                break;
                                }
                            }
                        }
                    if( !found ) 
                        {
                        mbuf[22+11*j] = 0x00;
                        mbuf[23+11*j] = 0x00;
                        mbuf[24+11*j] = 0x00;
                        mbuf[25+11*j] = 0x00;
                        }
                    }
                else 
                    {
                    if ((pufilt->caid >= 0x0600) && (pufilt->caid <= 0x0699))    // Irdeto
                        {
                        mbuf[22+11*j] = 0x00;
                        mbuf[23+11*j] = (uchar)(pufilt->prids[j]>>16);
                        mbuf[24+11*j] = (uchar)(pufilt->prids[j]>>8);
                        mbuf[25+11*j] = (uchar)(pufilt->prids[j]);
                        }
                    else
                        {
                        mbuf[22+11*j] = 0x00;
                        mbuf[23+11*j] = 0x00;
                        mbuf[24+11*j] = 0x00;
                        mbuf[25+11*j] = 0x00;
                        }
                    }
                len+=11;
                }

            if( network_message_send(client[cs_idx].udp_fd, &client[cs_idx].ncd_msgid,  mbuf, len, key, COMMTYPE_SERVER, 0 ) <0 )
                {
                if(req)
                    {
                    free(req);
                    req=0;
                    }
                cs_exit(0);
                }
            }
        }
    else
        {
        if (au == -2)
            cs_auth_client(0, "Init for AU enabled card not finished");
        else
            cs_auth_client(0, usr ? "login failure" : "no such user");
        if(req)
            {
            free(req);
            req=0;
            }
        cs_exit(0);
        }
}

static void newcamd_send_dcw(ECM_REQUEST *er)
{
  int len;
  ushort cl_msgid;
  
  if (!client[cs_idx].udp_fd) {
    cs_debug("ncd_send_dcw: error: client[cs_idx].udp_fd=%d", client[cs_idx].udp_fd);
    return;  
  }
  memcpy(&cl_msgid, req+(er->cpti*REQ_SIZE), 2);	// get client ncd_msgid + 0x8x
  mbuf[0] = er->ecm[0];
  if( client[cs_idx].ftab.filts[0].nprids==0 || er->rc>3 /*not found*/) 
  {
    len=3;
    mbuf[1] = mbuf[2] = 0x00;
  }
  else 
  {
    len = 19;
    mbuf[1] = mbuf[2] = 0x10;
    memcpy(mbuf+3, er->cw, 16);
  }

  cs_debug("ncd_send_dcw: er->cpti=%d, cl_msgid=%d, %02X", er->cpti, cl_msgid, mbuf[0]);

  network_message_send(client[cs_idx].udp_fd, &cl_msgid, mbuf, len, 
                       client[cs_idx].ncd_skey, COMMTYPE_SERVER, 0);
}

static void newcamd_process_ecm(uchar *buf)
{
  int pi;
  ECM_REQUEST *er;
  if (!(er=get_ecmtask())) {
    return;
  }
  // save client ncd_msgid
  memcpy(req+(er->cpti*REQ_SIZE), &client[cs_idx].ncd_msgid, 2);	
  cs_debug("ncd_process_ecm: er->cpti=%d, cl_msgid=%d, %02X", er->cpti, 
           client[cs_idx].ncd_msgid, buf[2]);
  er->l=buf[4]+3;
  er->srvid = (buf[0]<<8)|buf[1];
  er->caid = 0;
  pi = client[cs_idx].port_idx;
  if( cfg->ncd_ptab.nports && cfg->ncd_ptab.nports >= pi )
    er->caid=cfg->ncd_ptab.ports[pi].ftab.filts[0].caid;
  memcpy(er->ecm, buf+2, er->l);
  get_cw(er);
}

static void newcamd_process_emm(uchar *buf)
{
  int au, ok=1;
  ushort caid;

  memset(&epg, 0, sizeof(epg));
  au=client[cs_idx].au;

  // if client is not allowed to do AU just send back the OK-answer to
  // the client and do nothing else with the received data
  if ((au>=0) && (au<=CS_MAXREADER))
  {
  epg.l=buf[2]+3;
  caid = client[cs_idx].ftab.filts[0].caid;
  epg.caid[0] = (uchar)(caid>>8);
  epg.caid[1] = (uchar)(caid);
/*  if (caid == 0x0500)
  {
    ushort emm_head;

    emm_head = (buf[0]<<8) | buf[1];
    switch( emm_head )
    {
      case 0x8e70:  // EMM-S
        memcpy(epg.hexserial+1, buf+3, 4);
        epg.hexserial[4]=reader[au].hexserial[4];
        break;
      case 0x8870:  // EMM-U
      case 0x8c70:  // confidential ?
      default:
        cs_log("unsupported emm type: %04X", emm_head);
        ok=0;
    }
    if( !ok ) cs_log("only EMM-S supported");
  }
  else*/
    memcpy(epg.hexserial, reader[au].hexserial, 8);	// dummy
  
  memcpy(epg.emm, buf, epg.l);
  if( ok ) 
    do_emm(&epg);
  }

  // Should always send an answer to client (also if au is disabled),
  // some clients will disconnect if they get no answer
  buf[1] = 0x10;
  buf[2] = 0x00;
  network_message_send(client[cs_idx].udp_fd, &client[cs_idx].ncd_msgid, buf, 3, 
                       client[cs_idx].ncd_skey, COMMTYPE_SERVER, 0);
}

static void newcamd_server()
{
  int n;

  req=(uchar *)malloc(CS_MAXPENDING*REQ_SIZE);
  if (!req)
  {
    cs_log("Cannot allocate memory (errno=%d)", errno);
    cs_exit(1);
  }
  memset(req, 0, CS_MAXPENDING*REQ_SIZE);

  client[cs_idx].ncd_server = 1;
  cs_debug("client connected to %d port", 
            cfg->ncd_ptab.ports[client[cs_idx].port_idx].s_port);
  newcamd_auth_client();

  n=-9;
  while(n==-9)
  {	  
	  while ((n=process_input(mbuf, sizeof(mbuf), cfg->cmaxidle))>0)
	  {
	    switch(mbuf[2])
	    {
	      case 0x80:
	      case 0x81:
	        newcamd_process_ecm(mbuf);
	        break;
	      case MSG_KEEPALIVE:
	        newcamd_reply_ka();
	        break;
	      default:
	        if( mbuf[2]>0x81 && mbuf[2]<0x90 )
	          newcamd_process_emm(mbuf+2);
	        else
	          cs_debug("unknown command !");
	    }
	  }
		if(n==-9)
		{
	  		newcamd_reply_ka();
	  	}
	}
	
  if(req) { free(req); req=0;}

  cs_disconnect_client();
}

/*
*	client functions
*/

int newcamd_client_init()
{
  static struct	sockaddr_in loc_sa;
  struct protoent *ptrp;
  int p_proto;
  char ptxt[16];

  pfd=0;
  if (reader[ridx].r_port<=0)
  {
    cs_log("invalid port %d for server %s", reader[ridx].r_port, reader[ridx].device);
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
    cs_log("Socket creation failed (errno=%d)", errno);
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

  if (reader[ridx].l_port>0)
  {
    if (bind(client[cs_idx].udp_fd, (struct sockaddr *)&loc_sa, sizeof (loc_sa))<0)
    {
      cs_log("bind failed (errno=%d)", errno);
      close(client[cs_idx].udp_fd);
      return(1);
    }
    sprintf(ptxt, ", port=%d", reader[ridx].l_port);
  }
  else
    ptxt[0]='\0';

  memset((char *)&client[cs_idx].udp_sa,0,sizeof(client[cs_idx].udp_sa));
  client[cs_idx].udp_sa.sin_family = AF_INET;
  client[cs_idx].udp_sa.sin_port = htons((u_short)reader[ridx].r_port);

  ncd_proto = reader[ridx].ncd_proto;

  cs_log("proxy %s:%d newcamd52%d (fd=%d%s)",
          reader[ridx].device, reader[ridx].r_port,
          (ncd_proto==NCD_525)?5:4, client[cs_idx].udp_fd, ptxt);
  //pfd=client[cs_idx].udp_fd; // !!! we set it after connect() (linux)
  return(0);
}

static int newcamd_send_ecm(ECM_REQUEST *er, uchar *buf)
{
  //int rc=(-1);
  if (!client[cs_idx].udp_sa.sin_addr.s_addr)	// once resolved at least
    return(-1);

  // check server filters
  if( !newcamd_connect() ) return (-1);

  if( !chk_rsfilter(er, reader[ridx].ncd_disable_server_filt) ) return(-1);

  memcpy(buf, er->ecm, er->l);

  return((newcamd_send(buf, er->l, er->srvid)<1) ? (-1) : 0);
}

static int newcamd_recv_chk(uchar *dcw, int *rc, uchar *buf, int n)
{
  ushort idx; 

  if( n<21 )	// no cw, ignore others
    return(-1);
  *rc = 1;
  idx = (buf[0] << 8) | buf[1];
  memcpy(dcw, buf+5, 16);
  return(idx);
}

void module_newcamd(struct s_module *ph)
{
  strcpy(ph->desc, "newcamd");
  ph->type=MOD_CONN_TCP;
  ph->logtxt = ", crypted";
  ph->multi=1;
  ph->watchdog=1;
  ph->s_ip=cfg->ncd_srvip;
  ph->s_handler=newcamd_server;
  ph->recv=newcamd_recv;
  ph->send_dcw=newcamd_send_dcw;
  ph->ptab=&cfg->ncd_ptab;
  if( ph->ptab->nports==0 ) 
    ph->ptab->nports=1; // show disabled in log
  ph->c_multi=1;
  ph->c_init=newcamd_client_init;
  ph->c_recv_chk=newcamd_recv_chk;
  ph->c_send_ecm=newcamd_send_ecm;

}
