#include "globals.h"
#if defined MODULE_CAMD35 || defined MODULE_CAMD35_TCP

#include "cscrypt/md5.h"
#include "module-cacheex.h"
#include "oscam-aes.h"
#include "oscam-chk.h"
#include "oscam-cache.h"
#include "oscam-client.h"
#include "oscam-ecm.h"
#include "oscam-emm.h"
#include "oscam-net.h"
#include "oscam-string.h"
#include "oscam-reader.h"

//CMD00 - ECM (request)
//CMD01 - ECM (response)
//CMD02 - EMM (in clientmode - set EMM, in server mode - EMM data) - obsolete
//CMD03 - ECM (cascading request)
//CMD04 - ECM (cascading response)
//CMD05 - EMM (emm request) send cardata/cardinfo to client
//CMD06 - EMM (incomming EMM in server mode)
//CMD19 - EMM (incomming EMM in server mode) only seen with caid 0x1830
//CMD08 - Stop sending requests to the server for current srvid,prvid,caid
//CMD44 - MPCS/OScam internal error notification
//CMD55 - connect_on_init/keepalive

//CMD0x3c - CACHEEX Cache-push filter request
//CMD0x3d - CACHEEX Cache-push id request
//CMD0x3e - CACHEEX Cache-push id answer
//CMD0x3f - CACHEEX cache-push

//used variable ncd_skey for storing remote node id: ncd_skey[0..7] : 8
//bytes node id ncd_skey[8] : 1=valid node id received

#define REQ_SIZE    584     // 512 + 20 + 0x34

static int32_t __camd35_send(struct s_client *cl, uchar *buf, int32_t buflen, int answer_awaited)
{
	int32_t l;
	unsigned char rbuf[REQ_SIZE + 15 + 4], *sbuf = rbuf + 4;

	if(!cl->udp_fd || !cl->crypted) { return (-1); }  //exit if no fd or aes key not set!

	//Fix ECM len > 255
	if(buflen <= 0)
		{ buflen = ((buf[0] == 0) ? (((buf[21] & 0x0f) << 8) | buf[22]) + 3 : buf[1]); }
	l = 20 + (((buf[0] == 3) || (buf[0] == 4)) ? 0x34 : 0) + buflen;
	memcpy(rbuf, cl->ucrc, 4);
	memcpy(sbuf, buf, l);
	memset(sbuf + l, 0xff, 15); // set unused space to 0xff for newer camd3's
	i2b_buf(4, crc32(0L, sbuf + 20, buflen), sbuf + 4);
	l = boundary(4, l);
	cs_ddump_mask(cl->typ == 'c' ? D_CLIENT : D_READER, sbuf, l, "send %d bytes to %s", l, username(cl));
	aes_encrypt_idx(&cl->aes_keys, sbuf, l);

	int32_t status;
	if(cl->is_udp)
	{
		status = sendto(cl->udp_fd, rbuf, l + 4, 0, (struct sockaddr *)&cl->udp_sa, cl->udp_sa_len);
		if(status == -1) { set_null_ip(&SIN_GET_ADDR(cl->udp_sa)); }
	}
	else
	{
		status = send(cl->udp_fd, rbuf, l + 4, 0);

		if(cl->typ == 'p' && cl->reader)
		{
			if(status == -1) { network_tcp_connection_close(cl->reader, "can't send"); }
		}
		else if(cl->typ == 'c')
		{
			if(status == -1) { cs_disconnect_client(cl); }
		}
	}
	if(status != -1)
	{
		if(cl->reader && answer_awaited)
		{
			cl->reader->last_s = time(NULL);
		}
		if(cl->reader && !answer_awaited)
		{
			cl->reader->last_s = cl->reader->last_g = time(NULL);
		}
		cl->last = time(NULL);

	}
	return status;
}

static int32_t camd35_send(struct s_client *cl, uchar *buf, int32_t buflen)
{
	// send command and set sending time because we await response
	return __camd35_send(cl, buf, buflen, 1);
}

static int32_t camd35_send_without_timeout(struct s_client *cl, uchar *buf, int32_t buflen)
{
	// send command and do NOT set sending time because we DON'T await response
	return __camd35_send(cl, buf, buflen, 0);
}

static int32_t camd35_auth_client(struct s_client *cl, uchar *ucrc)
{
	int32_t rc = 1;
	uint32_t crc;
	struct s_auth *account;
	unsigned char md5tmp[MD5_DIGEST_LENGTH];

	if(cl->upwd[0])
		{ return (memcmp(cl->ucrc, ucrc, 4) ? 1 : 0); }
	cl->crypted = 1;
	crc = (((ucrc[0] << 24) | (ucrc[1] << 16) | (ucrc[2] << 8) | ucrc[3]) & 0xffffffffL);
	for(account = cfg.account; (account) && (!cl->upwd[0]); account = account->next)
		if(crc == crc32(0L, MD5((unsigned char *)account->usr, strlen(account->usr), md5tmp), MD5_DIGEST_LENGTH))
		{
			rc = cs_auth_client(cl, account, NULL);
			if(!rc)
			{
				memcpy(cl->ucrc, ucrc, 4);
				cs_strncpy((char *)cl->upwd, account->pwd, sizeof(cl->upwd));
				aes_set_key(&cl->aes_keys, (char *) MD5(cl->upwd, strlen((char *)cl->upwd), md5tmp));
				return 0;
			}
		}
	return (rc);
}

static int32_t camd35_recv(struct s_client *client, uchar *buf, int32_t l)
{
	int32_t rc, s, rs, n = 0, buflen = 0, len = 0;
	for(rc = rs = s = 0; !rc; s++)
	{
		switch(s)
		{
		case 0:
			if(!client->udp_fd) { return (-9); }
			if(client->is_udp && client->typ == 'c')
			{
				rs = recv_from_udpipe(buf);
			}
			else
			{
				//read minimum packet size (4 byte ucrc + 32 byte data) to detect packet size (tcp only)

				//rs = recv(client->udp_fd, buf, client->is_udp ? l : 36, 0);
				if(client->is_udp){
					while (1){
					rs = recv(client->udp_fd, buf, l, 0);
						if (rs < 0){
							if(errno == EINTR) { continue; }  // try again in case of interrupt
							if(errno == EAGAIN) { continue; }  //EAGAIN needs select procedure again
							cs_debug_mask(client->typ == 'c' ? D_CLIENT : D_READER, "ERROR: %s (errno=%d %s)", __func__, errno, strerror(errno));
							break;
						}else {break;}
					}
				}else{
					int32_t tot=36, readed=0;
					rs = 0;
					do
					{
						readed = recv(client->udp_fd, buf+rs, tot, 0);
						if (readed < 0){
							if(errno == EINTR) { continue; }  // try again in case of interrupt
							if(errno == EAGAIN) { continue; }  //EAGAIN needs select procedure again
							cs_debug_mask(client->typ == 'c' ? D_CLIENT : D_READER, "ERROR: %s (errno=%d %s)", __func__, errno, strerror(errno));
							break;
						}
						if (readed == 0){ // nothing to read left!
							break;
						}
						if (readed > 0){ // received something, add it!
							tot-=readed;
						rs+=readed;
						}
					}
					while(tot!=0);
				}

			}
			if(rs < 36)
			{
				rc = -1;
				goto out;
			}
			break;
		case 1:
			switch(camd35_auth_client(client, buf))
			{
			case  0:
				break;  // ok
			case  1:
				rc = -2;
				break; // unknown user
			default:
				rc = -9;
				break; // error's from cs_auth()
			}
			memmove(buf, buf + 4, rs -= 4);
			break;
		case 2:
			aes_decrypt(&client->aes_keys, buf, rs);
			if(rs != boundary(4, rs))
				cs_debug_mask(client->typ == 'c' ? D_CLIENT : D_READER,
							  "WARNING: packet size has wrong decryption boundary");

			n = (buf[0] == 3) ? 0x34 : 0;

			//Fix for ECM request size > 255 (use ecm length field)
			if(buf[0] == 0)
				{ buflen = (((buf[21] & 0x0f) << 8) | buf[22]) + 3; }
			else if(buf[0] == 0x3d || buf[0] == 0x3e || buf[0] == 0x3f)  //cacheex-push
				{ buflen = buf[1] | (buf[2] << 8); }
			else
				{ buflen = buf[1]; }

			n = boundary(4, n + 20 + buflen);
			if(!(client->is_udp && client->typ == 'c') && (rs < n) && ((n - 32) > 0))
			{

				//len = recv(client->udp_fd, buf+32, n-32, 0); // read the rest of the packet
				int32_t tot=n-32, readed=0;
				len = 0;
				do{
					readed = recv(client->udp_fd, buf+32+len, tot, 0); // read the rest of the packet
					if (readed < 0){
						if(errno == EINTR) { continue; }  // try again in case of interrupt
						if(errno == EAGAIN) { continue; }  //EAGAIN needs select procedure again
						cs_debug_mask(client->typ == 'c' ? D_CLIENT : D_READER, "ERROR: %s (errno=%d %s)", __func__, errno, strerror(errno));
						break;
					}
					if (readed == 0){ // nothing to read left!
						break;
					}
					if (readed > 0){ // received something, add it!
					tot-=readed;
					len+=readed;
					}
				}
				while(tot!=0);


				if(len > 0)
				{
					rs += len;
					aes_decrypt(&client->aes_keys, buf + 32, len);
				}
				if(len < 0)
				{
					rc = -1;
					goto out;
				}
			}

			cs_ddump_mask(client->typ == 'c' ? D_CLIENT : D_READER,
						  buf, rs, "received %d bytes from %s", rs, remote_txt());

			if(n < rs)
				cs_debug_mask(client->typ == 'c' ? D_CLIENT : D_READER,
							  "ignoring %d bytes of garbage", rs - n);
			else if(n > rs) { rc = -3; }
			break;
		case 3:
			if(crc32(0L, buf + 20, buflen) != b2i(4, buf + 4)) { rc = -4; }
			if(!rc) { rc = n; }
			break;
		}
	}

out:
	if((rs > 0) && ((rc == -1) || (rc == -2)))
	{
		cs_ddump_mask(client->typ == 'c' ? D_CLIENT : D_READER, buf, rs,
					  "received %d bytes from %s (native)", rs, remote_txt());
	}
	if(rc >= 0) { client->last = time(NULL); }  // last client action is now
	switch(rc)
	{
		//case 0:   break;
	case -1:
		cs_log("packet is too small (received %d bytes, expected %d bytes)", rs, l);
		break;
	case -2:
		if(cs_auth_client(client, 0, "unknown user"))
			{ cs_disconnect_client(client); }
		break;
	case -3:
		cs_log("incomplete request !");
		break;
	case -4:
		cs_log("checksum error (wrong password ?)");
		break;
		//default:  cs_debug_mask(D_TRACE, "camd35_recv returns rc=%d", rc); break;
	}

	return (rc);
}

/*
 *  server functions
 */

static void camd35_request_emm(ECM_REQUEST *er)
{
	int32_t i;
	time_t now;
	uchar mbuf[1024];
	struct s_client *cl = cur_client();
	struct s_reader *aureader = NULL, *rdr = NULL;

	if(er->selected_reader && !er->selected_reader->audisabled && ll_contains(cl->aureader_list, er->selected_reader))
		{ aureader = er->selected_reader; }

	if(!aureader && cl->aureader_list)
	{
		LL_ITER itr = ll_iter_create(cl->aureader_list);
		while((rdr = ll_iter_next(&itr)))
		{
			if(emm_reader_match(rdr, er->caid, er->prid))
			{
				aureader = rdr;
				break;
			}
		}
	}

	if(!aureader)
		{ return; }  // TODO

	uint16_t au_caid = aureader->caid;

	// Bulcrypt has 2 caids and aureader->caid can't be used.
    // Use ECM_REQUEST caid for AU.
	if(!au_caid && (er->caid == 0x5581 || er->caid == 0x4aee))
		{ au_caid = er->caid; }

	time(&now);
	if(!memcmp(cl->lastserial, aureader->hexserial, 8))
		if(abs(now - cl->last) < 180) { return; }

	memcpy(cl->lastserial, aureader->hexserial, 8);
	cl->last = now;

	if(au_caid)
	{
		cl->disable_counter = 0;
		cs_log("%s emm-request sent (reader=%s, caid=%04X, auprovid=%06X)",
			   username(cur_client()), aureader->label, au_caid,
			   aureader->auprovid ? aureader->auprovid : b2i(4, aureader->prid[0]));
	}
	else if(cl->disable_counter > 2)
		{ return; }
	else
		{ cl->disable_counter++; }

	memset(mbuf, 0, sizeof(mbuf));
	mbuf[2] = mbuf[3] = 0xff;           // must not be zero
	i2b_buf(2, er->srvid, mbuf + 8);

	//override request provid with auprovid if set in CMD05
	if(aureader->auprovid)
	{
		if(aureader->auprovid != er->prid)
			{ i2b_buf(4, aureader->auprovid, mbuf + 12); }
		else
			{ i2b_buf(4, er->prid, mbuf + 12); }
	}
	else
	{
		i2b_buf(4, er->prid, mbuf + 12);
	}

	i2b_buf(2, er->pid, mbuf + 16);
	mbuf[0] = 5;
	mbuf[1] = 111;
	if(au_caid)
	{
		mbuf[39] = 1;                           // no. caids
		mbuf[20] = au_caid >> 8;        // caid's (max 8)
		mbuf[21] = au_caid & 0xff;
		memcpy(mbuf + 40, aureader->hexserial, 6);  // serial now 6 bytes
		mbuf[47] = aureader->nprov;
		for(i = 0; i < aureader->nprov; i++)
		{
			if((au_caid >= 0x1700 && au_caid <= 0x1799)  ||  // Betacrypt
					(au_caid >= 0x0600 && au_caid <= 0x0699))    // Irdeto (don't know if this is correct, cause I don't own a IRDETO-Card)
			{
				mbuf[48 + (i * 5)] = aureader->prid[i][0];
				memcpy(&mbuf[50 + (i * 5)], &aureader->prid[i][1], 3);
			}
			else
			{
				mbuf[48 + (i * 5)] = aureader->prid[i][2];
				mbuf[49 + (i * 5)] = aureader->prid[i][3];
				memcpy(&mbuf[50 + (i * 5)], &aureader->sa[i][0], 4); // for conax we need at least 4 Bytes
			}
		}
		//we think client/server protocols should deliver all information, and only readers should discard EMM
		mbuf[128] = (aureader->blockemm & EMM_GLOBAL && !(aureader->saveemm & EMM_GLOBAL)) ? 0 : 1;
		mbuf[129] = (aureader->blockemm & EMM_SHARED && !(aureader->saveemm & EMM_SHARED)) ? 0 : 1;
		mbuf[130] = (aureader->blockemm & EMM_UNIQUE && !(aureader->saveemm & EMM_UNIQUE)) ? 0 : 1;
		mbuf[127] = (aureader->blockemm & EMM_UNKNOWN && !(aureader->saveemm & EMM_UNKNOWN)) ? 0 : 1;
	}
	else        // disable emm
		{ mbuf[20] = mbuf[39] = mbuf[40] = mbuf[47] = mbuf[49] = 1; }

	memcpy(mbuf + 10, mbuf + 20, 2);
	camd35_send(cl, mbuf, 0);       // send with data-len 111 for camd3 > 3.890
	mbuf[1]++;
	camd35_send(cl, mbuf, 0);       // send with data-len 112 for camd3 < 3.890
}

static void camd35_send_dcw(struct s_client *client, ECM_REQUEST *er)
{
	uchar *buf;
	buf = er->src_data; // get orig request

	if(!buf)
	{
		cs_log("%s: src_data missing.",client->reader->ph.desc);
		return;
	}

	if(er->rc == E_INVALID && !client->c35_suppresscmd08)  //send normal CMD08
	{
		buf[0] = 0x08;
		buf[1] = 2;
		memset(buf + 20, 0, buf[1]);
		buf[22] = er->rc; //put rc in byte 22 - hopefully don't break legacy camd3
	}
	else if(er->rc == E_STOPPED)  //send sleep CMD08
	{
		buf[0] = 0x08;
		buf[1] = 2;
		buf[20] = 0;
		buf[21] = 0xFF;
		cs_log("%s stop request send", client->account->usr);
	}
	else
	{
		// Send CW
		if((er->rc < E_NOTFOUND) || (er->rc == E_FAKE))
		{
			if(buf[0] == 3)
				{ memmove(buf + 20 + 16, buf + 20 + buf[1], 0x34); }
			buf[0]++;
			buf[1] = 16;
#ifdef CS_CACHEEX
			if(((client->typ == 'c' && client->account && client->account->cacheex.mode) 
				|| ((client->typ == 'p' || client->typ == 'r') && (client->reader && client->reader->cacheex.mode)))
				&& er->cwc_cycletime && er->cwc_next_cw_cycle < 2)  // ce1
			{
				buf[18] = er->cwc_cycletime; // contains cwc stage3 cycletime
				if(er->cwc_next_cw_cycle == 1)
				{ buf[18] = (buf[18] | 0x80); } // set bit 8 to high

				if(client->typ == 'c' && client->account && client->account->cacheex.mode)
					{ client->account->cwc_info++; }
				else if((client->typ == 'p' || client->typ == 'r') && (client->reader && client->reader->cacheex.mode))
					{ client->cwc_info++; }
				cs_debug_mask(D_CWC, "CWC (CE1) push to %s (camd3) cycletime: %isek - nextcwcycle: CW%i for %04X:%06X:%04X", username(client), er->cwc_cycletime, er->cwc_next_cw_cycle, er->caid, er->prid, er->srvid);
				buf[19] = er->ecm[0];
			} 
#endif
			memcpy(buf + 20, er->cw, buf[1]);
		}
		else
		{
			// Send old CMD44 to prevent cascading problems with older mpcs/oscam versions
			buf[0] = 0x44;
			buf[1] = 0;
		}
	}
	camd35_send(client, buf, 0);
	camd35_request_emm(er);
}

static void camd35_process_ecm(uchar *buf, int buflen)
{
	ECM_REQUEST *er;
	if(!buf || buflen < 23)
		{ return; }
	uint16_t ecmlen = (((buf[21] & 0x0f) << 8) | buf[22]) + 3;
	if(ecmlen + 20 > buflen)
		{ return; }
	if(!(er = get_ecmtask()))
		{ return; }
	//  er->l = buf[1];
	//fix ECM LEN issue
	er->ecmlen = ecmlen;
	if(!cs_malloc(&er->src_data, 0x34 + 20 + er->ecmlen))
		{ return; }
	memcpy(er->src_data, buf, 0x34 + 20 + er->ecmlen);  // save request
	er->srvid = b2i(2, buf + 8);
	er->caid = b2i(2, buf + 10);
	er->prid = b2i(4, buf + 12);
	//er->pid  = b2i(2, buf+16); value is ecmtask idx see camd35_recv_chk 941
	memcpy(er->ecm, buf + 20, er->ecmlen);
	get_cw(cur_client(), er);
}

static void camd35_process_emm(uchar *buf, int buflen, int emmlen)
{
	EMM_PACKET epg;
	if(!buf || buflen < 20 || emmlen + 20 > buflen)
		{ return; }
	memset(&epg, 0, sizeof(epg));
	epg.emmlen = emmlen;
	memcpy(epg.caid, buf + 10, 2);
	memcpy(epg.provid, buf + 12 , 4);
	memcpy(epg.emm, buf + 20, epg.emmlen);
	do_emm(cur_client(), &epg);
}

static int32_t tcp_connect(struct s_client *cl)
{
	if(cl->is_udp)    // check for udp client
	{
		if(!IP_ISSET(SIN_GET_ADDR(cl->udp_sa)))   // check ip is set
		{
			if(!(hostResolve(cl->reader)))   // no ip -> try to resolve ip of client
			{
				network_tcp_connection_close(cl->reader, "no ip");
				return 0;
			}
		}
	}

	if(!cl->reader->tcp_connected)    // client not connected
	{
		int32_t handle = 0;
		handle = network_tcp_connection_open(cl->reader); // try to connect
		if(handle < 0)   // got no handle -> error!
		{
			cl->reader->last_s = 0; // set last send to zero
			cl->reader->last_g = 0; // set last receive to zero
			cl->last = 0; // set last client action to zero
			return (0);
		}

		cl->reader->tcp_connected = 1;
		cl->reader->card_status = CARD_INSERTED;
		cl->reader->last_s = time(NULL); // reset last send
		cl->reader->last_g = time(NULL); // reset last receive
		cl->last = time(NULL); // reset last client action
		cl->pfd = cl->udp_fd = handle;
	}
	if(!cl->udp_fd) { return (0); }  // Check if client has no handle -> error
	// check if client reached timeout, if reached and reader is not udp type disconnect reader
	if(cl->reader->tcp_rto && (cl->reader->last_s - cl->reader->last_g > cl->reader->tcp_rto))
	{
		network_tcp_connection_close(cl->reader, "rto");
		return 0;
	}

	return (1); // all ok
}


#ifdef CS_CACHEEX
uint8_t camd35_node_id[8];

/**
 * send own id
 */
void camd35_cache_push_send_own_id(struct s_client *cl, uint8_t *mbuf)
{
	uint8_t rbuf[32]; //minimal size

	if(!cl->crypted) { return; }

	cs_debug_mask(D_CACHEEX, "cacheex: received id request from node %" PRIu64 "X %s", cacheex_node_id(mbuf + 20), username(cl));

	memset(rbuf, 0, sizeof(rbuf));
	rbuf[0] = 0x3e;
	rbuf[1] = 12;
	rbuf[2] = 0;
	memcpy(rbuf + 20, camd35_node_id, 8);
	cs_debug_mask(D_CACHEEX, "cacheex: sending own id %" PRIu64 "X request %s", cacheex_node_id(camd35_node_id), username(cl));
	camd35_send(cl, rbuf, 12); //send adds +20
}

/**
 * request remote id
 */
void camd35_cache_push_request_remote_id(struct s_client *cl)
{
	uint8_t rbuf[32];//minimal size

	memset(rbuf, 0, sizeof(rbuf));
	rbuf[0] = 0x3d;
	rbuf[1] = 12;
	rbuf[2] = 0;
	memcpy(rbuf + 20, camd35_node_id, 8);
	cs_debug_mask(D_CACHEEX, "cacheex: sending id request to %s", username(cl));
	camd35_send(cl, rbuf, 12); //send adds +20
}

/**
 * send push filter
 */
void camd35_cache_send_push_filter(struct s_client *cl, uint8_t mode)
{	
	struct s_reader *rdr = cl->reader;
	int i = 20, j;
	CECSPVALUETAB *filter;
	//maximum size: 20+255
	uint8_t buf[20+242];
	memset(buf, 0, sizeof(buf));	
	buf[0] = 0x3c;
	buf[1] = 0xf2;	

	//mode==2 send filters from rdr
	if(mode == 2 && rdr) 
	{
		filter = &rdr->cacheex.filter_caidtab;
	}
	//mode==3 send filters from acc
	else if(mode == 3 && cl->typ == 'c' && cl->account) 
	{
		filter = &cl->account->cacheex.filter_caidtab;
	}
	else {
		return;	
	}
	
	i2b_buf(2, filter->n, buf + i);
	i += 2;
	
	for(j=0; j<15; j++) 
	{
		if(j<CS_MAXCAIDTAB)
		{
			i2b_buf(4, filter->caid[j], buf + i);
		}
		i += 4;
	}

	for(j=0; j<15 && j<CS_MAXCAIDTAB; j++) 
	{
		if(j<CS_MAXCAIDTAB)
		{
			i2b_buf(4, filter->cmask[j], buf + i);
		}
		i += 4;
	}
	
	for(j=0; j<15 && j<CS_MAXCAIDTAB; j++) 
	{
		if(j<CS_MAXCAIDTAB)
		{			
			i2b_buf(4, filter->prid[j], buf + i);
		}
		i += 4;
	}
	
	for(j=0; j<15 && j<CS_MAXCAIDTAB; j++) 
	{
		if(j<CS_MAXCAIDTAB)
		{			
			i2b_buf(4, filter->srvid[j], buf + i);
		}
		i += 4;
	}

	cs_debug_mask(D_CACHEEX, "cacheex: sending push filter request to %s", username(cl));
	camd35_send_without_timeout(cl, buf, 242); //send adds +20  		
}

/**
 * store received push filter
 */
void camd35_cache_push_filter(struct s_client *cl, uint8_t *buf, uint8_t mode)
{
	struct s_reader *rdr = cl->reader;
	int i = 20, j;
	CECSPVALUETAB *filter;	
	
	//mode==2 write filters to acc
	if(mode == 2 && cl->typ == 'c' && cl->account && cl->account->cacheex.mode == 2
		&& cl->account->cacheex.allow_filter == 1) 
	{
		filter = &cl->account->cacheex.filter_caidtab;
	}
	//mode==3 write filters to rdr
	else if(mode == 3 && rdr && rdr->cacheex.allow_filter == 1) 
	{
		filter = &rdr->cacheex.filter_caidtab;
	}
	else {
		return;	
	}
	  
	filter->n = b2i(2, buf + i);
	i += 2;
	if(filter->n > CS_MAXCAIDTAB)
	{
		filter->n = CS_MAXCAIDTAB;
	}
	
	for(j=0; j<15; j++) 
	{
		if(j<CS_MAXCAIDTAB)
		{
			filter->caid[j] = b2i(4, buf + i);
		}
		i += 4;
	}

	for(j=0; j<15 && j<CS_MAXCAIDTAB; j++) 
	{
		if(j<CS_MAXCAIDTAB)
		{
			filter->cmask[j] = b2i(4, buf + i);
		}
		i += 4;
	}
	
	for(j=0; j<15 && j<CS_MAXCAIDTAB; j++) 
	{
		if(j<CS_MAXCAIDTAB)
		{
			filter->prid[j] = b2i(4, buf + i);
		}
		i += 4;
	}
	
	for(j=0; j<15 && j<CS_MAXCAIDTAB; j++) 
	{
		if(j<CS_MAXCAIDTAB)
		{
			filter->srvid[j] = b2i(4, buf + i);
		}
		i += 4;
	}
	
	cs_debug_mask(D_CACHEEX, "cacheex: received push filter request from %s", username(cl));
}

/**
 * when a server client connects
 */
static void camd35_server_client_init(struct s_client *cl)
{
	if(!cl->init_done)
	{
		cl->cacheex_needfilter = 1;		
	}
}

/**
 * store received remote id
 */
void camd35_cache_push_receive_remote_id(struct s_client *cl, uint8_t *buf)
{

	memcpy(cl->ncd_skey, buf + 20, 8);
	cl->ncd_skey[8] = 1;
	cs_debug_mask(D_CACHEEX, "cacheex: received id answer from %s: %" PRIu64 "X", username(cl), cacheex_node_id(cl->ncd_skey));
}


int32_t camd35_cache_push_chk(struct s_client *cl, ECM_REQUEST *er)
{
	if(ll_count(er->csp_lastnodes) >= cacheex_maxhop(cl))    //check max 10 nodes to push:
	{
		cs_debug_mask(D_CACHEEX, "cacheex: nodelist reached %d nodes, no push", cacheex_maxhop(cl));
		return 0;
	}

	if(cl->reader)
	{
		if(!cl->reader->tcp_connected)
		{
			cs_debug_mask(D_CACHEEX, "cacheex: not connected %s -> no push", username(cl));
			return 0;
		}
	}

	//if(chk_is_null_nodeid(remote_node,8)){
	if(!cl->ncd_skey[8])
	{
		cs_debug_mask(D_CACHEEX, "cacheex: NO peer_node_id got yet, skip!");
		return 0;
	}

	uint8_t *remote_node = cl->ncd_skey; //it is sended by reader(mode 2) or client (mode 3) each 30s using keepalive msgs

	//search existing peer nodes:
	LL_LOCKITER *li = ll_li_create(er->csp_lastnodes, 0);
	uint8_t *node;
	while((node = ll_li_next(li)))
	{
		cs_debug_mask(D_CACHEEX, "cacheex: check node %" PRIu64 "X == %" PRIu64 "X ?", cacheex_node_id(node), cacheex_node_id(remote_node));
		if(memcmp(node, remote_node, 8) == 0)
		{
			break;
		}
	}
	ll_li_destroy(li);

	//node found, so we got it from there, do not push:
	if(node)
	{
		cs_debug_mask(D_CACHEEX,
					  "cacheex: node %" PRIu64 "X found in list => skip push!", cacheex_node_id(node));
		return 0;
	}

	//check if cw is already pushed
	if(check_is_pushed(er->cw_cache, cl))
		{ return 0; }

	cs_debug_mask(D_CACHEEX, "cacheex: push ok %" PRIu64 "X to %" PRIu64 "X %s", cacheex_node_id(camd35_node_id), cacheex_node_id(remote_node), username(cl));

	return 1;
}
int32_t camd35_cache_push_out(struct s_client *cl, struct ecm_request_t *er)
{
	int8_t rc = (er->rc < E_NOTFOUND) ? E_FOUND : er->rc;
	if(rc != E_FOUND && rc != E_UNHANDLED) { return -1; }  //Maybe later we could support other rcs

	//E_FOUND     : we have the CW,
	//E_UNHANDLED : incoming ECM request

	if(cl->reader)
	{
		if(!tcp_connect(cl))
		{
			cs_debug_mask(D_CACHEEX, "cacheex: not connected %s -> no push", username(cl));
			return (-1);
		}
	}

	uint32_t size = sizeof(er->ecmd5) + sizeof(er->csp_hash) + sizeof(er->cw) + sizeof(uint8_t) +
					(ll_count(er->csp_lastnodes) + 1) * 8;
	unsigned char *buf;
	if(!cs_malloc(&buf, size + 20))  //camd35_send() adds +20
		{ return -1; }

	buf[0] = 0x3f; //New Command: Cache-push
	buf[1] = size & 0xff;
	buf[2] = size >> 8;
	buf[3] = rc;

	i2b_buf(2, er->srvid, buf + 8);
	i2b_buf(2, er->caid, buf + 10);
	i2b_buf(4, er->prid, buf + 12);
	//i2b_buf(2, er->idx, buf + 16); // Not relevant...?

#ifdef CS_CACHEEX
	if(er->cwc_cycletime && er->cwc_next_cw_cycle < 2)
	{
		buf[18] = er->cwc_cycletime; // contains cwc stage3 cycletime
		if(er->cwc_next_cw_cycle == 1)
		{ buf[18] = (buf[18] | 0x80); } // set bit 8 to high

		if(cl->typ == 'c' && cl->account && cl->account->cacheex.mode)
			{ cl->account->cwc_info++; }
		else if((cl->typ == 'p' || cl->typ == 'r') && (cl->reader && cl->reader->cacheex.mode))
			{ cl->cwc_info++; }
#endif
		cs_debug_mask(D_CWC, "CWC (CE) push to %s (camd3) cycletime: %isek - nextcwcycle: CW%i for %04X:%06X:%04X", username(cl), er->cwc_cycletime, er->cwc_next_cw_cycle, er->caid, er->prid, er->srvid);
	}

	buf[19] = er->ecm[0] != 0x80 && er->ecm[0] != 0x81 ? 0 : er->ecm[0];

	uint8_t *ofs = buf + 20;

	//write oscam ecmd5:
	memcpy(ofs, er->ecmd5, sizeof(er->ecmd5)); //16
	ofs += sizeof(er->ecmd5);

	//write csp hashcode:
	i2b_buf(4, htonl(er->csp_hash), ofs);
	ofs += 4;

	//write cw:
	memcpy(ofs, er->cw, sizeof(er->cw)); //16
	ofs += sizeof(er->cw);

	//write node count:
	*ofs = ll_count(er->csp_lastnodes) + 1;
	ofs++;

	//write own node:
	memcpy(ofs, camd35_node_id, 8);
	ofs += 8;

	//write other nodes:
	LL_LOCKITER *li = ll_li_create(er->csp_lastnodes, 0);
	uint8_t *node;
	while((node = ll_li_next(li)))
	{
		memcpy(ofs, node, 8);
		ofs += 8;
	}
	ll_li_destroy(li);

	int32_t res = camd35_send(cl, buf, size);
	NULLFREE(buf);
	return res;
}

void camd35_recv_ce1_cwc_info(struct s_client *cl, uchar *buf, int32_t idx)
{
	ECM_REQUEST *er = NULL;
	int32_t i;

	for(i = 0; i < cfg.max_pending; i++)
	{
		if (cl->ecmtask[i].idx == idx)
		{ 
			er = &cl->ecmtask[i]; 
			break;
		}
	}

	if(!er)
	{ return; }

	int8_t rc = buf[3];
	if(rc != E_FOUND)  
		{ return; }

	if(buf[18])
 	{
		if(buf[18] & (0x01 << 7))
		{
			er->cwc_cycletime = (buf[18] & 0x7F); // remove bit 8 to get cycletime
			er->parent->cwc_cycletime = er->cwc_cycletime;
			er->cwc_next_cw_cycle = 1;
			er->parent->cwc_next_cw_cycle = er->cwc_next_cw_cycle;
		}
		else
		{
			er->cwc_cycletime = buf[18];
			er->parent->cwc_cycletime = er->cwc_cycletime;
			er->cwc_next_cw_cycle = 0;
			er->parent->cwc_next_cw_cycle = er->cwc_next_cw_cycle;
		}
	}

	if(cl->typ == 'c' && cl->account && cl->account->cacheex.mode)
		{ cl->account->cwc_info++; }
	else if((cl->typ == 'p' || cl->typ == 'r') && (cl->reader && cl->reader->cacheex.mode))
		{ cl->cwc_info++; }

	cs_debug_mask(D_CWC, "CWC (CE1) received from %s (camd3) cycletime: %isek - nextcwcycle: CW%i for %04X:%06X:%04X", username(cl), er->cwc_cycletime, er->cwc_next_cw_cycle, er->caid, er->prid, er->srvid);

}

void camd35_cache_push_in(struct s_client *cl, uchar *buf)
{
	int8_t rc = buf[3];
	if(rc != E_FOUND && rc != E_UNHANDLED)  //Maybe later we could support other rcs
		{ return; }

	ECM_REQUEST *er;
	uint16_t size = buf[1] | (buf[2] << 8);
	if(size < sizeof(er->ecmd5) + sizeof(er->csp_hash) + sizeof(er->cw))
	{
		cs_debug_mask(D_CACHEEX, "cacheex: %s received old cash-push format! data ignored!", username(cl));
		return;
	}

	if(!(er = get_ecmtask()))
		{ return; }

	er->srvid = b2i(2, buf + 8);
	er->caid = b2i(2, buf + 10);
	er->prid = b2i(4, buf + 12);
	er->pid  = b2i(2, buf + 16);
	er->ecm[0] = buf[19]!=0x80 && buf[19]!=0x81 ? 0 : buf[19]; //odd/even byte, usefull to send it over CSP and to check cw for swapping
	er->rc = rc;

	er->ecmlen = 0;

#ifdef CS_CACHEEX
	if(buf[18])
	{
		if(buf[18] & (0x01 << 7))
		{
			er->cwc_cycletime = (buf[18] & 0x7F); // remove bit 8 to get cycletime
			er->cwc_next_cw_cycle = 1;
		}
		else
		{
			er->cwc_cycletime = buf[18];
			er->cwc_next_cw_cycle = 0;
		}
	}

	if (er->cwc_cycletime && er->cwc_next_cw_cycle < 2)
	{
		if(cl->typ == 'c' && cl->account && cl->account->cacheex.mode)
			{ cl->account->cwc_info++; }
		else if((cl->typ == 'p' || cl->typ == 'r') && (cl->reader && cl->reader->cacheex.mode))
			{ cl->cwc_info++; }
		cs_debug_mask(D_CWC, "CWC (CE) received from %s (camd3) cycletime: %isek - nextcwcycle: CW%i for %04X:%06X:%04X", username(cl), er->cwc_cycletime, er->cwc_next_cw_cycle, er->caid, er->prid, er->srvid);
	}
#endif


	uint8_t *ofs = buf + 20;

	//Read ecmd5
	memcpy(er->ecmd5, ofs, sizeof(er->ecmd5)); //16
	ofs += sizeof(er->ecmd5);

	if(!check_cacheex_filter(cl, er))
		{ return; }

	//Read csp_hash:
	er->csp_hash = ntohl(b2i(4, ofs));
	ofs += 4;

	//Read cw:
	memcpy(er->cw, ofs, sizeof(er->cw)); //16
	ofs += sizeof(er->cw);

	//Check auf neues Format:
	uint8_t *data;
	if(size > (sizeof(er->ecmd5) + sizeof(er->csp_hash) + sizeof(er->cw)))
	{

		//Read lastnodes:
		uint8_t count = *ofs;
		ofs++;

		//check max nodes:
		if(count > cacheex_maxhop(cl))
		{
			cs_debug_mask(D_CACHEEX, "cacheex: received %d nodes (max=%d), ignored! %s", (int32_t)count, cacheex_maxhop(cl), username(cl));
			NULLFREE(er);
			return;
		}
		cs_debug_mask(D_CACHEEX, "cacheex: received %d nodes %s", (int32_t)count, username(cl));
		if (er){
			er->csp_lastnodes = ll_create("csp_lastnodes");
		}
		while(count)
		{
			if(!cs_malloc(&data, 8))
				{ break; }
			memcpy(data, ofs, 8);
			ofs += 8;
			ll_append(er->csp_lastnodes, data);
			count--;
			cs_debug_mask(D_CACHEEX, "cacheex: received node %" PRIu64 "X %s", cacheex_node_id(data), username(cl));
		}
	}
	else
	{
		cs_debug_mask(D_CACHEEX, "cacheex: received old cachex from %s", username(cl));
		er->csp_lastnodes = ll_create("csp_lastnodes");
	}

	//store remote node id if we got one. The remote node is the first node in the node list
	data = ll_has_elements(er->csp_lastnodes);
	if(data && !cl->ncd_skey[8])    //Ok, this is tricky, we use newcamd key storage for saving the remote node
	{
		memcpy(cl->ncd_skey, data, 8);
		cl->ncd_skey[8] = 1; //Mark as valid node
	}
	cs_debug_mask(D_CACHEEX, "cacheex: received cacheex from remote node id %" PRIu64 "X", cacheex_node_id(cl->ncd_skey));

	//for compatibility: add peer node if no node received (not working now, maybe later):
	if(!ll_count(er->csp_lastnodes) && cl->ncd_skey[8])
	{
		if(!cs_malloc(&data, 8))
			{ return; }
		memcpy(data, cl->ncd_skey, 8);
		ll_append(er->csp_lastnodes, data);
		cs_debug_mask(D_CACHEEX, "cacheex: added missing remote node id %" PRIu64 "X", cacheex_node_id(data));
	}

	//  if (!ll_count(er->csp_lastnodes)) {
	//      if (!cs_malloc(&data, 8))
	//          break;
	//      memcpy(data, &cl->ip, 4);
	//      memcpy(data+4, &cl->port, 2);
	//      memcpy(data+6, &cl->is_udp, 1);
	//      ll_append(er->csp_lastnodes, data);
	//      cs_debug_mask(D_CACHEEX, "cacheex: added compat remote node id %" PRIu64 "X", cacheex_node_id(data));
	//  }

	cacheex_add_to_cache(cl, er);
}

#endif


/*
 *	client functions
 */
void send_keepalive(struct s_client *cl)
{

	if(cl->reader)
	{
		if(tcp_connect(cl))
		{
#ifdef CS_CACHEEX
			if(cl->reader->cacheex.mode>1){
				camd35_cache_push_request_remote_id(cl);
				return;
			}
#endif

			uint8_t rbuf[32];//minimal size
			memset(rbuf, 0, sizeof(rbuf));
			rbuf[0] = 55;
			rbuf[1] = 1;
			rbuf[2] = 0;
			camd35_send(cl, rbuf, 1); //send adds +20
		}
	}
}


void send_keepalive_answer(struct s_client *cl)
{
	if(check_client(cl) && cl->account)
	{
		uint8_t rbuf[32];//minimal size
		memset(rbuf, 0, sizeof(rbuf));
		rbuf[0] = 55;
		rbuf[1] = 1;
		rbuf[2] = 0;
		camd35_send(cl, rbuf, 1); //send adds +20
	}
}


int32_t camd35_client_init(struct s_client *cl)
{

	unsigned char md5tmp[MD5_DIGEST_LENGTH];
	cs_strncpy((char *)cl->upwd, cl->reader->r_pwd, sizeof(cl->upwd));
	i2b_buf(4, crc32(0L, MD5((unsigned char *)cl->reader->r_usr, strlen(cl->reader->r_usr), md5tmp), 16), cl->ucrc);
	aes_set_key(&cl->aes_keys, (char *)MD5(cl->upwd, strlen((char *)cl->upwd), md5tmp));
	cl->crypted=1;

	cs_log("%s proxy %s:%d", cl->reader->ph.desc, cl->reader->device, cl->reader->r_port);

	if(cl->reader->keepalive)
		send_keepalive(cl);

#ifdef CS_CACHEEX
	if(cl->reader->cacheex.mode==2)
		camd35_cache_send_push_filter(cl, 2);
#endif

	return(0);
}


void camd35_idle(void)
{
	struct s_client *cl = cur_client();

	if(!cl->reader)
		{ return; }

	if(cl->reader->keepalive) 
	{
		send_keepalive(cl);
	}
	else if(cl->reader->tcp_ito>0) // only check if user added an inactivity timeout
	{
		//inactivity timeout check
		time_t now;
		int32_t time_diff;
		time(&now);
		time_diff = abs(now - cl->reader->last_s);
		if(time_diff>cl->reader->tcp_ito)
		{
			if(check_client(cl) && cl->reader->tcp_connected && cl->reader->ph.type==MOD_CONN_TCP)
			{
				cs_debug_mask(D_READER, "%s inactive_timeout, close connection (fd=%d)", cl->reader->ph.desc, cl->pfd);
				network_tcp_connection_close(cl->reader, "inactivity");
			}
			else
				{ cl->reader->last_s = now; }
		}
	}
}


static void *camd35_server(struct s_client *client, uchar *mbuf, int32_t n)
{
	if(!client || !mbuf)
		{ return NULL; }

	if(client->reader)
	{
		client->reader->last_g = time(NULL);  // last receive is now
		if(mbuf[0] == 6 || mbuf[0] == 19)  // check for emm command
		{
			client->reader->last_s = time(NULL); // fixup: last send is now (if client is only sending emms connection would be dropped!)
		}
		cs_log("%s_SERVER last = %d, last_s = %d, last_g = %d", client->reader->ph.desc, (int) client->last, (int) client->reader->last_s, (int) client->reader->last_g);
	}
	client->last = time(NULL); // last client action is now


	switch(mbuf[0])
	{
	case  0:    // ECM
	case  3:    // ECM (cascading)
		camd35_process_ecm(mbuf, n);
		break;
#ifdef CS_CACHEEX
	case 0x3c:  // Cache-push filter request
		if(client->account && client->account->cacheex.mode==2){
			camd35_cache_push_filter(client, mbuf, 2);
		}
		break;	
	case 0x3d:  // Cache-push id request
		camd35_cache_push_receive_remote_id(client, mbuf); //reader send request id with its nodeid, so we save it!
		camd35_cache_push_send_own_id(client, mbuf);
		
		if(client->cacheex_needfilter && client->account && client->account->cacheex.mode==3){
			camd35_cache_send_push_filter(client, 3);
			client->cacheex_needfilter = 0;
		}
		break;
	case 0x3e:  // Cache-push id answer
		camd35_cache_push_receive_remote_id(client, mbuf);
		break;
	case 0x3f:  // Cache-push
		camd35_cache_push_in(client, mbuf);
		break;
#endif
	case  6:    // EMM
	case 19:  // EMM
		if(n > 2)
			{ camd35_process_emm(mbuf, n, mbuf[1]); }
		break;
	case 55:
		//keepalive msg
		send_keepalive_answer(client);
		break;
	default:
		cs_log("unknown [cs357x/cs378x] command from %s! (%d) n=%d", username(client), mbuf[0], n);
	}

	return NULL; //to prevent compiler message
}

static int32_t camd35_send_ecm(struct s_client *client, ECM_REQUEST *er, uchar *buf)
{
	static const char *typtext[] = {"ok", "invalid", "sleeping"};

	if(client->stopped)
	{
		if(er->srvid == client->lastsrvid && er->caid == client->lastcaid)
		{
			cs_log("%s is stopped - requested by server (%s)",
				   client->reader->label, typtext[client->stopped]);
			return (-1);
		}
		else
		{
			client->stopped = 0;
		}
	}

	client->lastsrvid = er->srvid;
	client->lastcaid = er->caid;
	client->lastpid = er->pid;


	if(!tcp_connect(client)) { return -1; }

	client->reader->card_status = CARD_INSERTED; //for udp

	memset(buf, 0, 20);
	memset(buf + 20, 0xff, er->ecmlen + 15);
	buf[1] = er->ecmlen;
	i2b_buf(2, er->srvid, buf + 8);
	i2b_buf(2, er->caid, buf + 10);
	i2b_buf(4, er->prid, buf + 12);
	i2b_buf(2, er->idx, buf + 16);
	buf[18] = 0xff;
	buf[19] = 0xff;
	memcpy(buf + 20, er->ecm, er->ecmlen);
	return ((camd35_send(client, buf, 0) < 1) ? (-1) : 0);
}

static int32_t camd35_send_emm(EMM_PACKET *ep)
{
	uchar buf[512];
	struct s_client *cl = cur_client();


	if(!tcp_connect(cl)) { return 0; }
	cl->reader->card_status = CARD_INSERTED; //for udp
	
	memset(buf, 0, 20);
	memset(buf + 20, 0xff, ep->emmlen + 15);

	buf[0] = 0x06;
	buf[1] = ep->emmlen;
	memcpy(buf + 10, ep->caid, 2);
	memcpy(buf + 12, ep->provid, 4);
	memcpy(buf + 20, ep->emm, ep->emmlen);

	return ((camd35_send_without_timeout(cl, buf, 0) < 1) ? 0 : 1);
}

static int32_t camd35_recv_chk(struct s_client *client, uchar *dcw, int32_t *rc, uchar *buf, int32_t rc2 __attribute__((unused)))
{
	uint16_t idx;
	static const char *typtext[] = {"ok", "invalid", "sleeping"};
	struct s_reader *rdr = client->reader;
	rdr->last_g = time(NULL);  // last receive is now

	// reading CMD05 Emm request and set serial
	if(buf[0] == 0x05 && buf[1] == 111)
	{

		//cs_log("CMD05: %s", cs_hexdump(1, buf, buf[1], tmp, sizeof(tmp)));
		rdr->nprov = 0; //reset if number changes on reader change
		rdr->nprov = buf[47];
		rdr->caid = b2i(2, buf + 20);
		rdr->auprovid = b2i(4, buf + 12);

		int32_t i;
		for(i = 0; i < rdr->nprov; i++)
		{
			if(((rdr->caid >= 0x1700) && (rdr->caid <= 0x1799))  ||     // Betacrypt
					((rdr->caid >= 0x0600) && (rdr->caid <= 0x0699)))   // Irdeto (don't know if this is correct, cause I don't own a IRDETO-Card)
			{
				rdr->prid[i][0] = buf[48 + (i * 5)];
				memcpy(&rdr->prid[i][1], &buf[50 + (i * 5)], 3);
			}
			else
			{
				rdr->prid[i][2] = buf[48 + (i * 5)];
				rdr->prid[i][3] = buf[49 + (i * 5)];
				memcpy(&rdr->sa[i][0], &buf[50 + (i * 5)], 4);
			}
		}

		memcpy(rdr->hexserial, buf + 40, 6);
		rdr->hexserial[6] = 0;
		rdr->hexserial[7] = 0;

		rdr->blockemm = 0;
		rdr->blockemm |= (buf[128] == 1) ? 0 : EMM_GLOBAL;
		rdr->blockemm |= (buf[129] == 1) ? 0 : EMM_SHARED;
		rdr->blockemm |= (buf[130] == 1) ? 0 : EMM_UNIQUE;
		rdr->blockemm |= (buf[127] == 1) ? 0 : EMM_UNKNOWN;
		cs_log("%s CMD05 AU request for caid: %04X auprovid: %06X",
			   rdr->label,
			   rdr->caid,
			   rdr->auprovid);
	}

	bool rc_invalid = 0;
	if(buf[0] == 0x08
			&& ((rdr->ph.type == MOD_CONN_TCP && !cfg.c35_tcp_suppresscmd08)
				|| (rdr->ph.type == MOD_CONN_UDP
					&& !cfg.c35_udp_suppresscmd08)))
	{
		if(buf[21] == 0xFF)
		{
			client->stopped = 2; // server says sleep
			rdr->card_status = NO_CARD;
		}
		else
		{
#ifdef WITH_LB
			if(cfg.lb_mode)
			{
				rc_invalid = 1;
			}else{
#endif
				client->stopped = 1; // server says invalid
				rdr->card_status = CARD_FAILURE;
#ifdef WITH_LB
			}
#endif
		}

		cs_log("%s CMD08 (%02X - %d) stop request by server (%s)", rdr->label, buf[21], buf[21], typtext[client->stopped]);
	}

#ifdef CS_CACHEEX
	if(buf[0] == 0x3c)    // Cache-push filter request
	{
		if(rdr->cacheex.mode==3){
			camd35_cache_push_filter(client, buf, 3);
		}
		return -1;
	}
	if(buf[0] == 0x3d)    // Cache-push id request
	{
		camd35_cache_push_receive_remote_id(client, buf); //client send request id with its nodeid, so we save it!
		camd35_cache_push_send_own_id(client, buf);
		return -1;
	}
	if(buf[0] == 0x3e)     // Cache-push id answer
	{
		camd35_cache_push_receive_remote_id(client, buf);
		return -1;
	}
	if(buf[0] == 0x3f)    //cache-push
	{
		camd35_cache_push_in(client, buf);
		return -1;
	}
#endif

	if(buf[0] == 55)  //keepalive answer
		{ return -1; }

	// CMD44: old reject command introduced in mpcs
	// keeping this for backward compatibility
	if((buf[0] != 1) && (buf[0] != 0x44) && (buf[0] != 0x08))
		{ return (-1); }

	idx = b2i(2, buf + 16);

#ifdef CS_CACHEEX
	if(buf[0] == 0x01 && buf[18] < 0xFF && buf[18] > 0x00) // cwc info ; normal camd3 ecms send 0xFF but we need no cycletime of 255 ;)
	{
		camd35_recv_ce1_cwc_info(client, buf, idx);
	}
#endif

	*rc = ((buf[0] != 0x44) && (buf[0] != 0x08));
	if(rc_invalid){
		*rc = 2;  // INVALID sent by CMD08
	}

	memcpy(dcw, buf + 20, 16);
	return (idx);
}

/*
 *  module definitions
 */
#ifdef MODULE_CAMD35
void module_camd35(struct s_module *ph)
{
	ph->ptab.nports = 1;
	ph->ptab.ports[0].s_port = cfg.c35_port;

	ph->desc = "cs357x";
	ph->type = MOD_CONN_UDP;
	ph->large_ecm_support = 1;
	ph->listenertype = LIS_CAMD35UDP;
	IP_ASSIGN(ph->s_ip, cfg.c35_srvip);
	ph->s_handler = camd35_server;
	ph->recv = camd35_recv;
	ph->send_dcw = camd35_send_dcw;
	ph->c_init = camd35_client_init;
	ph->c_recv_chk = camd35_recv_chk;
	ph->c_send_ecm = camd35_send_ecm;
	ph->c_send_emm = camd35_send_emm;
	ph->c_idle = camd35_idle;
#ifdef CS_CACHEEX
	ph->c_cache_push = camd35_cache_push_out;
	ph->c_cache_push_chk = camd35_cache_push_chk;
	ph->s_init = camd35_server_client_init;	
#endif
	ph->num = R_CAMD35;
}
#endif

#ifdef MODULE_CAMD35_TCP
void module_camd35_tcp(struct s_module *ph)
{
	ph->desc = "cs378x";
	ph->type = MOD_CONN_TCP;
	ph->large_ecm_support = 1;
	ph->listenertype = LIS_CAMD35TCP;
	ph->ptab = cfg.c35_tcp_ptab;
	IP_ASSIGN(ph->s_ip, cfg.c35_tcp_srvip);
	ph->s_handler = camd35_server;
	ph->recv = camd35_recv;
	ph->send_dcw = camd35_send_dcw;
	ph->c_init = camd35_client_init;
	ph->c_recv_chk = camd35_recv_chk;
	ph->c_send_ecm = camd35_send_ecm;
	ph->c_send_emm = camd35_send_emm;
	ph->c_idle = camd35_idle;
#ifdef CS_CACHEEX
	ph->c_cache_push = camd35_cache_push_out;
	ph->c_cache_push_chk = camd35_cache_push_chk;
	ph->s_init = camd35_server_client_init;
#endif
	ph->num = R_CS378X;
}
#endif
#endif
