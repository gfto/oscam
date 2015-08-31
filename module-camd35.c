#define MODULE_LOG_PREFIX "camd35"

#include "globals.h"
#if defined MODULE_CAMD35 || defined MODULE_CAMD35_TCP

#include "cscrypt/md5.h"
#include "module-cacheex.h"
#include "module-camd35.h"
#include "module-camd35-cacheex.h"
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

#define REQ_SIZE    MAX_ECM_SIZE + 20 + 0x34

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
	cs_log_dump_dbg(cl->typ == 'c' ? D_CLIENT : D_READER, sbuf, l, "send %d bytes to %s", l, username(cl));
	aes_encrypt_idx(cl->aes_keys, sbuf, l);

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

int32_t camd35_send(struct s_client *cl, uchar *buf, int32_t buflen)
{
	// send command and set sending time because we await response
	return __camd35_send(cl, buf, buflen, 1);
}

int32_t camd35_send_without_timeout(struct s_client *cl, uchar *buf, int32_t buflen)
{
	// send command and do NOT set sending time because we DON'T await response
	return __camd35_send(cl, buf, buflen, 0);
}

static int32_t camd35_auth_client(struct s_client *cl, uchar *ucrc)
{
	int32_t rc = 1, no_delay = 1;
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
				if (!aes_set_key_alloc(&cl->aes_keys, (char *) MD5(cl->upwd, strlen((char *)cl->upwd), md5tmp)))
				{
					return 1;
				}
				
				#ifdef CS_CACHEEX
				if(cl->account->cacheex.mode < 2)
				#endif
				if(!cl->is_udp && cl->tcp_nodelay == 0)
				{
					setsockopt(cl->udp_fd, IPPROTO_TCP, TCP_NODELAY, (void *)&no_delay, sizeof(no_delay));
					cl->tcp_nodelay = 1;
				}
				
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

				//rs = cs_recv(client->udp_fd, buf, client->is_udp ? l : 36, 0);
				if(client->is_udp){
					while (1){
					rs = cs_recv(client->udp_fd, buf, l, 0);
						if (rs < 0){
							if(errno == EINTR) { continue; }  // try again in case of interrupt
							if(errno == EAGAIN) { continue; }  //EAGAIN needs select procedure again
							cs_log_dbg(client->typ == 'c' ? D_CLIENT : D_READER, "ERROR: %s (errno=%d %s)", __func__, errno, strerror(errno));
							break;
						}else {break;}
					}
				}else{
					int32_t tot=36, readed=0;
					rs = 0;
					do
					{
						readed = cs_recv(client->udp_fd, buf+rs, tot, 0);
						if (readed < 0){
							if(errno == EINTR) { continue; }  // try again in case of interrupt
							if(errno == EAGAIN) { continue; }  //EAGAIN needs select procedure again
							cs_log_dbg(client->typ == 'c' ? D_CLIENT : D_READER, "ERROR: %s (errno=%d %s)", __func__, errno, strerror(errno));
							break;
						}
						if (readed == 0){ // nothing to read left!
							rc = -5;
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
				if(rc != -5)
					{ rc = -1; }
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
			aes_decrypt(client->aes_keys, buf, rs);
			if(rs != boundary(4, rs))
				cs_log_dbg(client->typ == 'c' ? D_CLIENT : D_READER,
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

				//len = cs_recv(client->udp_fd, buf+32, n-32, 0); // read the rest of the packet
				int32_t tot=n-32, readed=0;
				len = 0;
				do{
					readed = cs_recv(client->udp_fd, buf+32+len, tot, 0); // read the rest of the packet
					if (readed < 0){
						if(errno == EINTR) { continue; }  // try again in case of interrupt
						if(errno == EAGAIN) { continue; }  //EAGAIN needs select procedure again
						cs_log_dbg(client->typ == 'c' ? D_CLIENT : D_READER, "ERROR: %s (errno=%d %s)", __func__, errno, strerror(errno));
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
					aes_decrypt(client->aes_keys, buf + 32, len);
				}
				if(len < 0)
				{
					rc = -1;
					goto out;
				}
			}

			cs_log_dump_dbg(client->typ == 'c' ? D_CLIENT : D_READER,
						  buf, rs, "received %d bytes from %s", rs, remote_txt());

			if(n < rs)
				cs_log_dbg(client->typ == 'c' ? D_CLIENT : D_READER,
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
		cs_log_dump_dbg(client->typ == 'c' ? D_CLIENT : D_READER, buf, rs,
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
	case -5:
		cs_log_dbg(client->typ == 'c' ? D_CLIENT : D_READER, "connection closed");
		break;		
		//default:  cs_log_dbg(D_TRACE, "camd35_recv returns rc=%d", rc); break;
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

	if(!au_caid && caid_is_bulcrypt(er->caid)) // Bulcrypt has 2 caids and aureader->caid can't be used. Use ECM_REQUEST caid for AU.
		{ au_caid = er->caid; }

	time(&now);
	if(!memcmp(cl->lastserial, aureader->hexserial, 8))
		if(llabs(now - cl->last) < 180) { return; }

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
		rdr_log(client->reader, "ERROR: src_data missing");
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
			camd35_cacheex_init_dcw(client, er);
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
		
	uint16_t ecmlen = SCT_LEN((&buf[20]));
	
	if(ecmlen > MAX_ECM_SIZE || ecmlen + 20 > buflen)
		{ return; }
	
	if(!(er = get_ecmtask()))
		{ return; }

	er->ecmlen = ecmlen;
	
	if(!cs_malloc(&er->src_data, 0x34 + 20 + er->ecmlen))
		{ NULLFREE(er); return; }
		
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
	if(epg.emmlen < 0 || epg.emmlen > MAX_EMM_SIZE)
		{ return; }
	memcpy(epg.caid, buf + 10, 2);
	memcpy(epg.provid, buf + 12 , 4);
	memcpy(epg.emm, buf + 20, epg.emmlen);
	do_emm(cur_client(), &epg);
}

int32_t camd35_tcp_connect(struct s_client *cl)
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
	
	// check if client reached timeout
	if(cl->reader->tcp_rto && (cl->reader->last_s - cl->reader->last_g > cl->reader->tcp_rto))
	{
		if(!cl->is_udp) //tcp on timeout disconnect reader
		{
			network_tcp_connection_close(cl->reader, "rto");
			return 0;
		}
		else //udp check to discover ip change on dynamic ip servers
		{
			IN_ADDR_T last_ip;
			IP_ASSIGN(last_ip, cl->ip);
			if(!hostResolve(cl->reader))
			{
				network_tcp_connection_close(cl->reader, "no ip");
				return 0; 
			}
			if(!IP_EQUAL(last_ip, cl->ip))
			{
				network_tcp_connection_close(cl->reader, "ip change");
				return 0;
			}
		}
	}
	
	return (1); // all ok
}

/*
 *	client functions
 */
static void camd35_send_keepalive(struct s_client *cl)
{

	if(cl->reader)
	{
		if(camd35_tcp_connect(cl))
		{
			if(cacheex_get_rdr_mode(cl->reader) > 1)
			{
				camd35_cacheex_push_request_remote_id(cl);
				return;
			}
			uint8_t rbuf[32];//minimal size
			memset(rbuf, 0, sizeof(rbuf));
			rbuf[0] = 55;
			rbuf[1] = 1;
			rbuf[2] = 0;
			camd35_send(cl, rbuf, 1); //send adds +20
		}
	}
}


static void camd35_send_keepalive_answer(struct s_client *cl)
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


static int32_t camd35_client_init(struct s_client *cl)
{
	unsigned char md5tmp[MD5_DIGEST_LENGTH];
	int32_t no_delay = 1;
			   
	cs_strncpy((char *)cl->upwd, cl->reader->r_pwd, sizeof(cl->upwd));
	i2b_buf(4, crc32(0L, MD5((unsigned char *)cl->reader->r_usr, strlen(cl->reader->r_usr), md5tmp), 16), cl->ucrc);
	if (!aes_set_key_alloc(&cl->aes_keys, (char *)MD5(cl->upwd, strlen((char *)cl->upwd), md5tmp)))
	{
		return 1;
	}
	cl->crypted=1;

	rdr_log(cl->reader, "proxy %s:%d", cl->reader->device, cl->reader->r_port);

	if(!cl->is_udp && cacheex_get_rdr_mode(cl->reader) < 2)
		setsockopt(cl->udp_fd, IPPROTO_TCP, TCP_NODELAY, (void *)&no_delay, sizeof(no_delay));

	if(cl->reader->keepalive)
		camd35_send_keepalive(cl);

	if(cacheex_get_rdr_mode(cl->reader) == 2)
		camd35_cacheex_send_push_filter(cl, 2);

	return(0);
}


static void camd35_idle(void)
{
	struct s_client *cl = cur_client();

	if(!cl->reader)
		{ return; }

	if(cl->reader->keepalive) 
	{
		camd35_send_keepalive(cl);
	}
	else if(cl->reader->tcp_ito>0) // only check if user added an inactivity timeout
	{
		//inactivity timeout check
		time_t now;
		int32_t time_diff;
		time(&now);
		time_diff = llabs(now - cl->reader->last_s);
		if(time_diff>cl->reader->tcp_ito)
		{
			if(check_client(cl) && cl->reader->tcp_connected && cl->reader->ph.type==MOD_CONN_TCP)
			{
				rdr_log_dbg(cl->reader, D_READER, "inactive_timeout, close connection (fd=%d)", cl->pfd);
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
		rdr_log(client->reader, "SERVER last = %d, last_s = %d, last_g = %d", (int) client->last, (int) client->reader->last_s, (int) client->reader->last_g);
	}
	client->last = time(NULL); // last client action is now


	switch(mbuf[0])
	{
	case  0:    // ECM
	case  3:    // ECM (cascading)
		camd35_process_ecm(mbuf, n);
		break;
	case  6:    // EMM
	case 19:  // EMM
		if(n > 2)
			{ camd35_process_emm(mbuf, n, mbuf[1]); }
		break;
	case 55:
		//keepalive msg
		camd35_send_keepalive_answer(client);
		break;
	default:
		if (!camd35_cacheex_server(client, mbuf))
			cs_log("unknown [cs357x/cs378x] command from %s! (%d) n=%d", username(client), mbuf[0], n);
	}

	return NULL; //to prevent compiler message
}

static int32_t camd35_send_ecm(struct s_client *client, ECM_REQUEST *er)
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

	if(!camd35_tcp_connect(client)) { return -1; }

	client->reader->card_status = CARD_INSERTED; //for udp

	uint8_t *buf;
	if(!cs_malloc(&buf, er->ecmlen + 20 + 15))
	{ return -1; }
	
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
	int32_t rc = ((camd35_send(client, buf, 0) < 1) ? (-1) : 0);
	
	NULLFREE(buf);
	return rc;
}

static int32_t camd35_send_emm(EMM_PACKET *ep)
{
	uint8_t *buf;
	struct s_client *cl = cur_client();

	if(!camd35_tcp_connect(cl)) { return 0; }
	cl->reader->card_status = CARD_INSERTED; //for udp

	if(!cs_malloc(&buf, ep->emmlen + 20 + 15))
	{ return -1; }
	
	memset(buf, 0, 20);
	memset(buf + 20, 0xff, ep->emmlen + 15);

	buf[0] = 0x06;
	buf[1] = ep->emmlen;
	memcpy(buf + 10, ep->caid, 2);
	memcpy(buf + 12, ep->provid, 4);
	memcpy(buf + 20, ep->emm, ep->emmlen);

	int32_t rc = ((camd35_send_without_timeout(cl, buf, 0) < 1) ? 0 : 1);
	
	NULLFREE(buf);
	return rc;	
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

		if(cfg.getblockemmauprovid)
		{
			rdr->blockemm = 0;
			rdr->blockemm |= (buf[128] == 1) ? 0 : EMM_GLOBAL;
			rdr->blockemm |= (buf[129] == 1) ? 0 : EMM_SHARED;
			rdr->blockemm |= (buf[130] == 1) ? 0 : EMM_UNIQUE;
			rdr->blockemm |= (buf[127] == 1) ? 0 : EMM_UNKNOWN;
			rdr->auprovid = b2i(4, buf + 12);
		}
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
			if(config_enabled(WITH_LB) && cfg.lb_mode)
			{
				rc_invalid = 1;
			}else{
				client->stopped = 1; // server says invalid
				rdr->card_status = CARD_FAILURE;
			}
		}

		cs_log("%s CMD08 (%02X - %d) stop request by server (%s)", rdr->label, buf[21], buf[21], typtext[client->stopped]);
	}

	if (camd35_cacheex_recv_chk(client, buf))
		{ return -1; }

	if(buf[0] == 55)  //keepalive answer
		{ return -1; }

	// CMD44: old reject command introduced in mpcs
	// keeping this for backward compatibility
	if((buf[0] != 1) && (buf[0] != 0x44) && (buf[0] != 0x08))
		{ return (-1); }

	idx = b2i(2, buf + 16);

	camd35_cacheex_recv_ce1_cwc_info(client, buf, idx);

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
	camd35_cacheex_module_init(ph);
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
	camd35_cacheex_module_init(ph);
	ph->num = R_CS378X;
}
#endif

#endif
