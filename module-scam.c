#define MODULE_LOG_PREFIX "scam"

#include "globals.h"
#ifdef MODULE_SCAM
#include "oscam-client.h"
#include "oscam-ecm.h"
#include "oscam-net.h"
#include "oscam-string.h"
#include "oscam-reader.h"
#include "oscam-lock.h"
#include "oscam-time.h"
#include "oscam-chk.h"
#include "cscrypt/des.h"

struct scam_data
{
	uchar			enckey[8];
	uchar			deckey[8];
	uint8_t			enc_xor_offset;
	uint8_t			dec_xor_offset;
	uint8_t			login_pending;
	char			login_username[64];
	uint16_t		version;
};

static inline void xxor(uint8_t *data, int32_t len, const uint8_t *v1, const uint8_t *v2)
{
	uint32_t i;
	switch(len)
	{
	case 16:
		for(i = 8; i < 16; ++i)
		{
			data[i] = v1[i] ^ v2[i];
		}
	case 8:
		for(i = 4; i < 8; ++i)
		{
			data[i] = v1[i] ^ v2[i];
		}
	case 4:
		for(i = 0; i < 4; ++i)
		{
			data[i] = v1[i] ^ v2[i];
		}
		break;
	default:
		while(len--) { *data++ = *v1++ ^ *v2++; }
		break;
	}
}

static void scam_generate_deskey(char *keyString, uint8_t *desKey)
{
	uint8_t iv[8], key[8], *tmpKey;
	int32_t i, passLen, alignedPassLen;
	
	memset(iv, 0, 8);
	memset(desKey, 0, 8);
	memset(key, 0, 8);
	
	passLen = keyString == NULL ? 0 : strlen(keyString);
	if(passLen > 1024) {
		passLen = 1024;
	}

	alignedPassLen = (passLen + 7) & -8;
	if(alignedPassLen == 0) alignedPassLen = 8;
		
	if(!cs_malloc(&tmpKey, alignedPassLen)) {
		return;
	}

	if(passLen == 0) {
		memset(tmpKey, 0xAA, 8);
		passLen = 8;
	}
	else {
		memcpy(tmpKey, keyString, passLen);
	}
	
	for(i=0; i<alignedPassLen-passLen; i++) {
		tmpKey[passLen+i] = (uint8_t)i;
	}

	xxor(desKey,8,tmpKey,iv);	
	
	for(i=0; i<alignedPassLen; i+=8) {
		memcpy(key, &tmpKey[i], 8);
		doPC1(key);	
		des(key,DES_ECS2_CRYPT,&tmpKey[i]);
		xxor(desKey,8,desKey,&tmpKey[i]);
	}
	
	NULLFREE(tmpKey);
}

static void scam_encrypt_packet(uint8_t *packet, uint32_t packetLength, uint8_t *key, uint32_t dataLength, uint32_t dataOffset, uint8_t *xorOffset)
{
	uint8_t iv[8];
	uint32_t i;
	memset(iv, 0, 8);

	des_cbc_encrypt(packet + dataOffset, iv, key, dataLength);	

	for(i=0; i<packetLength; i++) {
		key[*xorOffset] ^=	packet[i];
		*xorOffset = (*xorOffset + 1) & 7;
	}
}	

static void scam_decrypt_packet(uint8_t *packet, uint32_t packetLength, uint8_t *key, uint32_t dataLength, uint32_t dataOffset, uint8_t *xorOffset)
{
	uint8_t tmpKey[8], iv[8];
	uint32_t i;
	memcpy(tmpKey, key, 8);
	memset(iv, 0, 8);

	for(i=0; i<packetLength; i++) {
		tmpKey[*xorOffset] ^=	packet[i];
		*xorOffset = (*xorOffset + 1) & 7;
	}
		
	des_cbc_decrypt(packet + dataOffset, iv, key, dataLength);	
	memcpy(key, tmpKey, 8);
}

static void scam_decode_length(uint8_t *packet, uint32_t *dataLength, uint32_t *dataOffset)
{
	uint32_t i, n;
	
	if(packet[1] & 0x80) {
		n = packet[1]&~0x80;
		*dataLength = 0;
		for(i=0; i<n; i++) {
			*dataLength = (*dataLength << 8) | packet[2+i];
		}	
		*dataOffset = 2 + n;
	}
	else {
		*dataLength = packet[1];
		*dataOffset =	2;
	}
}

static uint32_t scam_get_length_data_length(uint8_t *packet)
{
	if(packet[1] & 0x80) {
		return packet[1]&~0x80;
	}
	else {
		return 1;
	}
}

static void scam_encode_length(uint32_t len, uint8_t *data, uint8_t *dataLen)
{
	if(len < 128)
	{
		data[0] = (uint8_t)len;
		*dataLen = 1;
	}
	else if (len < 256 )
	{
		data[0] = 0x81;
		data[1] = (uint8_t)len;
		*dataLen = 2;
	}
	else if (len < 65536 ) {
		data[0] = 0x82;
		data[1] = (uint8_t)(len>>8);
		data[2] = (uint8_t)(len&0xFF);	
		*dataLen = 3;
	}
	else if (len < 16777216 )
	{
		data[0] = 0x83;
		data[1] = (uint8_t)(len>>16);
		data[2] = (uint8_t)((len>>8)&0xFF);
		data[3] = (uint8_t)(len&0xFF);	
		*dataLen = 4;
	}
	else
	{
		data[0] = 0x84;
		data[1] = (uint8_t)(len>>24);
		data[2] = (uint8_t)((len>>16)&0xFF);
		data[3] = (uint8_t)((len>>8)&0xFF);
		data[4] = (uint8_t)(len&0xFF);	
		*dataLen = 5;
	}
}


static void scam_client_close(struct s_client *cl, int32_t call_conclose)
{
	struct s_reader *rdr = cl->reader;
	if(!rdr) { return; }

	if(rdr) { rdr->tcp_connected = 0; }
	if(rdr) { rdr->card_status = NO_CARD; }
	if(rdr) { rdr->last_s = rdr->last_g = 0; }
	if(cl) { cl->last = 0; }

	if(call_conclose)	//clears also pending ecms!
		{ network_tcp_connection_close(rdr, "close"); }
	else
	{
		if(cl->udp_fd)
		{
			close(cl->udp_fd);
			cl->udp_fd = 0;
			cl->pfd = 0;
		}
	}
}

static int32_t scam_send(struct s_client *cl, uchar *buf, uint32_t len)
{
	uchar *mbuf, lenData[5];
	uint8_t lenDataLen = 0, paddingLen = 0;
	uint16_t crc = 0;
	int32_t result, packetLen;
	struct scam_data *scam = cl->scam;
	
	if(scam == NULL) { return 0; }
	if(len == 0) { return 0; }

	paddingLen = 8 - ((4+len) % 8);
	if(paddingLen == 8) {
		paddingLen = 0;
	}
	else if(paddingLen > 0 && paddingLen < 3) {
		paddingLen += 8;	
	}

	scam_encode_length(4+len+paddingLen, lenData, &lenDataLen);
	if(lenDataLen == 0) { return -1; }
	packetLen = 1+lenDataLen+4+len+paddingLen;	
	if(!cs_malloc(&mbuf, packetLen)) { return -1; }
	
	mbuf[0] = 0x0F;
	memcpy(&mbuf[1], lenData, lenDataLen);
	mbuf[1+lenDataLen] = 0x10;
	mbuf[1+lenDataLen+1] = 0x02;
	memcpy(&mbuf[1+lenDataLen+4], buf, len);

	if(paddingLen > 0) {
		mbuf[1+lenDataLen+4+len] = 0x7F;
		mbuf[1+lenDataLen+4+len+1] = paddingLen - 2;
		get_random_bytes(mbuf+1+lenDataLen+4+len+2, paddingLen - 2);
	}
	
	crc = ccitt_crc(mbuf+1+lenDataLen+4, len+paddingLen, 0xFFFF, 0);
	i2b_buf(2, crc, &mbuf[1+lenDataLen+2]);
	
	scam_encrypt_packet(mbuf, packetLen, scam->enckey, 4+len+paddingLen, 1+lenDataLen, &scam->enc_xor_offset);	
	result = send(cl->pfd, mbuf, packetLen, 0);
	NULLFREE(mbuf);
	
	return (result);
}

static int32_t scam_msg_recv(struct s_client *cl, uint8_t *buf, int32_t maxlen)
{
	int32_t len;
	int32_t handle = cl->udp_fd;
	struct scam_data *scam = cl->scam;
	
	if(scam == NULL) { return 0; }
	if(handle <= 0 || maxlen < 3)
		{ cs_log("scam_msg_recv: fd is 0"); return -1; }

	len = recv(handle, buf, 2, MSG_WAITALL);
	if(len != 2)		// invalid header length read
	{
		if(len <= 0)
			{ cs_log_dbg(cl->typ == 'c' ? D_CLIENT : D_READER, "disconnected by remote server"); }
		else
			{ cs_log_dbg(cl->typ == 'c' ? D_CLIENT : D_READER, "invalid header length (expected 2, read %d)", len); }
		return -1;
	}
	
	if(buf[0] != 0x0F) 
	{
		cs_log_dbg(cl->typ == 'c' ? D_CLIENT : D_READER, "invalid packet tag");
		return 0;			
	}
	
	int32_t headerSize = buf[1]&0x80 ? (2 + (buf[1]&~0x80)) : 2;
	if(headerSize > 2) {
		if(maxlen < headerSize+1) { return -1; }
		len = recv(handle, buf+2, headerSize-2, MSG_WAITALL);
		if(len != headerSize-2)		// invalid header length read
		{
			if(len <= 0)
				{ cs_log_dbg(cl->typ == 'c' ? D_CLIENT : D_READER, "disconnected by remote server"); }
			else
				{ cs_log_dbg(cl->typ == 'c' ? D_CLIENT : D_READER, "invalid header length (expected %d, read %d)", headerSize, 2+len); }
			return -1;
		}	
	}
	
	uint32_t dataLength, dataOffset;
	scam_decode_length(buf, &dataLength, &dataOffset);
	
	if(dataLength)		// check if any data is expected in msg
	{
		if(dataLength%8 != 0)
		{
			cs_log_dbg(cl->typ == 'c' ? D_CLIENT : D_READER, "message data has invalid size (size=%d)", dataLength);
			return 0;
		}		
		
		if(headerSize+dataLength > (uint32_t)maxlen)
		{
			cs_log_dbg(cl->typ == 'c' ? D_CLIENT : D_READER, "message too big (size=%d max=%d)", headerSize+dataLength, maxlen);
			return 0;
		}

		len = recv(handle, buf + dataOffset, dataLength, MSG_WAITALL);
		if((uint32_t)len != dataLength)
		{
			if(len <= 0) {
				cs_log_dbg(cl->typ == 'c' ? D_CLIENT : D_READER, "disconnected by remote"); 
			}
			else {
				cs_log_dbg(cl->typ == 'c' ? D_CLIENT : D_READER, "invalid message length read (expected %d, read %d)", dataLength, len);
			}
			return -1;
		}

		scam_decrypt_packet(buf, headerSize+dataLength, scam->deckey, dataLength, dataOffset, &scam->dec_xor_offset);	
	}
	
	return headerSize+dataLength;
}

static int32_t scam_recv(struct s_client *cl, uchar *buf, int32_t len)
{
	int32_t n;
	struct s_reader *rdr = (cl->typ == 'c') ? NULL : cl->reader;

	if(buf == NULL || len <= 0)
		{ return -1; }

	n = scam_msg_recv(cl, buf, len); // recv and decrypt msg
	if(n <= 0)
	{
		cs_log_dbg(cl->typ == 'c' ? D_CLIENT : D_READER, "connection closed by %s, n=%d.", remote_txt(), n);
		if(rdr)
		{
			scam_client_close(cl, 1);
		}
		else
		{
			cs_disconnect_client(cl);
		}
		cs_sleepms(150);
		n = -1;
	}
	else
	{
		cl->last = time(NULL); // last client action is now
		if(rdr) { rdr->last_g = time(NULL); }	// last reader receive is now
	}

	return n;
}

//scam client functions

static int32_t scam_client_init(struct s_client *cl);

static int32_t scam_client_connect(void)
{
	struct s_client *cl = cur_client();
	
	if(cl->reader->tcp_connected < 2 && scam_client_init(cl) < 0)
		{ return 0; }

	if(!cl->udp_fd)
		{ return 0; }

	return 1;
}

static void scam_client_idle(void)
{
	struct s_client *client = cur_client();
	struct s_reader *rdr = client->reader;
	time_t now = time(NULL);
	if(!rdr) { return; }

	if(rdr->tcp_ito > 0)
	{
		int32_t time_diff;
		time_diff = llabs(now - rdr->last_s);
		if(time_diff > (rdr->tcp_ito))
		{
			network_tcp_connection_close(rdr, "inactivity");
			return;
		}
	}
	else if(rdr->tcp_ito == -1)
	{
		scam_client_connect();
		return;
	}
}

static void scam_client_recv_caid(uint8_t *buf, uint32_t len)
{
	uint16_t caid;
	
	if(len < 3) {
		return;
	}
	
	caid = buf[1] << 8 | buf[2];
	if(buf[0]) {
		cs_log("scam server has card: %04X", caid);
	}
	else {
		cs_log("scam server no longer has card: %04X", caid);
	}
}

static void scam_client_recv_server_version(uint8_t *buf, uint32_t len)
{
	uint32_t pos = 0, dataLength = 0, dataOffset = 0, usedLen = 0;
	char versionString[128];
	uint16_t versionShort = 0;
	versionString[0] = 0;
	
	scam_decode_length(buf, &dataLength, &dataOffset);
	
	while(pos+dataOffset+dataLength-1 < len)
	{
		switch(buf[pos]) {
			
			case 0x01: // version string
				usedLen = dataLength;
				if(usedLen > 127) {
					usedLen = 127;
				}
				memcpy(versionString, buf+dataOffset, usedLen);
				versionString[usedLen] = 0;
				break;
				
			case 0x0A: // version short
				if(dataLength != 2) break;
				versionShort = (buf[pos+dataOffset] << 8) | buf[pos+dataOffset+1];
				break;
					
			default:
				cs_log_dbg(D_READER, "unknown server version packet tag %X", buf[pos]); 
				break;
		}
		
		pos += dataOffset+dataLength;
		if(pos+2 < len && pos+1+scam_get_length_data_length(buf+pos) < len) {
			scam_decode_length(buf+pos, &dataLength, &dataOffset);
		}
		else {
			break;	
		}
	}
	
	cs_log("scam server version: %s (%d)", versionString, versionShort);
}

static void scam_client_recv_dcw(struct s_client *cl, uint8_t *buf, uint32_t len, uint8_t *dcw, int32_t *ecm_task_idx, int32_t *rc)
{
	//	00C00000	enimga namespace
	//	0455		tsid
	//	0001			onid
	//	151A		srvid
	//	200081		???
	//	943E85577035C469	dcw1
	//	C73882811721E31B	dcw2
	
	if(len != 29) {
		cs_log_dbg(cl->typ == 'c' ? D_CLIENT : D_READER, "unknown server dcw packet length %d", len); 
		return;
	}
	
	*ecm_task_idx = b2i(4, &buf[0]); // we store idx here instead of ens
	memcpy(dcw, &buf[13], 16);
	*rc = 1;
}

static void scam_client_send_hello(struct s_client *cl) 
{
	uchar mbuf[70];
	uint32_t usernameLen, i = 0;	
	struct s_reader *rdr = cl->reader;
	struct scam_data *scam = cl->scam;
	
	if(scam == NULL) { return; }
	if(!rdr) { return; }

	usernameLen = strlen(rdr->r_usr);
	if(usernameLen > 63) { // because rdr->r_usr is max. 63+1 chars
		usernameLen = 63;	
	}

	mbuf[i++] = 0x46; // client hello data type
	mbuf[i++] = 6 + usernameLen; // will never exceed 63+6 = 69 bytes (<127 bytes)
	
	// client version
	mbuf[i++] = 0xA0; // client version data type
	mbuf[i++] = 0x02; // data length (2)
	mbuf[i++] = 0x00; // version ( 0x0007)
	mbuf[i++] = 0x07;
	
	//username
	mbuf[i++] = 0xA1; // username data type
	mbuf[i++] = (uint8_t)usernameLen;
	memcpy(mbuf+i, rdr->r_usr, usernameLen);
	mbuf[i+usernameLen] = 0;
	
	scam_send(cl, mbuf, 8+usernameLen);
	
	scam_generate_deskey(rdr->r_pwd, scam->enckey);
	scam_generate_deskey(rdr->r_pwd, scam->deckey);
	scam->enc_xor_offset = 0;
	scam->dec_xor_offset = 0;
}

static int32_t scam_client_send_ecm(struct s_client *cl, ECM_REQUEST *er)
{				
	// 2481A5	310A 
	//				00C00000	enimga namespace
	//				0455		tsid
	//				0001		onid
	//				151A		srvid
	//			3002
	//				1843		caid
	//			3304
	//				66A1AE16	pat/pmt crc? we currently fill it with chid
	//			348189			
	//				8130..		ecm
	//			3501
	//				02			needed dcws?

	uchar *mbuf, packetLenData[5], ecmLenData[5];
	uint32_t i = 0, ret = 0, dataLength = 0, packetLength = 0;
	uint8_t pLenDataLen = 0, eLenDataLen = 0;
	
	if(!scam_client_connect())
		{ return (-1); }

	scam_encode_length(er->ecmlen, ecmLenData, &eLenDataLen);
	dataLength = 23 + eLenDataLen + er->ecmlen + 3;
	scam_encode_length(dataLength, packetLenData, &pLenDataLen);
	packetLength = 1 + pLenDataLen + dataLength;
	
	if(!cs_malloc(&mbuf, packetLength))
		{ return -1; }
		
	mbuf[i++] = 0x24; // ecm request data type
	memcpy(mbuf+i, packetLenData, pLenDataLen); i += pLenDataLen;
	
	mbuf[i++] = 0x31; // channel info data type
	mbuf[i++] = 0x0A; // size is always 0x0A
	
	//i2b_buf(4, er->ens, mbuf+i); i += 4;
	i2b_buf(4, er->idx, mbuf+i); i += 4; // we store idx instead of ens here
	
	i2b_buf(2, er->tsid, mbuf+i); i += 2;
	i2b_buf(2, er->onid, mbuf+i); i += 2;
	i2b_buf(2, er->srvid, mbuf+i); i += 2;

	mbuf[i++] = 0x30; // caid data type
	mbuf[i++] = 0x02; // size is always 0x02
	i2b_buf(2, er->caid, mbuf+i); i += 2;	

	mbuf[i++] = 0x33; // ??? data type
	mbuf[i++] = 0x04; // size is always 0x04
	i2b_buf(2, er->chid, mbuf+i); i += 4;	

	mbuf[i++] = 0x34; // ecm data type
	memcpy(mbuf+i, ecmLenData, eLenDataLen); i += eLenDataLen;
	memcpy(mbuf+i, er->ecm, er->ecmlen); i += er->ecmlen;
	
	mbuf[i++] = 0x35; // ??? data type
	mbuf[i++] = 0x01; // size is always 0x01
	mbuf[i++] = 0x02; // unknown value

	ret = scam_send(cl, mbuf, packetLength);

	cs_log_dbg(D_TRACE, "scam: sending ecm");
	cs_log_dump_dbg(D_CLIENT, mbuf, packetLength, "ecm:");
	NULLFREE(mbuf);
	return ((ret < 1) ? (-1) : 0);
}

static int32_t scam_client_init(struct s_client *cl)
{
	int32_t handle;
	
	handle = network_tcp_connection_open(cl->reader);
	if(handle < 0) {
		cl->reader->last_s = 0; // set last send to zero
		cl->reader->last_g = 0; // set last receive to zero
		cl->last = 0; // set last client action to zero
		return (0);
	}
	
	if(cl->scam) {
		memset(cl->scam, 0, sizeof(struct scam_data));
	}

	if(!cl->scam && !cs_malloc(&cl->scam, sizeof(struct scam_data))) {
		return 0;	
	}

	cs_log("scam: proxy %s:%d (fd=%d)",
			cl->reader->device, cl->reader->r_port, cl->udp_fd);

	cl->reader->tcp_connected = 2;
	cl->reader->card_status = CARD_INSERTED;
	cl->reader->last_g = cl->reader->last_s = time((time_t *)0);

	cs_log_dbg(D_CLIENT, "scam: last_s=%ld, last_g=%ld", cl->reader->last_s, cl->reader->last_g);

	cl->pfd = cl->udp_fd;

	scam_client_send_hello(cl);
		
	return (0);
}

static int32_t scam_client_handle(struct s_client *cl, uchar *dcw, int32_t *rc, uchar *buf, int32_t n)
{
	uint32_t pos = 0, packetLength = 0, packetOffset = 0, dataLength = 0, dataOffset = 0;
	int32_t ret = -1;
	
	if(n < 3) {
		return (-1);	
	}
	
	scam_decode_length(buf, &packetLength, &packetOffset);
	pos += packetOffset;

	if(pos+2 < (uint32_t)n && pos+1+scam_get_length_data_length(buf+pos) < (uint32_t)n) {
		scam_decode_length(buf+pos, &dataLength, &dataOffset);
	}
	else {
		return (-1);	
	}
	
	while(pos+dataOffset+dataLength-1 < (uint32_t)n)
	{
		switch(buf[pos]) {			
			case 0x10: // checksum
				if(dataLength != 2) { break; }
				if(b2i(2, &buf[pos+dataOffset]) != ccitt_crc(buf+pos+dataOffset+2, n-pos-dataOffset-2, 0xFFFF, 0)) {
					cs_log_dbg(cl->typ == 'c' ? D_CLIENT : D_READER, "sent packet with invalid checksum"); 
					return (-1);
				}
				break;
				
			case 0x20: // caid list
				scam_client_recv_caid(buf+pos+dataOffset, dataLength);
				break;
				
			case 0x45: // server version
				scam_client_recv_server_version(buf+pos+dataOffset, dataLength);
				break;
				
			case 0x63: // dcw
				scam_client_recv_dcw(cl, buf+pos+dataOffset, dataLength, dcw, &ret, rc);
				break;

			case 0x7F: // padding
				break;
				
			default:
				cs_log_dbg(cl->typ == 'c' ? D_CLIENT : D_READER, "unknown scam server packet %X", buf[pos]);
				break;
		}
		
		pos += dataOffset+dataLength;
		if(pos+2 < (uint32_t)n && pos+1+scam_get_length_data_length(buf+pos) < (uint32_t)n) {
			scam_decode_length(buf+pos, &dataLength, &dataOffset);
		}
		else {
			break;	
		}
	}
	
	return ret;
}

// scam server functions
static uint8_t scam_server_authip_client(struct s_client *cl)
{
	if(cfg.scam_allowed && !check_ip(cfg.scam_allowed, cl->ip))
	{
		cs_log("scam: IP not allowed");
		cs_auth_client(cl, (struct s_auth *)0, NULL);
		cs_disconnect_client(cl);
		return 0;
	}
	
	return 1;
}

static void scam_server_init(struct s_client *cl)
{
	if(!cl->init_done)
	{
		if(IP_ISSET(cl->ip))
			{ cs_log("scam: new connection from %s", cs_inet_ntoa(cl->ip)); }
			
		if(scam_server_authip_client(cl)) {
			if(cl->scam) {
				memset(cl->scam, 0, sizeof(struct scam_data));
			}
			if(cl->scam || cs_malloc(&cl->scam, sizeof(struct scam_data))) {
				cl->init_done = 1;		
			}
		}
	}
	return;
}

static void scam_server_recv_ecm(struct s_client *cl, uchar *buf, int32_t len)
{
	uint32_t pos = 0, dataLength = 0, dataOffset = 0, usedLen = 0;	
	ECM_REQUEST *er;
	uint8_t gotCaid = 0, gotEcm = 0;

	if(len < 1) {
		return;	
	}

	if(!(er = get_ecmtask()))
		{ return; }

	scam_decode_length(buf, &dataLength, &dataOffset);

	while(pos+dataOffset+dataLength-1 < (uint32_t)len)
	{
		switch(buf[pos]) {
			
			case 0x31: // channel data
				if(dataLength != 0x0A) break;
				er->ens = b2i(4, buf+pos+dataOffset);
				er->tsid = b2i(2, buf+pos+dataOffset+4);
				er->onid = b2i(2, buf+pos+dataOffset+6);
				er->srvid = b2i(2, buf+pos+dataOffset+8);
				break;
				
			case 0x30: // caid
				if(dataLength != 0x02) break;
				er->caid = b2i(2, buf+pos+dataOffset);
				gotCaid = 1;
				break;
				
			case 0x33: // unknown
				break;	
							
			case 0x34: // ecm
				usedLen = dataLength;
				if(usedLen > MAX_ECM_SIZE) {
					break;
				}
				er->ecmlen = usedLen;
				memcpy(er->ecm, buf+pos+dataOffset, usedLen);
				gotEcm = 1;
				break;

			case 0x35: // unknown
				break;
				
			default:
				cs_log_dbg(cl->typ == 'c' ? D_CLIENT : D_READER, "sent unknown scam client ecm tag %X", buf[pos]); 
				break;
		}
		
		pos += dataOffset+dataLength;
		if(pos+2 < (uint32_t)len && pos+1+scam_get_length_data_length(buf+pos) < (uint32_t)len) {
			scam_decode_length(buf+pos, &dataLength, &dataOffset);
		}
		else {
			break;	
		}
	}		

	if(gotCaid && gotEcm) {
		get_cw(cl, er);
	}
	else {
		NULLFREE(er);
		cs_log("WARNING: ECM-request corrupt");	
	}
}

static void scam_caidlist_add(uint16_t *caidlist, uint32_t listsize, uint32_t *count, uint16_t caid)
{
	uint32_t i;
	uint8_t exists = 0;
	
	if(*count >= listsize) {
		return;
	}
	
	for(i=0; i<*count; i++) {
		if(caidlist[i] == caid) {
			exists = 1;
			break;
		}
	}
	
	if(!exists) {
		caidlist[*count] = caid;
		(*count)++;	
	}
}

static void scam_server_send_caidlist(struct s_client *cl)
{
	uchar mbuf[5];
	int32_t j;
	uint32_t i = 0;
	uint16_t caids[55];
	uint32_t cardcount = 0;
	struct s_reader *rdr = NULL;
	
	cs_readlock(&readerlist_lock);
	for(rdr = first_active_reader; rdr; rdr = rdr->next)
	{
		if(rdr->caid && chk_ctab(rdr->caid, &cl->ctab)) {
			scam_caidlist_add(caids, ARRAY_SIZE(caids), &cardcount, rdr->caid);
		}
		
		for(j = 0; j < rdr->ctab.ctnum; j++) {
			CAIDTAB_DATA *d = &rdr->ctab.ctdata[j];
			if(d->caid && chk_ctab(d->caid, &cl->ctab)) {
				scam_caidlist_add(caids, ARRAY_SIZE(caids), &cardcount, d->caid);
			}
		}
	}
	cs_readunlock(&readerlist_lock);

	for(j=0; j < (int32_t)cardcount; j++) {
		i = 0;
		mbuf[i++] = 0x20; // caid	data type
		mbuf[i++] = 0x03; // length
		mbuf[i++] = 0x01; // active card
		i2b_buf(2, caids[j], mbuf+i);
		scam_send(cl, mbuf, 5);
	}
}

static void scam_server_send_serverversion(struct s_client *cl)
{
	uchar mbuf[64];
	uint32_t i = 0;
	char *version = "scam/3.60 oscam";
	uint8_t vlen = strlen(version);
	
	mbuf[i++] = 0x45; // server version data type
	mbuf[i++] = 2+vlen+4; // will never exceed 127 bytes

	mbuf[i++] = 0x01; // server version string data type
	mbuf[i++] = vlen; // will never exceed 127 bytes
	memcpy(mbuf+i, version, vlen); i += vlen;
	
	mbuf[i++] = 0x0A; // server version short data type
	mbuf[i++] = 0x02; // is always 0x02
	i2b_buf(2, 0x7, mbuf+i);
	
	scam_send(cl, mbuf, 2+2+vlen+4);
}

static void scam_server_recv_auth(struct s_client *cl, uchar *buf, int32_t len)
{
	uint32_t pos = 0, dataLength = 0, dataOffset = 0, usedLen = 0;
	uint8_t userok = 0;
	struct s_auth *account;
	struct scam_data *scam = cl->scam;
	
	if(scam == NULL) { return; }		
	scam->login_username[0] = 0;
	
	if(len < 1) {
		return;	
	}
	
	scam_decode_length(buf, &dataLength, &dataOffset);
	
	while(pos+dataOffset+dataLength-1 < (uint32_t)len)
	{
		switch(buf[pos]) {
			
			case 0xA0: // version short
				if(dataLength != 2) break;
				scam->version = (buf[pos+dataOffset] << 8) | buf[pos+dataOffset+1];
				break;

			case 0xA1: // username string
				usedLen = dataLength;
				if(usedLen > 64) {
					usedLen = 63;
				}
				memcpy(scam->login_username, buf+pos+dataOffset, usedLen);
				scam->login_username[usedLen] = 0;
				break;
				
			default:
				cs_log_dbg(cl->typ == 'c' ? D_CLIENT : D_READER, "unknown client auth packet tag %X", buf[pos]); 
				break;
		}
		
		pos += dataOffset+dataLength;
		if(pos+2 < (uint32_t)len && pos+1+scam_get_length_data_length(buf+pos) < (uint32_t)len) {
			scam_decode_length(buf+pos, &dataLength, &dataOffset);
		}
		else {
			break;	
		}
	}
	
	for(account = cfg.account; account; account = account->next)
	{
		if(streq(scam->login_username, account->usr)) 
		{	
			userok = 1;
			break;
		}
	}
	
	if(!userok) 
	{
		cs_auth_client(cl, (struct s_auth *)0, NULL);
		cs_disconnect_client(cl);
		return;
	}

	scam->login_pending = 1;
	scam_generate_deskey(account->pwd, scam->enckey);
	scam_generate_deskey(account->pwd, scam->deckey);
	scam->enc_xor_offset = 0;
	scam->dec_xor_offset = 0;
		
	scam_server_send_caidlist(cl);
	scam_server_send_serverversion(cl);
}

static void scam_server_send_dcw(struct s_client *cl, ECM_REQUEST *er)
{
	uchar mbuf[31];
	uint32_t i = 0;
	
	if(!(er->rc < E_NOTFOUND)) {
		return;	
	}

	mbuf[i++] = 0x63; // dcw data type
	mbuf[i++] = 0x1D; // fixed sized < 127
	
	i2b_buf(4, er->ens, mbuf+i); i += 4;
	i2b_buf(2, er->tsid, mbuf+i); i += 2;
	i2b_buf(2, er->onid, mbuf+i); i += 2;
	i2b_buf(2, er->srvid, mbuf+i); i += 2;

	mbuf[i++] = 0x20; // unknown
	mbuf[i++] = 0x00; // unknown
	mbuf[i++] = 0x81; // unknown
	memcpy(mbuf+i, er->cw, 16);

	scam_send(cl, mbuf, 31);
}

static void *scam_server_handle(struct s_client *cl, uchar *buf, int32_t n)
{
	uint32_t pos = 0, packetLength = 0, packetOffset = 0, dataLength = 0, dataOffset = 0;
	struct s_auth *account;
	struct scam_data *scam;
	
	if(n < 3)
		{ return NULL; }

	if(!cl->init_done)
	{
		if(!scam_server_authip_client(cl)) { return NULL; }
		if(cl->scam) {
			memset(cl->scam, 0, sizeof(struct scam_data));
		}
		if(cl->scam == NULL && !cs_malloc(&cl->scam, sizeof(struct scam_data))) {
			return NULL;
		}
		cl->init_done = 1;
	}
	
	scam = cl->scam;
	if(scam == NULL) {
		return NULL;	
	}
	
	scam_decode_length(buf, &packetLength, &packetOffset);
	pos += packetOffset;
	
	if(scam->login_pending && packetLength > 1 && (buf[pos] != 0x10 || buf[pos+1] != 0x02)) {
		scam->login_pending = 0;
		cs_auth_client(cl, (struct s_auth *)0, NULL);
		cs_disconnect_client(cl);
		return NULL;		
	}
	
	if(pos+2 < (uint32_t)n && pos+1+scam_get_length_data_length(buf+pos) < (uint32_t)n) {
		scam_decode_length(buf+pos, &dataLength, &dataOffset);
	}
	else {
		return NULL;	
	}
	
	while(pos+dataOffset+dataLength-1 < (uint32_t)n)
	{
		switch(buf[pos]) {
			
			case 0x10: // checksum
				if(dataLength != 2) { break; }
				if(b2i(2, &buf[pos+dataOffset]) != ccitt_crc(buf+pos+dataOffset+2, n-pos-dataOffset-2, 0xFFFF, 0)) {
					cs_log_dbg(cl->typ == 'c' ? D_CLIENT : D_READER, "sent packet with invalid checksum"); 
					return NULL;
				}
				if(scam->login_pending) {
					for(account = cfg.account; account; account = account->next) {
						if(streq(scam->login_username, account->usr)) {
							scam->login_pending = 0;
							if(!cs_auth_client(cl, account, NULL)) {
								cs_log("scam client login: %s version: %d", scam->login_username, scam->version);
							}
							else {
								cs_disconnect_client(cl);
							}
							break;
						}
					}
					if(scam->login_pending) 
					{
						scam->login_pending = 0;
						cs_auth_client(cl, (struct s_auth *)0, NULL);
						cs_disconnect_client(cl);
						return NULL;
					}
				}				
				break;
				
			case 0x46: // client auth 
				scam_server_recv_auth(cl, buf+pos+dataOffset, dataLength);
				break;
				
			case 0x24: // ecm request
				scam_server_recv_ecm(cl, buf+pos+dataOffset, dataLength);
				break;	
				
			case 0x7F: // padding
				break;
				
			default:
				cs_log_dbg(cl->typ == 'c' ? D_CLIENT : D_READER, "sent unknown scam client packet %X", buf[pos]); 
				break;
		}
		
		pos += dataOffset+dataLength;
		if(pos+2 < (uint32_t)n && pos+1+scam_get_length_data_length(buf+pos) < (uint32_t)n) {
			scam_decode_length(buf+pos, &dataLength, &dataOffset);
		}
		else {
			break;	
		}
	}

	return NULL;
}

void scam_cleanup(struct s_client *cl)
{
	NULLFREE(cl->scam);
}

void module_scam(struct s_module *ph)
{
	ph->desc = "scam";
	ph->type = MOD_CONN_TCP;
	ph->listenertype = LIS_SCAM;
	ph->num = R_SCAM;
	ph->large_ecm_support = 1;
	IP_ASSIGN(ph->s_ip, cfg.scam_srvip);
	ph->ptab.nports = 1;
	ph->ptab.ports[0].s_port = cfg.scam_port;
	// server + client
	ph->recv = scam_recv;
	ph->cleanup = scam_cleanup;
	// server
	ph->s_init = scam_server_init;
	ph->s_handler = scam_server_handle;
	ph->send_dcw = scam_server_send_dcw;
	// client
	ph->c_init = scam_client_init;
	ph->c_idle = scam_client_idle;
	ph->c_recv_chk = scam_client_handle;
	ph->c_send_ecm = scam_client_send_ecm;
}

#endif
