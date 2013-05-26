/*
 * module-csp.c
 *
 *  Created on: 20.12.2011
 *      Author: Corsair
 */

#include "globals.h"

#ifdef CS_CACHEEX

#include "module-cacheex.h"
#include "oscam-ecm.h"
#include "oscam-net.h"
#include "oscam-string.h"

#define TYPE_REQUEST   1
#define TYPE_REPLY     2
#define TYPE_PINGREQ   3
#define TYPE_PINGRPL   4
#define TYPE_RESENDREQ 5

#define FAKE_ONID      0xFFFF
#define FAKE_TAG       0x80

static void * csp_server(struct s_client *client __attribute__((unused)), uchar *mbuf __attribute__((unused)), int32_t n __attribute__((unused)))
{
	return NULL;
}

static int32_t csp_recv(struct s_client *client, uchar *buf, int32_t l)
{
	int32_t rs = 0;
	if (!client->udp_fd) return(-9);
	if (client->is_udp && client->typ == 'c') {
		rs = recv_from_udpipe(buf); // whats this? 
	} else {
		rs = recv(client->udp_fd, buf, client->is_udp ? l : 36, 0);
	}
	//cs_ddump_mask(D_TRACE, buf, rs, "received %d bytes from csp", rs);

	uint8_t type = buf[0]; // TYPE
	uint8_t commandTag = buf[1]; // first ecm byte indicating odd or even (0x80 or 0x81)

	switch (type) {
		case TYPE_REPLY: // request hash + reply received:
			if (rs >= 29) {
				uint16_t srvid = (buf[2] << 8) | buf[3];
				uint16_t onid = (buf[4] << 8) | buf[5];
				uint16_t caid = (buf[6] << 8) | buf[7];
				int32_t hash = (buf[8] << 24) | (buf[9] << 16) | (buf[10] << 8) | buf[11];
				uint8_t rplTag = buf[12];

				ECM_REQUEST *er = get_ecmtask();
				if (!er) return -1;

				er->caid = caid;
				er->onid = onid;
				er->srvid = srvid;
				er->csp_hash = hash;
				er->ecm[0] = commandTag;
				er->rc = E_FOUND;
				
				if (chk_csp_ctab(er, &cfg.csp.filter_caidtab)) {
					memcpy(er->cw, buf + 13, sizeof(er->cw));
					uchar orgname[32] = {0};
					if (rs >= 31) {
						// origin connector name included
						uint16_t namelen = (buf[29] << 8) | buf[30];
						if (namelen > sizeof(orgname)) namelen = sizeof(orgname);
						memcpy(orgname, buf + 31, namelen);
					}
					cs_ddump_mask(D_TRACE, er->cw, sizeof(er->cw), "received cw from csp onid=%04X caid=%04X srvid=%04X hash=%08X (org connector: %s, tags: %02X/%02X)", onid, caid, srvid, hash, orgname, commandTag, rplTag);
					cacheex_add_to_cache_from_csp(client, er);
				} else free(er);
			}
			break;

		case TYPE_REQUEST: // pending request hash received
			if (rs == 12) { // ignore requests for arbitration (csp "pre-requests", size 20)
				uint16_t srvid = (buf[2] << 8) | buf[3];
				uint16_t onid = (buf[4] << 8) | buf[5];
				uint16_t caid = (buf[6] << 8) | buf[7];
				int32_t hash = (buf[8] << 24) | (buf[9] << 16) | (buf[10] << 8) | buf[11];

				ECM_REQUEST *er = get_ecmtask();
				if (!er) return -1;

				er->caid = caid;
				er->onid = onid;
				er->srvid = srvid;
				er->csp_hash = hash;
				er->ecm[0] = commandTag;
				er->rc = E_UNHANDLED;
				
				if (chk_csp_ctab(er, &cfg.csp.filter_caidtab) && cfg.csp.allow_request) {
					cs_ddump_mask(D_TRACE, buf, l, "received ecm request from csp onid=%04X caid=%04X srvid=%04X hash=%08X (tag: %02X)", onid, caid, srvid, hash, commandTag);
					cacheex_add_to_cache_from_csp(client, er);
				} else free(er);
			}
			break;

		case TYPE_PINGREQ:
			if (rs == 13) {
				uint32_t port = b2i(4, buf + 9);
				/* 
				struct SOCKADDR peer_sa;
				memset((char *) &peer_sa, 0, sizeof(peer_sa));
				SIN_GET_FAMILY(peer_sa) = client->udp_sa.sin_family;
				IP_ASSIGN(SIN_GET_ADDR(peer_sa), client->udp_sa.sin_addr.s_addr);
				SIN_GET_PORT(peer_sa) = htons(port);
				 */
				SIN_GET_PORT(client->udp_sa) = htons(port);
				uchar pingrpl[9];
				pingrpl[0] = TYPE_PINGRPL;
				memcpy(pingrpl + 1, buf + 1, 8);
				int32_t status = sendto(client->udp_fd, pingrpl, sizeof(pingrpl), 0, (struct sockaddr *) &client->udp_sa, client->udp_sa_len);
				cs_debug_mask(D_TRACE, "received ping from cache peer: %s:%d (replied: %d)", cs_inet_ntoa(client->udp_sa.sin_addr.s_addr), port, status);
			}
			break;

		case TYPE_PINGRPL:
			break;

		case TYPE_RESENDREQ:
			break;

		default:
			cs_debug_mask(D_TRACE, "unknown csp cache message received: %d", type);
	}

	return rs;
}

int32_t csp_cache_push_out(struct s_client *cl, struct ecm_request_t *er)
{
	int8_t rc = (er->rc < E_NOTFOUND) ? E_FOUND : er->rc;
	uint8_t size = 0, type;

	switch (rc) {
		case E_FOUND: // we have the cw
			size = 29;
			type = TYPE_REPLY;
			break;
		case E_UNHANDLED: // request pending
			size = 12;
			type = TYPE_REQUEST;
			break;
		default:
			return -1;

	}

	uchar *buf;
	if (!cs_malloc(&buf, size)) return -1;

	uint16_t onid = er->onid;
	if (onid == 0) onid = FAKE_ONID;
	uint8_t tag = er->ecm[0];
	if (tag == 0) tag = FAKE_TAG;

	buf[0] = type;
	buf[1] = tag;
	i2b_buf(2, er->srvid, buf + 2);
	i2b_buf(2, onid, buf + 4);
	i2b_buf(2, er->caid, buf + 6);
	i2b_buf(4, er->csp_hash, buf + 8);

	if (rc == E_FOUND) {
		buf[12] = er->ecm[0];
		memcpy(buf + 13, er->cw, sizeof(er->cw));
	}

	cs_ddump_mask(D_TRACE, buf, size, "pushing cache update to csp onid=%04X caid=%04X srvid=%04X hash=%08X (tag: %02X)", onid, er->caid, er->srvid, er->csp_hash, tag);
	/*
	struct SOCKADDR peer_sa = {0};
	SIN_GET_FAMILY(peer_sa) = cl->udp_sa.sin_family;
	cs_inet_addr("127.0.0.1", &peer_sa.sin_addr.s_addr);
	SIN_GET_PORT(peer_sa) = htons(12346);
	int32_t status = sendto(cl->udp_fd, buf, size, 0, (struct sockaddr *)&peer_sa, sizeof(peer_sa));
	*/
	int32_t status = sendto(cl->udp_fd, buf, size, 0, (struct sockaddr *)&cl->udp_sa, cl->udp_sa_len);
	free(buf);
	return status;
}

void module_csp(struct s_module *ph)
{
	ph->ptab.nports = 1;
	ph->ptab.ports[0].s_port = cfg.csp_port;

	ph->desc = "csp";
	ph->type = MOD_CONN_UDP;
	ph->large_ecm_support = 1;
	ph->listenertype = LIS_CSPUDP;
	IP_ASSIGN(ph->s_ip, cfg.csp_srvip);
	ph->s_handler = csp_server;
	ph->recv = csp_recv;
	ph->c_cache_push = csp_cache_push_out;
	ph->num = R_CSP;
}

#endif
