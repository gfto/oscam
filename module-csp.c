/*
 * module-csp.c
 *
 *  Created on: 20.12.2011
 *      Author: Corsair
 */

#include "globals.h"

#ifdef CS_CACHEEX

#include "module-cacheex.h"

#define TYPE_REQUEST   1
#define TYPE_REPLY     2
#define TYPE_PINGREQ   3
#define TYPE_PINGRPL   4
#define TYPE_RESENDREQ 5

int32_t csp_ecm_hash_calc(uchar *buf, int32_t n)
{
	int32_t i = 0;
	int32_t h = 0;
    for (i = 0; i < n; i++) {
    	h = 31*h + buf[i];
    }
    return h;
}

int32_t csp_ecm_hash(ECM_REQUEST *er)
{
	return csp_ecm_hash_calc(er->ecm+3, er->l-3);
}

static void * csp_server(struct s_client *client __attribute__((unused)), uchar *mbuf __attribute__((unused)), int32_t n __attribute__((unused)))
{
	return NULL;
}

static void csp_server_init(struct s_client * client) {
	client->is_udp = 1;
}

static int32_t csp_recv(struct s_client *client, uchar *buf, int32_t l)
{
	int32_t rs = 0;
	if (!client->udp_fd) return(-9);
	if (client->is_udp && client->typ == 'c') {
		rs=recv_from_udpipe(buf);
	} else {
		rs = recv(client->udp_fd, buf, client->is_udp ? l : 36, 0);
	}
	//cs_ddump_mask(D_TRACE, buf, rs, "received %d bytes from csp", rs);

	uint8_t type = buf[0]; //TYPE
	//int8_t commandTag = buf[1]; //commandTag

    switch(type) {
      case TYPE_REPLY: // We got a CW:
    	  if (rs >= 29) {
			uint16_t srvid = (buf[2] << 8) | buf[3];
			//uint16_t nwid = (buf[4] << 8) | buf[5];
			uint16_t caid = (buf[6] << 8) | buf[7];
			int32_t hash = (buf[8] << 24) | (buf[9] << 16) | (buf[10] << 8) | buf[11];
			//int8_t commandTag2 = buf[12];

			ECM_REQUEST *er = get_ecmtask();
			if (!er)
				return -1;

			er->caid = caid;
			er->srvid = srvid;
			er->csp_hash = hash;
			er->rc = E_FOUND;
			memcpy(er->cw, buf+13, sizeof(er->cw));

			cs_ddump_mask(D_TRACE, er->cw, sizeof(er->cw), "received cw from csp caid=%04X srvid=%04X hash=%08X", caid, srvid, hash);
			cacheex_add_to_cache_from_csp(client, er);
    	  }
        break;

      case TYPE_REQUEST: // We got an Request:
    	  if (rs >= 12) {
			uint16_t srvid = (buf[2] << 8) | buf[3];
			//uint16_t nwid = (buf[4] << 8) | buf[5];
			uint16_t caid = (buf[6] << 8) | buf[7];
			int32_t hash = (buf[8] << 24) | (buf[9] << 16) | (buf[10] << 8) | buf[11];
			//int8_t commandTag2 = buf[12];

			ECM_REQUEST *er = get_ecmtask();
			if (!er)
				return -1;

			er->caid = caid;
			er->srvid = srvid;
			er->csp_hash = hash;
			er->rc = E_UNHANDLED;

			cs_ddump_mask(D_TRACE, buf, l, "received ecm request from csp caid=%04X srvid=%04X hash=%08X", caid, srvid, hash);
			cacheex_add_to_cache_from_csp(client, er);
    	  }
        break;

      case TYPE_PINGREQ:
        break;

      case TYPE_PINGRPL:
        break;

      case TYPE_RESENDREQ:
        break;

      default:
        cs_debug_mask(D_TRACE, "Unknown cache message received");
    }

	return rs;
}

//int32_t csp_send(struct s_client *client, ECM_REQUEST *er, struct s_ecm_answer *ea)
//{
//	int8_t rc = ea?ea->rc:er->rc;
//	uint8_t *cw = ea?ea->cw:er->cw;
//
//	uint8_t buf[512];
//	memset(buf, 0, sizeof(buf));
//	uint16_t srvid = (buf[2] << 8) | buf[3];
//	//uint16_t nwid = (buf[4] << 8) | buf[5];
//	uint16_t caid = (buf[6] << 8) | buf[7];
//	int32_t hash = (buf[8] << 24) | (buf[9] << 16) | (buf[10] << 8) | buf[11];
//	//int8_t commandTag2 = buf[12];
//
//	switch(rc) {
//		case E_FOUND:
//			buf[0] = TYPE_REPLY;
//
//			break;
//
//	}
//}

//
//static void csp_send_dcw(struct s_client *client, ECM_REQUEST *er)
//{
//}
//
//int32_t csp_client_init(struct s_client *client)
//{
//	return -1;
//}
//
//static int32_t csp_recv_chk(struct s_client *client, uchar *dcw, int32_t *rc, uchar *buf, int32_t rc2)
//{
//	return -1;
//}
//
//static int32_t csp_send_ecm(struct s_client *client, ECM_REQUEST *er, uchar *buf)
//{
//	return -1;
//}
//
void module_csp(struct s_module *ph)
{
  static PTAB ptab; //since there is always only 1 csp server running, this is threadsafe
  ptab.ports[0].s_port = cfg.csp_port;
  ph->ptab = &ptab;
  ph->ptab->nports = 1;

  ph->desc="csp";
  ph->type=MOD_CONN_UDP;
  ph->large_ecm_support = 1;
  ph->listenertype = LIS_CSPUDP;
  ph->multi=1;
  IP_ASSIGN(ph->s_ip, cfg.csp_srvip);
  ph->s_handler=csp_server;
  ph->s_init=csp_server_init;
  ph->recv=csp_recv;
//  ph->send_dcw=csp_send_dcw;
  ph->c_multi=1;
//  ph->c_init=csp_client_init;
//  ph->c_recv_chk=csp_recv_chk;
//  ph->c_send_ecm=csp_send_ecm;
//  ph->c_send_emm=csp_send_emm;
//  ph->c_init_log=csp_client_init_log;
//  ph->c_recv_log=csp_recv_log;
//  ph->c_cache_push=csp_cache_push_out;
  ph->num=R_CSP;
}

#endif
