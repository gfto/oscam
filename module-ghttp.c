#include "globals.h"
#ifdef MODULE_GHTTP
#include "oscam-client.h"
#include "oscam-net.h"
#include "oscam-string.h"
#include "oscam-reader.h"
#include "module-dvbapi.h"
#ifdef WITH_SSL
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

typedef struct {
	uint16_t prev_sid;
	ECM_REQUEST last_ecm;
	int do_post_next;
	uchar* session_id;
	pthread_mutex_t conn_mutex;
#ifdef WITH_SSL
	SSL *ssl_handle;
	SSL_CTX *ssl_context;
#endif
} s_ghttp;

typedef struct {
	uint16_t onid;
	uint16_t tsid;
	uint16_t sid;
	uint16_t pid;
} s_ca_context;

static LLIST *ignored_ca_contexts;

static int32_t _ghttp_post_ecmdata(struct s_client *client, ECM_REQUEST* er);

static void _ssl_connect(struct s_client *client, int32_t socket)
{
#ifdef WITH_SSL	
	s_ghttp* context = (s_ghttp*)client->ghttp;

	if (context->ssl_handle) { // cleanup previous
		SSL_shutdown(context->ssl_handle);
		SSL_free(context->ssl_handle);
	}
	if (context->ssl_context)
		SSL_CTX_free(context->ssl_context);

	cs_debug_mask(D_CLIENT, "%s: trying ssl...", client->reader->label);
	SSL_load_error_strings();
	SSL_library_init();
	context->ssl_context = SSL_CTX_new(SSLv23_client_method());
	if (context->ssl_context == NULL)
		ERR_print_errors_fp(stderr);
	context->ssl_handle = SSL_new(context->ssl_context);
	if (context->ssl_handle == NULL)
		ERR_print_errors_fp(stderr);
	if (!SSL_set_fd(context->ssl_handle, socket))
		ERR_print_errors_fp(stderr);
	if (SSL_connect(context->ssl_handle) != 1)
		ERR_print_errors_fp(stderr);
#endif
}

int32_t ghttp_client_init(struct s_client *cl)
{
	int32_t handle;

	cs_log("%s: init google cache client %s:%d (fd=%d)", cl->reader->label, cl->reader->device, cl->reader->r_port, cl->udp_fd);

	handle = network_tcp_connection_open(cl->reader);
	if (handle < 0) return -1;

	cl->reader->tcp_connected = 2;
	cl->reader->card_status = CARD_INSERTED;
	cl->reader->last_g = cl->reader->last_s = time((time_t *)0);

	cl->pfd = cl->udp_fd;

	if (!cl->ghttp) {
		if (!cs_malloc(&(cl->ghttp), sizeof(s_ghttp)))
			return -1;
	}
	memset(cl->ghttp, 0, sizeof(s_ghttp));

	if (cl->reader->ghttp_use_ssl) {
#ifndef WITH_SSL		
		cs_log("%s: use_ssl set but no ssl support available, aborting...", cl->reader->label);
		return -1;
#endif		
		_ssl_connect(cl, handle);
	}

	return 0;
}

static uint32_t javastring_hashcode(uchar* input, int32_t len)
{
	uint32_t h = 0;
	while (/**input &&*/ len--) {
		h = 31 * h + *input++;
	}
	return h;
}

static int32_t ghttp_send(struct s_client *client, uchar *buf, int32_t l)
{		
	cs_debug_mask(D_CLIENT, "%s: sending %d bytes", client->reader->label, l);
	if (!client->pfd) {
		// disconnected? try reinit.
		cs_debug_mask(D_CLIENT, "%s: disconnected?", client->reader->label);
		ghttp_client_init(client);
	}
	
	s_ghttp* context = (s_ghttp*)client->ghttp;
	pthread_mutex_lock(&context->conn_mutex);
	
	if (client->reader->ghttp_use_ssl) {
#ifdef WITH_SSL		
		return SSL_write(context->ssl_handle, buf, l);
#endif		
	} else return send(client->pfd, buf, l, 0);
}

static int32_t ghttp_recv(struct s_client *client, uchar *buf, int32_t l)
{
	int32_t n = -1;
	s_ghttp* context = (s_ghttp*)client->ghttp;
	
	if (!client->pfd) {
		pthread_mutex_unlock(&context->conn_mutex);
		return -1;
	}

	if (client->reader->ghttp_use_ssl) {
#ifdef WITH_SSL		
		n = SSL_read(context->ssl_handle, buf, l);
#endif		
	} else n = recv(client->pfd, buf, l, 0);
	
	pthread_mutex_unlock(&context->conn_mutex);

	if (n > 0) {
		cs_debug_mask(D_CLIENT, "%s: received %d bytes from %s", client->reader->label, n, remote_txt());
		client->last = time((time_t *)0);

		if (n > 300) {
			buf[n] = '\0';
			cs_debug_mask(D_CLIENT, "%s: unexpected reply size %d - %s", client->reader->label, n, buf);
			return -1; // assumes google error, disconnects
		}
	}
	if (n < 5) {
		cs_debug_mask(D_CLIENT, "%s: read %d bytes, disconnecting", client->reader->label, n);
		n = -1;
	}
	return n;
}

static void _add_ignored_pids(uint16_t onid, uint16_t tsid, uint16_t sid, uchar *buf, int len)
{
	int8_t offs = 0;
	uint16_t pid = 0;
	s_ca_context* ignore;

	while (offs < len) {
		pid = b2i(2, buf + offs);
		offs += 2;
		if (cs_malloc(&ignore, sizeof(s_ca_context))) {
			ignore->onid = onid;
			ignore->tsid = tsid;
			ignore->sid = sid;
			ignore->pid = pid;
		}
		if (!ll_contains_data(ignored_ca_contexts, ignore, sizeof(s_ca_context)))
			ll_append(ignored_ca_contexts, ignore);

		while (ll_count(ignored_ca_contexts) > 32)
			ll_remove_first_data(ignored_ca_contexts);

		cs_debug_mask(D_CLIENT, "ignored ca contexts size %d", ll_count(ignored_ca_contexts));
	}
}

static int32_t ghttp_recv_chk(struct s_client *client, uchar *dcw, int32_t *rc, uchar *buf, int32_t n)
{
	char* data;
	char* lenstr;
	uchar* content;
	int rcode, clen = 0;
	s_ghttp* context = (s_ghttp*)client->ghttp;
	ECM_REQUEST *er = &context->last_ecm;

	if (n < 5) return -1;

	data = strstr((char*)buf, "HTTP/1.1 ");
	if (!data) {
		cs_debug_mask(D_CLIENT, "%s: non http or otherwise corrupt response: %s", client->reader->label, buf);
		cs_ddump_mask(D_CLIENT, buf, n, "%s: ", client->reader->label);
		network_tcp_connection_close(client->reader, "receive error or idle timeout");
		return -1;
	}
	data = data + strlen("HTTP/1.1 ");
	rcode = atoi(data);

	lenstr = strstr((char*)buf, "Content-Length: ");
	if (lenstr) {
		lenstr = lenstr + strlen("Content-Length: ");
		clen = atoi(lenstr);
	}
	content = (uchar*)(strstr(data, "\r\n\r\n") + 4);
	
	buf[n] = '\0';
	cs_ddump_mask(D_TRACE, content, clen, "%s: reply\n%s", client->reader->label, buf);

	if (rcode < 200 || rcode > 204) {
		cs_debug_mask(D_CLIENT, "%s: http error code %d", client->reader->label, rcode);
		data = strstr(data, "Content-Type: application/octet-stream"); // if not octet-stream, google error. need reconnect?
		if (data) // we have error info string in the post content
		{
			if (clen > 0) {
				content[clen] = '\0';
				cs_debug_mask(D_CLIENT, "%s: http error message: %s", client->reader->label, content);
			}
		}
		if (rcode == 503) {
			context->prev_sid = 0;
			if (context->do_post_next) {
				cs_debug_mask(D_CLIENT, "%s: recv_chk got 503 despite post, trying reconnect", client->reader->label);
				network_tcp_connection_close(client->reader, "timeout");
				return -1;
			} else {
				// on 503 timeout, switch to POST
				context->do_post_next = 1;
				if (er) {
					cs_debug_mask(D_CLIENT, "%s: recv_chk got 503, trying direct post", client->reader->label);
					_ghttp_post_ecmdata(client, er);
				}

				*rc = 0;
				memset(dcw, 0, 16);
				return -1;
			}
		} else if (rcode == 401) {
			context->do_post_next = 1;
			NULLFREE(context->session_id);
			if (er) {
				cs_debug_mask(D_CLIENT, "%s: session expired, trying direct post", client->reader->label);
				_ghttp_post_ecmdata(client, er);
			}

			*rc = 0;
			memset(dcw, 0, 16);
			return -1;
		}
		return -1;
	}

	// successful http reply (200 ok or 204 no content)

	data = strstr((char*)buf, "Set-Cookie: GSSID=");
	if (data) { // new session cookie included
		data += strlen("Set-Cookie: GSSID=");
		NULLFREE(context->session_id);
		if (cs_malloc(&context->session_id, 7)) { // todo dont assume session id of length 6
			strncpy((char*)context->session_id, data, 6);
			context->session_id[6] = '\0';
			cs_debug_mask(D_CLIENT, "%s: set session_id to: %s", client->reader->label, context->session_id);
		}
	}

	data = strstr((char*)buf, "Pragma: context-ignore=");
	if (data && clen > 0) { // this is a pmt response with ecm pids to ignore in the content
		data += strlen("Pragma: context-ignore=");
		int len = strstr(data, "\r\n") - data;
		data[len + 1] = '\0';
		cs_ddump_mask(D_CLIENT, content, clen, "%s: pmt ignore reply - %s (%d pids)", client->reader->label, data, clen / 2);
		uint32_t onid = 0, tsid = 0, sid = 0;
		if (sscanf(data, "%4x-%4x-%4x", &onid, &tsid, &sid) == 3)
			_add_ignored_pids(onid, tsid, sid, content, clen);
		return -1;
	}

	// switch back to cache get after rapid ecm response (arbitrary atm), only effect is a slight bw save for client
	if (context->do_post_next) {
		data = strstr((char*)buf, "Pragma: cached");
		if (data || (client->cwlastresptime > 0 && client->cwlastresptime < 750)) {
			cs_debug_mask(D_CLIENT, "%s: probably cached cw (%d ms), switching back to cache get for next req", client->reader->label, client->cwlastresptime);
			context->do_post_next = 0;
		}
	}

	if (clen == 16) { // cw in content
		memcpy(dcw, content, 16);
		*rc = 1;
		cs_ddump_mask(D_TRACE, dcw, 16, "%s: cw recv chk", client->reader->label);
		return client->reader->msg_idx;
	} else {
		if (clen != 0) cs_ddump_mask(D_CLIENT, content, clen, "%s: recv_chk fail, clen = %d", client->reader->label, clen);
	}
	return -1;
}

static char* _ghttp_basic_auth(struct s_client *client)
{
	uchar auth[64];
	char* encauth = NULL;
	int32_t ret;
	s_ghttp* context = (s_ghttp*)client->ghttp;

	if (!context->session_id && strlen(client->reader->r_usr) > 0) {
		cs_debug_mask(D_CLIENT, "%s: username specified and no existing session, adding basic auth", client->reader->label);
		ret = snprintf((char*)auth, sizeof(auth), "%s:%s", client->reader->r_usr, client->reader->r_pwd);
		ret = b64encode((char*)auth, ret, &encauth);
	}
	return encauth;
}

static int32_t _ghttp_http_get(struct s_client *client, uint32_t hash, int odd)
{
	uchar req[128];
	char* encauth = NULL;
	int32_t ret;
	s_ghttp* context = (s_ghttp*)client->ghttp;

	encauth = _ghttp_basic_auth(client);

	if (encauth) { // basic auth login
		ret = snprintf((char*)req, sizeof(req), "GET /api/c/%d/%x HTTP/1.1\r\nHost: %s\r\nAuthorization: Basic %s\r\n\r\n", odd ? 81 : 80, hash, client->reader->device, encauth);
	} else {
		if (context->session_id) { // session exists
			ret = snprintf((char*)req, sizeof(req), "GET /api/c/%s/%d/%x HTTP/1.1\r\nHost: %s\r\n\r\n", context->session_id, odd ? 81 : 80, hash, client->reader->device);
		} else { // no credentials configured, assume no session required
			ret = snprintf((char*)req, sizeof(req), "GET /api/c/%d/%x HTTP/1.1\r\nHost: %s\r\n\r\n", odd ? 81 : 80, hash, client->reader->device);
		}
	}

	ret = ghttp_send(client, req, ret);

	return ret;
}

static int32_t _ghttp_post_ecmdata(struct s_client *client, ECM_REQUEST* er)
{
	uchar req[640];
	uchar* end;
	char* encauth = NULL;
	int32_t ret;
	s_ghttp* context = (s_ghttp*)client->ghttp;

	encauth = _ghttp_basic_auth(client);

	if (encauth) { // basic auth login
		ret = snprintf((char*)req, sizeof(req), "POST /api/e/%x/%x/%x/%x/%x/%x HTTP/1.1\r\nHost: %s\r\nAuthorization: Basic %s\r\nContent-Length: %d\r\n\r\n", er->onid, er->tsid, er->pid, er->srvid, er->caid, er->prid, client->reader->device, encauth, er->ecmlen);
	} else {
		if (context->session_id) { // session exists
			ret = snprintf((char*)req, sizeof(req), "POST /api/e/%s/%x/%x/%x/%x/%x/%x HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", context->session_id, er->onid, er->tsid, er->pid, er->srvid, er->caid, er->prid, client->reader->device, er->ecmlen);
		} else { // no credentials configured, assume no session required
			ret = snprintf((char*)req, sizeof(req), "POST /api/e/%x/%x/%x/%x/%x/%x HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", er->onid, er->tsid, er->pid, er->srvid, er->caid, er->prid, client->reader->device, er->ecmlen);
		}
	}
	end = req + ret;
	memcpy(end, er->ecm, er->ecmlen);

	cs_debug_mask(D_CLIENT, "%s: sending full ecm - /api/e/%x/%x/%x/%x/%x/%x", client->reader->label, er->onid, er->tsid, er->pid, er->srvid, er->caid, er->prid);

	ret = ghttp_send(client, req, ret + er->ecmlen);

	return ret;
}

static bool _is_pid_ignored(uint16_t onid, uint16_t tsid, uint16_t sid, uint16_t pid)
{
	s_ca_context* ignore;
	if (cs_malloc(&ignore, sizeof(s_ca_context))) {
		ignore->onid = onid;
		ignore->tsid = tsid;
		ignore->sid = sid;
		ignore->pid = pid;
		if (ll_contains_data(ignored_ca_contexts, ignore, sizeof(s_ca_context))) return true;
	}
	return false;
}

static int32_t ghttp_send_ecm(struct s_client *client, ECM_REQUEST *er, uchar *UNUSED(buf))
{
	uint32_t hash;
	s_ghttp* context = (s_ghttp*)client->ghttp;

	if (_is_pid_ignored(er->onid, er->tsid, er->srvid, er->pid)) {
		cs_debug_mask(D_CLIENT, "ca context found in ignore list, ecm blocked: %x-%x-%x pid %x", er->onid, er->tsid, er->srvid, er->pid);
		return -1;
	}
	context->prev_sid = context->last_ecm.srvid;

	client->reader->msg_idx = er->idx;
	if (context->do_post_next) {
		_ghttp_post_ecmdata(client, er);
	} else {
		hash = javastring_hashcode(er->ecm + 3, er->ecmlen - 3);
		_ghttp_http_get(client, hash, er->ecm[0] == 0x81);
	}

	context->last_ecm = *er; //struct copy

	return 0;
}

#ifdef HAVE_DVBAPI

static int32_t ghttp_capmt_notify(struct s_client *client, struct demux_s *demux)
{
	uchar req[640], lenhdr[64] = "";
	uchar* pids;
	uchar* end;
	char* encauth = NULL;
	int32_t ret;
	int8_t i, pids_len = 0, offs = 0;
	s_ghttp* context = (s_ghttp*)client->ghttp;

	if (!context) return -1;

	cs_debug_mask(D_CLIENT, "%s: capmt %x-%x-%x %d pids on adapter %d mask %x dmx index %d", client->reader->label, demux->onid, demux->tsid, demux->program_number, demux->ECMpidcount, demux->adapter_index, demux->ca_mask, demux->demux_index);

	if (demux->ECMpidcount > 0) {
		if (cs_malloc(&pids, demux->ECMpidcount * 8)) {
			pids_len = demux->ECMpidcount * 8;
			for (i = 0; i < demux->ECMpidcount; i++) {
				i2b_buf(2, demux->ECMpids[i].ECM_PID, pids + offs);
				i2b_buf(2, demux->ECMpids[i].CAID, pids + (offs += 2));
				i2b_buf(4, demux->ECMpids[i].PROVID, pids + (offs += 2));
				offs += 4;
			}
			snprintf((char*)lenhdr, sizeof(lenhdr), "\r\nContent-Length: %d", pids_len);
		}
	}

	encauth = _ghttp_basic_auth(client);

	if (encauth) { // basic auth login
		ret = snprintf((char*)req, sizeof(req), "%s /api/p/%x/%x/%x/%x/%x HTTP/1.1\r\nHost: %s\r\nAuthorization: Basic %s%s\r\n\r\n", ((pids_len > 0) ? "POST" : "GET"), demux->onid, demux->tsid, demux->program_number, demux->ECMpidcount, demux->enigma_namespace, client->reader->device, encauth, lenhdr);
	} else {
		if (context->session_id) { // session exists
			ret = snprintf((char*)req, sizeof(req), "%s /api/p/%s/%x/%x/%x/%x/%x HTTP/1.1\r\nHost: %s%s\r\n\r\n", ((pids_len > 0) ? "POST" : "GET"), context->session_id, demux->onid, demux->tsid, demux->program_number, demux->ECMpidcount, demux->enigma_namespace, client->reader->device, lenhdr);
		} else { // no credentials configured, assume no session required
			ret = snprintf((char*)req, sizeof(req), "%s /api/p/%x/%x/%x/%x/%x HTTP/1.1\r\nHost: %s%s\r\n\r\n", ((pids_len > 0) ? "POST" : "GET"), demux->onid, demux->tsid, demux->program_number, demux->ECMpidcount, demux->enigma_namespace, client->reader->device, lenhdr);
		}
	}
	end = req + ret;
	if (pids_len > 0) memcpy(end, pids, pids_len);

	cs_ddump_mask(D_CLIENT, pids, pids_len, "%s: sending capmt ecm pids - %s /api/p/%x/%x/%x/%x/%x", client->reader->label, (pids_len > 0) ? "POST" : "GET", demux->onid, demux->tsid, demux->program_number, demux->ECMpidcount, demux->enigma_namespace);

	ret = ghttp_send(client, req, ret + pids_len);

	if (pids_len > 0) {
		cs_debug_mask(D_CLIENT, "%s: new unscrambling detected, switching to post", client->reader->label);
		context->do_post_next = 1;
		NULLFREE(pids);
	}

	return 0;
}
#endif

void module_ghttp(struct s_module *ph)
{
	ph->ptab.nports = 0;
	// ph->ptab.ports[0].s_port = cfg.ghttp_port;
	ph->desc = "ghttp";
	ph->type = MOD_CONN_TCP;
	// ph->listenertype = LIS_GHTTP;    
	ph->recv = ghttp_recv;
	ph->c_init = ghttp_client_init;
	ph->c_recv_chk = ghttp_recv_chk;
	ph->c_send_ecm = ghttp_send_ecm;
#ifdef HAVE_DVBAPI	
	ph->c_capmt = ghttp_capmt_notify;
#endif
	ph->num = R_GHTTP;
	if (!ignored_ca_contexts) ignored_ca_contexts = ll_create("ignored ca contexts");
}
#endif
