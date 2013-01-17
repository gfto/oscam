#include "globals.h"
#ifdef MODULE_GHTTP
#include "oscam-client.h"
#include "oscam-net.h"
#include "oscam-string.h"

typedef struct
{
  uint16_t prev_sid;
  ECM_REQUEST last_ecm;
  int do_post_next;
  uchar* session_id;
} s_ghttp;

static int32_t _ghttp_post_ecmdata(struct s_client *client, ECM_REQUEST* er);

int32_t ghttp_client_init(struct s_client *cl)
{
  int32_t handle;

  cs_log("%s: init cache client %s:%d (fd=%d)", cl->reader->label, cl->reader->device, cl->reader->r_port, cl->udp_fd);    

  handle = network_tcp_connection_open(cl->reader);
  if(handle < 0) return -1;

  cl->reader->tcp_connected = 2;
  cl->reader->card_status = CARD_INSERTED;
  cl->reader->last_g = cl->reader->last_s = time((time_t *)0);

  cl->pfd = cl->udp_fd;

  if(!cl->ghttp) {
    if(!cs_malloc(&(cl->ghttp), sizeof (s_ghttp)))
      return -1;
  }
  memset(cl->ghttp, 0, sizeof (s_ghttp));

  cs_debug_mask(D_CLIENT, "%s: last_s=%ld, last_g=%ld", cl->reader->label, cl->reader->last_s, cl->reader->last_g);
  
  return 0;
}


static inline unsigned char to_uchar (char ch)
{
  return ch;
}

void base64_encode(const char *in, size_t inlen, char *out, size_t outlen)
{
  static const char b64str[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  while (inlen && outlen) {
    *out++ = b64str[(to_uchar (in[0]) >> 2) & 0x3f];
    if (!--outlen) break;
    *out++ = b64str[((to_uchar (in[0]) << 4) + (--inlen ? to_uchar (in[1]) >> 4 : 0)) & 0x3f];
    if (!--outlen) break;
    *out++ = (inlen ? b64str[((to_uchar (in[1]) << 2) + (--inlen ? to_uchar (in[2]) >> 6 : 0)) & 0x3f] : '=');
    if (!--outlen) break;
    *out++ = inlen ? b64str[to_uchar (in[2]) & 0x3f] : '=';
    if (!--outlen) break;
    if (inlen) inlen--;
    if (inlen) in += 3;

    if (outlen) *out = '\0';
  }
}

size_t b64encode(const char *in, size_t inlen, char **out)
{
  size_t outlen = 1 + BASE64_LENGTH (inlen);
  if (inlen > outlen) {
    *out = NULL;
    return 0;
  }
  if(!cs_malloc(out, outlen)) return -1;
  base64_encode (in, inlen, *out, outlen);
  return outlen - 1;
}

uint32_t javastring_hashcode(uchar* input, int32_t len)
{
  uint32_t h = 0;
  while(/**input &&*/ len--) {
    h = 31 * h + *input++;
  }
  return h;
}

static int32_t ghttp_send(struct s_client * client, uchar *buf, int32_t l)
{
  cs_debug_mask(D_CLIENT, "%s: sending %d bytes", client->reader->label, l);
  if(!client->pfd) {
    //disconnected? try reinit.
    cs_debug_mask(D_CLIENT, "%s: disconnected?", client->reader->label);
    ghttp_client_init(client);
  }
  return send(client->pfd, buf, l, 0);
}

static int32_t ghttp_recv(struct s_client *client, uchar *buf, int32_t l)
{
  int32_t n = -1;
  if(!client->pfd) return (-1);

  if((n = recv(client->pfd, buf, l, 0)) > 0) {
    cs_debug_mask(D_CLIENT, "%s: received %d bytes from %s", client->reader->label, n, remote_txt());
    client->last = time((time_t *)0);

    if(n > 300) return -1; //assumes google error, disconnects
  }
  return n;
}

static int32_t ghttp_recv_chk(struct s_client *client, uchar *dcw, int32_t *rc, uchar *buf, int32_t UNUSED(n))
{
  char* data;
  char* lenstr;
  int rcode, len = 0;
  s_ghttp* context = (s_ghttp*)client->ghttp;
  ECM_REQUEST *er = &context->last_ecm;

  data = strstr((char*)buf, "HTTP/1.1");
  if(!data) {
    cs_debug_mask(D_CLIENT, "%s: non http or otherwise corrupt response/disconnect: %s", client->reader->label, buf);     
    network_tcp_connection_close(client->reader, "receive error or idle timeout");
    return -1;
  }
  data = data + strlen("HTTP/1.1 ");
  rcode = atoi(data);
  if(rcode < 200 || rcode > 204) {
    cs_debug_mask(D_CLIENT, "%s: http error code %d", client->reader->label, rcode);    
    data = strstr(data, "Content-Type: application/octet-stream"); // if not octet-stream, google error. need reconnect?
    if(data) // we have error info string in data
    { 
      lenstr = strstr((char*)buf, "Content-Length: ");
      if(lenstr) {
        lenstr = lenstr + strlen("Content-Length: ");
        len = atoi(lenstr);
      }
      data = strstr(data, "\r\n\r\n") + 4;
      if(data) {
        data[len] = '\0';
        cs_debug_mask(D_CLIENT, "%s: http error message: %s", client->reader->label, data);
      }      
    }
    if(rcode == 503) {
      context->prev_sid = 0;
      if(context->do_post_next) {
        cs_debug_mask(D_CLIENT, "%s: recv_chk got 503 despite post, trying reconnect", client->reader->label);        
        network_tcp_connection_close(client->reader, "timeout");
        return -1;
      } else {
        // on 503 timeout, switch to POST
        context->do_post_next = 1;
        cs_debug_mask(D_CLIENT, "%s: recv_chk got 503, trying direct post", client->reader->label);         
        _ghttp_post_ecmdata(client, er);

        *rc = 0;
        memset(dcw, 0, 16);
        return -1;
      }
    } else if(rcode == 401) {
      cs_debug_mask(D_CLIENT, "%s: session expired, trying direct post", client->reader->label); 
      context->do_post_next = 1;
      NULLFREE(context->session_id);
      _ghttp_post_ecmdata(client, er);

      *rc = 0;
      memset(dcw, 0, 16);
      return -1;
    }
    return -1;
  }

  // switch back to cache get after rapid ecm response (arbitrary atm), only effect is a slight bw save for client
  if(context->do_post_next && context->last_ecm.srvid == context->prev_sid) {
    if(client->cwlastresptime > 0 && client->cwlastresptime < 800) {
      cs_debug_mask(D_CLIENT, "%s: prev resp time for same sid was %d ms, switching back to cache get for next req", client->reader->label, client->cwlastresptime); 
      context->do_post_next = 0;
    }
  }

  data = strstr((char*)buf, "Set-Cookie: GSSID=");
  if(data) {
    data += strlen("Set-Cookie: GSSID=");
    NULLFREE(context->session_id);
    if(cs_malloc(&context->session_id, 7)) { // todo dont assume session id of length 6
      strncpy((char*)context->session_id, data, 6);
      context->session_id[6] = '\0';
      cs_debug_mask(D_CLIENT, "%s: set session_id to: %s", client->reader->label, context->session_id);
    }
  }

  data = strstr((char*)buf, "Content-Length: 16");
  if(data) {
    data = strstr((char*)buf, "\r\n\r\n");
    data += 4;
    memcpy(dcw, data, 16);
    *rc = 1;
    char tmp_dbg[33];
    cs_debug_mask(D_CLIENT, "%s: recv chk - %s", client->reader->label, cs_hexdump(0, dcw, 16, tmp_dbg, sizeof (tmp_dbg)));
    return client->reader->msg_idx;
  } else {
    cs_debug_mask(D_CLIENT, "%s: recv_chk fail!", client->reader->label);
  }
  return -1;
}

static int32_t _ghttp_http_get(struct s_client *client, uint32_t hash, int odd)
{
  uchar req[128], auth[64];
  char* encauth = NULL;
  int32_t ret;
  s_ghttp* context = (s_ghttp*)client->ghttp;

  if(!context->session_id && strlen(client->reader->r_usr) > 0) {
    cs_debug_mask(D_CLIENT, "%s: username specified and no existing session, adding basic auth", client->reader->label);
    ret = snprintf((char*)auth, sizeof(auth), "%s:%s", client->reader->r_usr, client->reader->r_pwd);
    ret = b64encode((char*)auth, ret, &encauth);
  }

  if(encauth) { // basic auth login
    ret = snprintf((char*)req, sizeof(req), "GET /api/c/%d/%x HTTP/1.1\r\nHost: %s\r\nAuthorization: Basic %s\r\n\r\n", odd ? 81 : 80, hash, client->reader->device, encauth);
  } else {
    if(context->session_id) { // session exists
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
  uchar req[640], auth[64];
  uchar* end;
  char* encauth = NULL;
  int32_t ret;
  s_ghttp* context = (s_ghttp*)client->ghttp;

  if(!context->session_id && strlen(client->reader->r_usr) > 0) {
    cs_debug_mask(D_CLIENT, "%s: username specified and no existing session, adding basic auth", client->reader->label);
    ret = snprintf((char*)auth, sizeof(auth), "%s:%s", client->reader->r_usr, client->reader->r_pwd);
    ret = b64encode((char*)auth, ret, &encauth);
  }

  if(encauth) { // basic auth login
    ret = snprintf((char*)req, sizeof(req), "POST /api/e/%x/%x/%x/%x/%x/%x HTTP/1.1\r\nHost: %s\r\nAuthorization: Basic %s\r\nContent-Length: %d\r\n\r\n", er->onid, er->tsid, er->pid, er->srvid, er->caid, er->prid, client->reader->device, encauth, er->ecmlen);
  } else {
    if(context->session_id) { // session exists
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

static int32_t ghttp_send_ecm(struct s_client *client, ECM_REQUEST *er, uchar *UNUSED(buf))
{
  uint32_t hash;
  // int32_t ret;
  s_ghttp* context = (s_ghttp*)client->ghttp;

  context->prev_sid = context->last_ecm.srvid;
  if(context->prev_sid != er->srvid) {
    cs_debug_mask(D_CLIENT, "%s: zap detected? prev %x, current %x", client->reader->label, context->prev_sid, er->srvid);    
    context->do_post_next = 1;
  }

  client->reader->msg_idx = er->idx;
  if(context->do_post_next) {
    _ghttp_post_ecmdata(client, er);
  } else {
    hash = javastring_hashcode(er->ecm + 3, er->ecmlen - 3);
    _ghttp_http_get(client, hash, er->ecm[0] == 0x81);
  }

  context->last_ecm = *er; //struct copy

  return 0;
}

void module_ghttp(struct s_module *ph)
{
  static PTAB ptab;
  // ptab.ports[0].s_port = cfg.ghttp_port;
  ph->ptab = &ptab;
  ph->ptab->nports = 0;

  ph->desc = "ghttp";
  ph->type = MOD_CONN_TCP;
  // ph->listenertype = LIS_GHTTP;    
  ph->multi = 0;
  ph->recv = ghttp_recv;
  ph->c_multi = 0;
  ph->c_init = ghttp_client_init;
  ph->c_recv_chk = ghttp_recv_chk;
  ph->c_send_ecm = ghttp_send_ecm;
  ph->num = R_GHTTP;
}
#endif
