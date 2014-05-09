#ifndef MODULE_GBOX_H_
#define MODULE_GBOX_H_

#ifdef MODULE_GBOX

#define NO_GBOX_ID			0
#define GBOX_MAXHOPS			10
#define DEFAULT_GBOX_MAX_DIST		2
#define DEFAULT_GBOX_MAX_ECM_SEND	3
#define DEFAULT_GBOX_RECONNECT		300
#define CS_GBOX_MAX_LOCAL_CARDS		16

#if defined(__CYGWIN__) 
#define FILE_GSMS_TXT		"C:/tmp/gsms.txt"
#else
#define FILE_GSMS_TXT		"/tmp/gsms.txt"
#endif

void gbox_init_send_gsms(void);

struct gbox_ecm_request_ext
{
//    uint32_t        gbox_crc;       // rcrc for gbox, used to identify ECM
//    uint16_t        gbox_ecm_id;
//    uint8_t         gbox_ecm_ok;
    uint8_t         gbox_hops;
    uint16_t        gbox_peer;
    uint16_t        gbox_mypeer;
    uint16_t        gbox_caid;      //could be calculated 0x05 and 0x0D are
    uint16_t        gbox_prid;      //same as gbox_caid
    uint8_t         gbox_slot;
    uint8_t         gbox_version;
    uint8_t         gbox_unknown;   //byte between version and cpu info of
    uint8_t         gbox_type;
    uchar           gbox_routing_info[GBOX_MAXHOPS];  //support max 10 hops
};
#endif

#endif
