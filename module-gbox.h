#ifndef MODULE_GBOX_H_
#define MODULE_GBOX_H_

#ifdef MODULE_GBOX

#define NO_GBOX_ID			0
#define GBOX_MAXHOPS			10
#define DEFAULT_GBOX_MAX_DIST		2
#define DEFAULT_GBOX_MAX_ECM_SEND	3
#define DEFAULT_GBOX_RECONNECT		300
#define CS_GBOX_MAX_LOCAL_CARDS		16

struct gbox_srvid
{
        uint16_t sid;
        uint32_t provid_id;
        time_t last_cw_received;
};

struct gbox_card
{
        uint16_t peer_id;
        uint16_t caid;
        uint32_t provid;
        uint32_t provid_1;
        uint8_t slot;
        uint8_t dist;
        uint8_t lvl;
        LLIST *badsids; // sids that have failed to decode (struct cc_srvid)
        LLIST *goodsids; //sids that could be decoded (struct cc_srvid)
        uint32_t no_cws_returned;
        uint32_t average_cw_time;
};

struct gbox_data
{
        uint16_t id;
        uchar password[4];
        uchar checkcode[7];
        uint8_t minor_version;
        uint8_t cpu_api;
        LLIST *cards;
};

struct gbox_peer
{
        struct gbox_data gbox;
        uchar *hostname;
        int32_t online;
        int32_t hello_stat;
        uchar ecm_idx;
        uchar gbox_count_ecm;
        CS_MUTEX_LOCK lock;
        struct s_client *my_user;
        LL_ITER last_it;
};

enum
{
    MSG_ECM = 0x445C,
    MSG_CW = 0x4844,
    MSG_HELLO = 0xDDAB,
    MSG_HELLO1 = 0x4849,
    MSG_CHECKCODE = 0x41C0,
    MSG_GOODBYE = 0x9091,
    MSG_GSMS_ACK_1 = 0x9098,
    MSG_GSMS_ACK_2 = 0x9099,
    MSG_GSMS_1 = 0x0FF0,
    MSG_GSMS_2 = 0x0FFF,
    MSG_BOXINFO = 0xA0A1,
    MSG_UNKNWN = 0x48F9,
};
           
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

uint16_t gbox_get_local_gbox_id(void);
uint32_t gbox_get_local_gbox_password(void);
void gbox_send(struct s_client *cli, uchar *buf, int32_t l);

#endif

#endif
