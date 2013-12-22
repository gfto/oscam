#ifndef MODULE_GBOX_H_
#define MODULE_GBOX_H_

struct gbox_ecm_request_ext
{
//    uint32_t        gbox_crc;       // rcrc for gbox, used to identify ECM
//    uint16_t        gbox_ecm_id;
//    uint8_t         gbox_ecm_ok;
    uint8_t         gbox_hops;
    uint16_t        gbox_peer;
    uint16_t        gbox_mypeer;
    uint32_t        gbox_peer_key;
    uint16_t        gbox_caid;      //could be calculated 0x05 and 0x0D are
    uint16_t        gbox_prid;      //same as gbox_caid
    uint8_t         gbox_slot;
    uint8_t         gbox_version;
    uint8_t         gbox_unknown;   //byte between version and cpu info of
    uint8_t         gbox_type;
    uchar           gbox_routing_info[10];  //support max 10 hops
};

// Parsing function used in oscam-config-reader.c
void mgencrypted_fn(const char *token, char *value, void *setting, FILE *f);

#endif
