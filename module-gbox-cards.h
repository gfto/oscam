#ifndef MODULE_GBOX_CARDS_H_
#define MODULE_GBOX_CARDS_H_

#ifdef MODULE_GBOX
void gbox_write_cards_info(void);
void gbox_write_stats(void);
void init_gbox_cards(void);
void gbox_add_card(uint16_t id_peer, uint32_t caprovid, uint8_t slot, uint8_t level, uint8_t distance, uint8_t type, struct gbox_peer *origin_peer);
void gbox_calc_checkcode(uint8_t *checkcode);
uint16_t gbox_count_peer_cards(uint16_t peer_id);
void gbox_delete_cards_from_peer(uint16_t peer_id);
void gbox_delete_cards_from_type(uint8_t type);
void gbox_free_cardlist(void);
void gbox_send_hello(struct s_client *cli);
void gbox_add_good_sid(uint16_t id_card, uint16_t caid, uint8_t slot, uint16_t sid_ok, uint32_t cw_time);
void gbox_remove_bad_sid(uint16_t id_peer, uint8_t id_slot, uint16_t sid);
uint8_t gbox_next_free_slot(uint16_t id);
uint8_t gbox_get_cards_for_ecm(uchar *send_buf_1, int32_t cont_1, uint8_t max_cards, ECM_REQUEST *er, uint32_t *current_avg_card_time, uint16_t peer_id);
#endif

#endif
