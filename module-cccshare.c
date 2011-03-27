#include "globals.h"
#include "module-cccam.h"
#include "reader-common.h"
#include "module-cccshare.h"

static uint32 cc_share_id = 0x64;
static LLIST *reported_carddatas;
//static pthread_mutex_t cc_shares_lock;

static int card_added_count = 0;
static int card_removed_count = 0;
static int card_dup_count = 0;
static pthread_t share_updater_thread = 0;

LLIST *get_and_lock_sharelist()
{
		//pthread_mutex_lock(&cc_shares_lock);
		return reported_carddatas;
}

void unlock_sharelist()
{
		//pthread_mutex_unlock(&cc_shares_lock);
}

void add_good_bad_sids(struct s_sidtab *ptr, SIDTABBITS sidtabno, struct cc_card *card) {
        //good sids:
        int l;
        for (l=0;l<ptr->num_srvid;l++) {
				struct cc_srvid *srvid = malloc(sizeof(struct cc_srvid));
                srvid->sid = ptr->srvid[l];
                srvid->ecmlen = 0; //0=undefined, also not used with "O" CCcam
                ll_append(card->goodsids, srvid);
        }

        //bad sids:
        struct s_sidtab *ptr_no;
        int n;
        for (n=0,ptr_no=cfg.sidtab; ptr_no; ptr_no=ptr_no->next,n++) {
				if (sidtabno&((SIDTABBITS)1<<n)) {
                		int m;
                        int ok_caid = FALSE;
                        for (m=0;m<ptr_no->num_caid;m++) { //search bad sids for this caid:
                        		if (ptr_no->caid[m] == card->caid) {
                                		ok_caid = TRUE;
                                        break;
                                }
                        }
                        if (ok_caid) {
                        		for (l=0;l<ptr_no->num_srvid;l++) {
                                		struct cc_srvid *srvid = malloc(sizeof(struct cc_srvid));
                                        srvid->sid = ptr_no->srvid[l];
                                        srvid->ecmlen = 0; //0=undefined, also not used with "O" CCcam
                                        ll_append(card->badsids, srvid);
                                }
                        }
				}
        }
}

int write_card(struct cc_data *cc, uint8 *buf, struct cc_card *card, int add_own, int ext, int au_allowed, struct s_client *cl) {
    memset(buf, 0, CC_MAXMSGSIZE);
    buf[0] = card->id >> 24;
    buf[1] = card->id >> 16;
    buf[2] = card->id >> 8;
    buf[3] = card->id & 0xff;
    buf[4] = card->remote_id >> 24;
    buf[5] = card->remote_id >> 16;
    buf[6] = card->remote_id >> 8;
    buf[7] = card->remote_id & 0xFF;
    buf[8] = card->caid >> 8;
    buf[9] = card->caid & 0xff;
    buf[10] = card->hop;
    buf[11] = card->reshare;
    if (au_allowed)
            memcpy(buf + 12, card->hexserial, 8);

    //with cccam 2.2.0 we have assigned and rejected sids:
    int ofs = ext?23:21;

    //write providers:
    LL_ITER *it = ll_iter_create(card->providers);
    struct cc_provider *prov;
    while ((prov = ll_iter_next(it))) {
        ulong prid = prov->prov;
        buf[ofs+0] = prid >> 16;
        buf[ofs+1] = prid >> 8;
        buf[ofs+2] = prid & 0xFF;
        if (au_allowed)
        		memcpy(buf + ofs + 3, prov->sa, 4);
        buf[20]++;
        ofs+=7;
    }
    ll_iter_release(it);

    //write sids only if cccam 2.2.x:
    if (ext) {
    	if (card->card_type == CT_CARD_BY_SERVICE_USER) {
		        //good sids:
		        struct s_sidtab *ptr = card->sidtab;
		        int l;
		        for (l=0;l<ptr->num_srvid;l++) {
		            buf[ofs+0] = ptr->srvid[l] >> 8;
		            buf[ofs+1] = ptr->srvid[l] & 0xFF;
		            ofs+=2;
		            buf[21]++; //nassign
		            if (buf[21] >= 200)
		                break;
				}

		        //bad sids:
		        int n;
		        for (n=0,ptr=cfg.sidtab; ptr; ptr=ptr->next,n++) {
						if (cl->sidtabno&((SIDTABBITS)1<<n)) {
                				int m;
                				int ok_caid = FALSE;
                				for (m=0;m<ptr->num_caid;m++) { //search bad sids for this caid:
                        				if (ptr->caid[m] == card->caid) {
                                				ok_caid = TRUE;
                                				break;
                                		}
								}
								if (ok_caid) {
                        				for (l=0;l<ptr->num_srvid;l++) {
                        						buf[ofs+0] = ptr->srvid[l] >> 8;
                        						buf[ofs+1] = ptr->srvid[l] & 0xFF;
                        						ofs+=2;
                        						buf[22]++; //nreject
                        						if (buf[22] >= 200)
														break;
		                                }
        		                }
						}
				}
    	} else {
		        //assigned sids:
		        it = ll_iter_create(card->goodsids);
		        struct cc_srvid *srvid;
		        while ((srvid = ll_iter_next(it))) {
		            buf[ofs+0] = srvid->sid >> 8;
		            buf[ofs+1] = srvid->sid & 0xFF;
		            ofs+=2;
		            buf[21]++; //nassign
		            if (buf[21] >= 200)
		                break;
		        }
		        ll_iter_release(it);
		
		        //reject sids:
		        it = ll_iter_create(card->badsids);
		        while ((srvid = ll_iter_next(it))) {
		            buf[ofs+0] = srvid->sid >> 8;
		            buf[ofs+1] = srvid->sid & 0xFF;
		            ofs+=2;
		            buf[22]++; //nreject
		            if (buf[22] >= 200)
		                break;
		        }
		        ll_iter_release(it);
		}
    }

    //write remote nodes
    int nremote_ofs = ofs;
    ofs++;
    it = ll_iter_create(card->remote_nodes);
    uint8 *remote_node;
    while ((remote_node = ll_iter_next(it))) {
        memcpy(buf+ofs, remote_node, 8);
        ofs+=8;
        buf[nremote_ofs]++;
    }
    ll_iter_release(it);
    if (add_own) {
        memcpy(buf+ofs, cc->node_id, 8);
        ofs+=8;
        buf[nremote_ofs]++;
    }
    return ofs;
}


int send_card_to_clients(struct cc_card *card, struct s_client *one_client) {
        int count = 0;

        uint8 buf[CC_MAXMSGSIZE];

        struct s_client *cl;
        for (cl = one_client?one_client:first_client; cl; cl=one_client?NULL:cl->next) {
                struct cc_data *cc = cl->cc;
                if (cl->typ=='c' && cc && ((one_client && cc->mode != CCCAM_MODE_SHUTDOWN) || (ph[cl->ctyp].num == R_CCCAM && cc->mode == CCCAM_MODE_NORMAL))) { //CCCam-Client!
                		int ext = cc->cccam220?MSG_NEW_CARD_SIDINFO:MSG_NEW_CARD;
                        if (card_valid_for_client(cl, card)) {
								int usr_reshare = cl->account->cccreshare;
                                int usr_ignorereshare = cl->account->cccignorereshare;
                                
                                int reader_reshare = card->origin_reader?card->origin_reader->cc_reshare:cfg.cc_reshare;
                                int reshare = (reader_reshare < usr_reshare) ? reader_reshare : usr_reshare;
								int new_reshare;
								if (cfg.cc_ignore_reshare || usr_ignorereshare)
										new_reshare = reshare;
								else {
										new_reshare = card->reshare;
										if (card->card_type == CT_REMOTECARD)
												new_reshare--;
										if (new_reshare > reshare)
												new_reshare = reshare;
								}
                                if (new_reshare < 0)
                                		continue;

								if (!card->id)
										card->id = cc_share_id++;

								int len = write_card(cc, buf, card, 1,  ext, ll_count(cl->aureader_list), cl);
								//buf[10] = card->hop-1;
								buf[11] = new_reshare;

								if (cc_cmd_send(cl, buf, len, ext) < 0)
										cc->mode = CCCAM_MODE_SHUTDOWN;
								count++;
                        }
                }
		}
        return count;
}

void send_remove_card_to_clients(struct cc_card *card) {
		if (!card || !card->id)
				return;
				
		uint8 buf[4];
		buf[0] = card->id >> 24;
		buf[1] = card->id >> 16;
		buf[2] = card->id >> 8;
		buf[3] = card->id & 0xFF;

		struct s_client *cl;
		for (cl = first_client; cl; cl=cl->next) {
				struct cc_data *cc = cl->cc;
				if (cl->typ=='c' && cc && ph[cl->ctyp].num == R_CCCAM && cc->mode == CCCAM_MODE_NORMAL) { //CCCam-Client!
						if (card_valid_for_client(cl, card)) {
								cc_cmd_send(cl, buf, 4, MSG_CARD_REMOVED);
						}
				}
		}
}


/**
 * if idents defined on an cccam reader, the cards caid+provider are checked.
 * return 1 a) if no ident defined b) card is in identlist
 *        0 if card is not in identlist
 *
 * a card is in the identlist, if the cards caid is matching and mininum a provider is matching
 **/
int chk_ident(FTAB *ftab, struct cc_card *card) {

    int j, k;
    int res = 1;

    if (ftab && ftab->filts) {
        for (j = 0; j < ftab->nfilts; j++) {
            if (ftab->filts[j].caid) {
                res = 0;
                if (ftab->filts[j].caid==card->caid) { //caid matches!

                    int nprids = ftab->filts[j].nprids;
                    if (!nprids) // No Provider ->Ok
                        return 1;


                    LL_ITER *it = ll_iter_create(card->providers);
                    struct cc_provider *prov;

                    while ((prov = ll_iter_next(it))) {
                        for (k = 0; k < nprids; k++) {
                            ulong prid = ftab->filts[j].prids[k];
                            if (prid == prov->prov) { //Provider matches
                                ll_iter_release(it);
                                return 1;
                            }
                        }
                    }
                    ll_iter_release(it);
                }
            }
        }
    }
    return res;
}

int cc_clear_reported_carddata(LLIST *reported_carddatas, LLIST *except,
                int send_removed) {
        int i=0;
        LL_ITER *it = ll_iter_create(reported_carddatas);
        struct cc_card *card;
        while ((card = ll_iter_next(it))) {
                struct cc_card *card2 = NULL;
                if (except) {
                        LL_ITER *it2 = ll_iter_create(except);
                        while ((card2 = ll_iter_next(it2))) {
                                if (card == card2)
                                        break;
                        }
                        ll_iter_release(it2);
                }

                ll_iter_remove(it);
                
                if (!card2) {
                        if (send_removed)
                        		send_remove_card_to_clients(card);
                        cc_free_card(card);
                        i++;
                }
        }
        ll_iter_release(it);
        return i;
}

int cc_free_reported_carddata(LLIST *reported_carddatas, LLIST *except,
                int send_removed) {
        int i=0;
        if (reported_carddatas) {
                i = cc_clear_reported_carddata(reported_carddatas, except, send_removed);
                ll_destroy(reported_carddatas);
        }
        return i;
}

int card_valid_for_client(struct s_client *cl, struct cc_card *card) {

        struct s_reader *rdr = card->origin_reader;
        //Check group:
        if (rdr && !(rdr->grp & cl->grp))
                return 0;

        if (!chk_ident(&cl->ftab, card))
                return 0;

        //Check caids:
        if (!chk_ctab(card->caid, &cl->ctab))
                return 0;

        //Check reshare
        if (!cfg.cc_ignore_reshare && !cl->account->cccignorereshare && !card->reshare)
        		return 0;
        		
		//Check account maxhops:
		if (cl->account->cccmaxhops < card->hop)
				return 0;

		//Check remote node id, if card is from there, ignore it!
        LL_ITER *it = ll_iter_create(card->remote_nodes);
		uint8 * node;
		struct cc_data *cc = cl->cc;
        while ((node=ll_iter_next(it))) {
        		if (!memcmp(node, cc->peer_node_id, 8)) {
        				ll_iter_release(it);
        				return 0;
				}
		}
		ll_iter_release(it);

        //Check Services:
        it = ll_iter_create(card->providers);
        struct cc_provider *prov;
        while ((prov = ll_iter_next(it))) {
        		ulong prid = prov->prov;
                if (!chk_srvid_by_caid_prov(cl, card->caid, prid)) {
                		ll_iter_release(it);
                		return 0;
				}
		}
		ll_iter_release(it);
		
        //Check Card created by Service:
        if (card->card_type == CT_CARD_BY_SERVICE_READER || card->card_type == CT_CARD_BY_SERVICE_USER) {
        		struct s_sidtab *ptr;
        		int j;
        		int ok = !cl->sidtabok && !cl->sidtabno; //default valid if no positive services and no negative services
        		if (!ok) {
		        		for (j=0,ptr=cfg.sidtab; ptr; ptr=ptr->next,j++) {
        						if (ptr == card->sidtab) {
										if (cl->account->sidtabno&((SIDTABBITS)1<<j))
        										return 0;
										if (cl->account->sidtabok&((SIDTABBITS)1<<j))
        										ok = 1;
										break;
								}
						}
                }
                if (!ok)
                		return 0;
		}
                        				
        return 1;
}

ulong get_reader_prid(struct s_reader *rdr, int j) {
    return b2i(4, rdr->prid[j]);
}
//ulong get_reader_prid(struct s_reader *rdr, int j) {
//  ulong prid;
//  if (!(rdr->typ & R_IS_CASCADING)) { // Real cardreaders have 4-byte Providers
//      prid = b2i(4, &rdr->prid[j][0]);
//      //prid = (rdr->prid[j][0] << 24) | (rdr->prid[j][1] << 16)
//      //      | (rdr->prid[j][2] << 8) | (rdr->prid[j][3] & 0xFF);
//  } else { // Cascading/Network-reader 3-bytes Providers
//      prid = b2i(3, &rdr->prid[j][0]);
//      //prid = (rdr->prid[j][0] << 16) | (rdr->prid[j][1] << 8)
//      //      | (rdr->prid[j][2] & 0xFF);
//
//  }
//  return prid;
//}

void copy_sids(LLIST *dst, LLIST *src) {
    LL_ITER *it_src = ll_iter_create(src);
    LL_ITER *it_dst = ll_iter_create(dst);
    struct cc_srvid *srvid_src;
    struct cc_srvid *srvid_dst;
    while ((srvid_src=ll_iter_next(it_src))) {
        ll_iter_reset(it_dst);
        while ((srvid_dst=ll_iter_next(it_dst))) {
            if (sid_eq(srvid_src, srvid_dst))
                break;
        }
        if (!srvid_dst) {
            srvid_dst = cs_malloc(&srvid_dst, sizeof(struct cc_srvid), QUITERROR);
            memcpy(srvid_dst, srvid_src, sizeof(struct cc_srvid));
            ll_iter_insert(it_dst, srvid_dst);
        }
    }
    ll_iter_release(it_dst);
    ll_iter_release(it_src);
}


int add_card_providers(struct cc_card *dest_card, struct cc_card *card,
        int copy_remote_nodes) {
    int modified = 0;

    //1. Copy nonexisting providers, ignore double:
    struct cc_provider *prov_info;
    LL_ITER *it_src = ll_iter_create(card->providers);
    LL_ITER *it_dst = ll_iter_create(dest_card->providers);

    struct cc_provider *provider;
    while ((provider = ll_iter_next(it_src))) {
        ll_iter_reset(it_dst);
        while ((prov_info = ll_iter_next(it_dst))) {
            if (prov_info->prov == provider->prov)
                break;
        }
        if (!prov_info) {
            struct cc_provider *prov_new = cs_malloc(&prov_new, sizeof(struct cc_provider), QUITERROR);
            memcpy(prov_new, provider, sizeof(struct cc_provider));
            ll_iter_insert(it_dst, prov_new);
            modified = 1;
        }
    }
    ll_iter_release(it_dst);
    ll_iter_release(it_src);

    if (copy_remote_nodes) {
        //2. Copy nonexisting remote_nodes, ignoring existing:
        it_src = ll_iter_create(card->remote_nodes);
        it_dst = ll_iter_create(dest_card->remote_nodes);
        uint8 *remote_node;
        uint8 *remote_node2;
        while ((remote_node = ll_iter_next(it_src))) {
            ll_iter_reset(it_dst);
            while ((remote_node2 = ll_iter_next(it_dst))) {
                if (memcmp(remote_node, remote_node2, 8) == 0)
                    break;
            }
            if (!remote_node2) {
                uint8* remote_node_new = cs_malloc(&remote_node_new, 8, QUITERROR);
                memcpy(remote_node_new, remote_node, 8);
                ll_iter_insert(it_dst, remote_node_new);
                modified = 1;
            }
        }
        ll_iter_release(it_dst);
        ll_iter_release(it_src);
    }
    return modified;
}

struct cc_card *create_card(struct cc_card *card) {
    struct cc_card *card2 = cs_malloc(&card2, sizeof(struct cc_card), QUITERROR);
    if (card)
        memcpy(card2, card, sizeof(struct cc_card));
    else
        memset(card2, 0, sizeof(struct cc_card));
    card2->providers = ll_create();
    card2->badsids = ll_create();
    card2->goodsids = ll_create();
    card2->remote_nodes = ll_create();

    if (card) {
        copy_sids(card2->goodsids, card->goodsids);
        copy_sids(card2->badsids, card->badsids);
        card2->origin_id = card->id;
        card2->id = 0;
    }

    return card2;
}

struct cc_card *create_card2(struct s_reader *rdr, int j, uint16 caid, uint8 hop, uint8 reshare) {

    struct cc_card *card = create_card(NULL);
    card->remote_id = (rdr?(rdr->cc_id << 16):0x7F7F8000)|j;
    card->caid = caid;
    card->hop = hop;
    card->reshare = reshare;
    card->origin_reader = rdr;
    return card;
}

/**
 * num_same_providers checks if card1 has exactly the same providers as card2
 * returns same provider count
 **/
int num_same_providers(struct cc_card *card1, struct cc_card *card2) {

    int found=0;

    LL_ITER *it1 = ll_iter_create(card1->providers);
    LL_ITER *it2 = ll_iter_create(card2->providers);

    struct cc_provider *prov1, *prov2;

    while ((prov1=ll_iter_next(it1))) {

        ll_iter_reset(it2);
        while ((prov2=ll_iter_next(it2))) {
            if (prov1->prov==prov2->prov) {
                found++;
                break;
            }

        }
    }

    ll_iter_release(it2);
    ll_iter_release(it1);

    return found;
}

/**
 * equal_providers checks if card1 has exactly the same providers as card2
 * returns 1=equal 0=different
 **/
int equal_providers(struct cc_card *card1, struct cc_card *card2) {

    if (ll_count(card1->providers) != ll_count(card2->providers))
    	return 0;
    if (ll_count(card1->providers) == 0)
       return 1;

    LL_ITER *it1 = ll_iter_create(card1->providers);
    LL_ITER *it2 = ll_iter_create(card2->providers);

    struct cc_provider *prov1, *prov2;

    while ((prov1=ll_iter_next(it1))) {

        ll_iter_reset(it2);
        while ((prov2=ll_iter_next(it2))) {
            if (prov1->prov==prov2->prov) {
                break;
            }

        }
        if (!prov2) break;
    }

    ll_iter_release(it2);
    ll_iter_release(it1);

    return (prov1 == NULL);
}


/**
 * Adds a new card to a cardlist.
 */
int add_card_to_serverlist(LLIST *cardlist, struct cc_card *card) {

    int modified = 0;
    LL_ITER *it = ll_iter_create(cardlist);
    struct cc_card *card2;

    //Minimize all, transmit just CAID, merge providers:
    if (cfg.cc_minimize_cards == MINIMIZE_CAID && !cfg.cc_forward_origin_card) {
        while ((card2 = ll_iter_next(it)))
            if (card2->caid == card->caid &&
                    !memcmp(card->hexserial, card2->hexserial, sizeof(card->hexserial))) {

                //Merge cards only if resulting providercount is smaller than CS_MAXPROV
                int nsame, ndiff, nnew;

                nsame = num_same_providers(card, card2); //count same cards
                ndiff = ll_count(card->providers)-nsame; //cound different cards, this cound will be added
                nnew = ndiff + ll_count(card2->providers); //new card count after add. because its limited to CS_MAXPROV, dont add it

                if (nnew <= CS_MAXPROV)
                    break;
            }
        if (!card2) {
            card2 = create_card(card);
            card2->hop = 0;
            ll_clear_data(card2->badsids);
            ll_iter_insert(it, card2);
            modified = 1;

        }
        else card_dup_count++;

        add_card_providers(card2, card, 0); //merge all providers

    }

    //Removed duplicate cards, keeping card with lower hop:
    else if (cfg.cc_minimize_cards == MINIMIZE_HOPS && !cfg.cc_forward_origin_card) {
        while ((card2 = ll_iter_next(it))) {
            if (card2->caid == card->caid &&
                    !memcmp(card->hexserial, card2->hexserial, sizeof(card->hexserial)) &&
                    equal_providers(card, card2)) {
                break;
            }
        }

        if (card2 && card2->hop > card->hop) { //hop is smaller, drop old card
            cc_free_card(card2);
            ll_iter_remove(it);
            card2 = NULL;
            card_dup_count++;
        }

        if (!card2) {
            card2 = create_card(card);
            card2->hop = card->hop;
            ll_clear_data(card2->badsids);
            ll_iter_insert(it, card2);
            add_card_providers(card2, card, 1);
            modified = 1;
        }
        else card_dup_count++;

    }
    //like cccam:
    else { //just remove duplicate cards (same ids)
        while ((card2 = ll_iter_next(it))) {
            if (same_card(card, card2))
                break;
        }
        if (card2 && card2->hop > card->hop) {
            cc_free_card(card2);
            ll_iter_remove(it);
            card2 = NULL;
            card_dup_count++;
        }
        if (!card2) {
            card2 = create_card(card);
            card2->hop = card->hop;
            ll_iter_insert(it, card2);
            add_card_providers(card2, card, 1);
            modified = 1;
        }
        else card_dup_count++;
    }
    ll_iter_release(it);
    return modified;
}

int find_reported_card(struct cc_card *card1)
{
    LL_ITER *it = ll_iter_create(reported_carddatas);
    struct cc_card *card2;
    while ((card2 = ll_iter_next(it))) {
        if (same_card(card1, card2)) {
            card1->id = card2->id; //Set old id !!
            cc_free_card(card2);
            ll_iter_remove(it);
            ll_iter_release(it);
            return 1; //Old card and new card are equal!
        }
    }
    ll_iter_release(it);
    return 0; //Card not found
}

/**
* Server:
* Adds a cccam-carddata buffer to the list of reported carddatas
*/
void cc_add_reported_carddata(LLIST *reported_carddatas, struct cc_card *card) {
		ll_append(reported_carddatas, card);
}       
       
int report_card(struct cc_card *card, LLIST *new_reported_carddatas)
{
    int res = 0;
    if (!find_reported_card(card)) { //Add new card:

        send_card_to_clients(card, NULL);

        card_added_count++;
    }
    cc_add_reported_carddata(new_reported_carddatas, card);
    return res;
}


/**
 * Server:
 * Reports all caid/providers to the connected clients
 * returns 1=ok, 0=error
 *
 * cfg.cc_reshare_services=0 CCCAM reader reshares only received cards
 *                         =1 CCCAM reader reshares received cards + defined services
 *                         =2 CCCAM reader reshares only defined reader-services as virtual cards
 *                         =3 CCCAM reader reshares only defined user-services as virtual cards
 */
void update_card_list() {
    int j, flt;

    LLIST *server_cards = ll_create();
    LLIST *new_reported_carddatas = ll_create();

    card_added_count = 0;
    card_removed_count = 0;
    card_dup_count = 0;

    //User-Services:
    if (cfg.cc_reshare_services==3 && cfg.sidtab) {
        struct s_sidtab *ptr;
        for (j=0,ptr=cfg.sidtab; ptr; ptr=ptr->next,j++) {
                int k;
                for (k=0;k<ptr->num_caid;k++) {
                    struct cc_card *card = create_card2(NULL, (j<<8)|k, ptr->caid[k], 0, cfg.cc_reshare);
                    card->card_type = CT_CARD_BY_SERVICE_USER;
                    card->sidtab = ptr;
                    int l;
                    for (l=0;l<ptr->num_provid;l++) {
                        struct cc_provider *prov = cs_malloc(&prov, sizeof(struct cc_provider), QUITERROR);
                        memset(prov, 0, sizeof(struct cc_provider));
                        prov->prov = ptr->provid[l];
                        ll_append(card->providers, prov);
                    }

                    add_card_to_serverlist(server_cards, card);
                }
                flt=1;
        }
    }
    else
    {
        struct s_reader *rdr;
        int r = 0;
        for (rdr = first_active_reader; rdr; rdr = rdr->next) {
            if (!rdr->fd)
                continue;

            //Generate a uniq reader id:
            if (!rdr->cc_id) {
                rdr->cc_id = ++r;
                struct s_reader *rdr2;
                for (rdr2 = first_active_reader; rdr2; rdr2 = rdr2->next) {
                    if (rdr2 != rdr && rdr2->cc_id == rdr->cc_id) {
                        rdr2 = first_active_reader;
                        rdr->cc_id=++r;
                    }
                }
            }

            flt = 0;

            //Reader-Services:
            if ((cfg.cc_reshare_services==1||cfg.cc_reshare_services==2||!rdr->caid) && cfg.sidtab && rdr->sidtabok) {
                struct s_sidtab *ptr;
                for (j=0,ptr=cfg.sidtab; ptr; ptr=ptr->next,j++) {
                    if (rdr->sidtabok&((SIDTABBITS)1<<j)) {
                        int k;
                        for (k=0;k<ptr->num_caid;k++) {
                            struct cc_card *card = create_card2(rdr, (j<<8)|k, ptr->caid[k], 0, rdr->cc_reshare);
                            card->card_type = CT_CARD_BY_SERVICE_READER;
                            card->sidtab = ptr;
                            int l;
                            for (l=0;l<ptr->num_provid;l++) {
                                struct cc_provider *prov = cs_malloc(&prov, sizeof(struct cc_provider), QUITERROR);
                                memset(prov, 0, sizeof(struct cc_provider));
                                prov->prov = ptr->provid[l];
                                ll_append(card->providers, prov);
                            }

                            //CCcam 2.2.x proto can transfer good and bad sids:
                            add_good_bad_sids(ptr, rdr->sidtabno, card);

                            add_card_to_serverlist(server_cards, card);
                        }
                        flt=1;
                    }
                }
            }

            //Filts by Hardware readers:
            if ((rdr->typ != R_CCCAM) && rdr->ftab.filts && !flt) {
                for (j = 0; j < CS_MAXFILTERS; j++) {
                    if (rdr->ftab.filts[j].caid) {
                        ushort caid = rdr->ftab.filts[j].caid;
                        struct cc_card *card = create_card2(rdr, j, caid, 0, rdr->cc_reshare);
                        card->card_type = CT_LOCALCARD;
                        
                        //Setting UA: (Unique Address):
                        if (!rdr->audisabled)
								cc_UA_oscam2cccam(rdr->hexserial, card->hexserial, caid);
                        //cs_log("Ident CCcam card report caid: %04X readr %s subid: %06X", rdr->ftab.filts[j].caid, rdr->label, rdr->cc_id);
                        int k;
                        for (k = 0; k < rdr->ftab.filts[j].nprids; k++) {
                            struct cc_provider *prov = cs_malloc(&prov, sizeof(struct cc_provider), QUITERROR);
                            memset(prov, 0, sizeof(struct cc_provider));
                            prov->prov = rdr->ftab.filts[j].prids[k];

                            //cs_log("Ident CCcam card report provider: %02X%02X%02X", buf[21 + (k*7)]<<16, buf[22 + (k*7)], buf[23 + (k*7)]);
                            if (!rdr->audisabled) {
                                int l;
                                for (l = 0; l < rdr->nprov; l++) {
                                    ulong rprid = get_reader_prid(rdr, l);
                                    if (rprid == prov->prov)
                                        cc_SA_oscam2cccam(&rdr->sa[l][0], prov->sa);
                                }
                            }

                            ll_append(card->providers, prov);
                        }

						add_card_to_serverlist(server_cards, card);
                        flt = 1;
                    }
                }
            }

            if ((rdr->typ != R_CCCAM) && !rdr->caid && !flt) {
                for (j = 0; j < CS_MAXCAIDTAB; j++) {
                    //cs_log("CAID map CCcam card report caid: %04X cmap: %04X", rdr->ctab.caid[j], rdr->ctab.cmap[j]);
                    ushort lcaid = rdr->ctab.caid[j];

                    if (!lcaid || (lcaid == 0xFFFF))
                        lcaid = rdr->ctab.cmap[j];

                    if (lcaid && (lcaid != 0xFFFF)) {
                        struct cc_card *card = create_card2(rdr, j, lcaid, 0, rdr->cc_reshare);
                        card->card_type = CT_CARD_BY_CAID;
                        if (!rdr->audisabled)
                            cc_UA_oscam2cccam(rdr->hexserial, card->hexserial, lcaid);

                        add_card_to_serverlist(server_cards, card);
                        flt = 1;
                    }
                }
            }

            if ((rdr->typ != R_CCCAM) && rdr->caid && !flt) {
                //cs_log("tcp_connected: %d card_status: %d ", rdr->tcp_connected, rdr->card_status);
                ushort caid = rdr->caid;
                struct cc_card *card = create_card2(rdr, 1, caid, 0, rdr->cc_reshare);
                card->card_type = CT_CARD_BY_CAID;
                
                if (!rdr->audisabled)
                    cc_UA_oscam2cccam(rdr->hexserial, card->hexserial, caid);
                for (j = 0; j < rdr->nprov; j++) {
                    ulong prid = get_reader_prid(rdr, j);
                    struct cc_provider *prov = cs_malloc(&prov, sizeof(struct cc_provider), QUITERROR);
                    memset(prov, 0, sizeof(struct cc_provider));
                    prov->prov = prid;
                    //cs_log("Ident CCcam card report provider: %02X%02X%02X", buf[21 + (k*7)]<<16, buf[22 + (k*7)], buf[23 + (k*7)]);
                    if (!rdr->audisabled) {
                        //Setting SA (Shared Addresses):
                        cc_SA_oscam2cccam(rdr->sa[j], prov->sa);
                    }
                    ll_append(card->providers, prov);
                    //cs_log("Main CCcam card report provider: %02X%02X%02X%02X", buf[21+(j*7)], buf[22+(j*7)], buf[23+(j*7)], buf[24+(j*7)]);
                }
                if (rdr->tcp_connected || rdr->card_status == CARD_INSERTED) {

                    add_card_to_serverlist(server_cards, card);
                }
                else
                    cc_free_card(card);
            }

            if (rdr->typ == R_CCCAM && cfg.cc_reshare_services<2 && rdr->card_status != CARD_FAILURE) {

                cs_debug_mask(D_TRACE, "asking reader %s for cards...", rdr->label);

                struct cc_card *card;
                struct s_client *rc = rdr->client;
                struct cc_data *rcc = rc?rc->cc:NULL;

                int count = 0;
                if (rcc && rcc->cards && rcc->mode == CCCAM_MODE_NORMAL) {
                    if (!pthread_mutex_trylock(&rcc->cards_busy)) {
                        LL_ITER *it = ll_iter_create(rcc->cards);
                        while ((card = ll_iter_next(it))) {
                            if (chk_ctab(card->caid, &rdr->ctab)) {
                                    int ignore = 0;

                                    LL_ITER *it2 = ll_iter_create(card->providers);
                                    struct cc_provider *prov;
                                    while ((prov = ll_iter_next(it2))) {
                                        ulong prid = prov->prov;
                                        if (!chk_srvid_by_caid_prov(rdr->client, card->caid, prid)) {
                                            ignore = 1;
                                            break;
                                        }
                                    }
                                    ll_iter_release(it2);

                                    if (!ignore) { //Filtered by service
                                        add_card_to_serverlist(server_cards, card);
                                        count++;
                                    }
                            }
                        }
                        ll_iter_release(it);
                        pthread_mutex_unlock(&rcc->cards_busy);
                    }
                }
                else
                		cs_debug_mask(D_TRACE, "reader %s not active! (mode=%d)", rdr->label, rcc?rcc->mode:-1);
                cs_debug_mask(D_TRACE, "got %d cards from %s", count, rdr->label);
            }
        }
    }

    //report reshare cards:
    //cs_debug_mask(D_TRACE, "%s reporting %d cards", getprefix(), ll_count(server_cards));
    LL_ITER *it = ll_iter_create(server_cards);
    struct cc_card *card;
    while ((card = ll_iter_next(it))) {
            //cs_debug_mask(D_TRACE, "%s card %d caid %04X hop %d", getprefix(), card->id, card->caid, card->hop);

            report_card(card, new_reported_carddatas);
            ll_iter_remove(it);
    }
    ll_iter_release(it);
    cc_free_cardlist(server_cards, TRUE);

    //remove unsed, remaining cards:
    card_removed_count += cc_free_reported_carddata(reported_carddatas, new_reported_carddatas, TRUE);
    reported_carddatas = new_reported_carddatas;

	cs_debug_mask(D_TRACE, "reported/updated +%d/-%d/dup %d of %d cards to sharelist",
       		card_added_count, card_removed_count, card_dup_count, ll_count(reported_carddatas));
}

int cc_srv_report_cards(struct s_client *cl) {
		//pthread_mutex_lock(&cc_shares_lock);
		LL_ITER *it = ll_iter_create(reported_carddatas);
		struct cc_card *card;
		while ((card = ll_iter_next(it))) {
				send_card_to_clients(card, cl);
		}
		ll_iter_release(it);
		//pthread_mutex_unlock(&cc_shares_lock);

		return 1;
}

void refresh_shares()
{
		//pthread_mutex_lock(&cc_shares_lock);
		update_card_list();
		//pthread_mutex_unlock(&cc_shares_lock);
}

#define DEFAULT_SHORT_INTERVAL 30

void share_updater()
{
		int i = DEFAULT_SHORT_INTERVAL;
		ulong last_check = 0;
		ulong last_card_check = 0;
		ulong card_count = 0;
		while (TRUE) {
				if ((i > 0 || cfg.cc_forward_origin_card) && card_count < 100) { //fast refresh only if we have less cards
						cs_sleepms(1000);
						i--;
				}
				else if (i > 0) {
						cs_sleepms(6000); //1s later than garbage collector because this list uses much space
						i--;
				}
				else
				{
						if (cfg.cc_update_interval <= 0)
								cfg.cc_update_interval = DEFAULT_UPDATEINTERVAL;
						cs_sleepms(cfg.cc_update_interval*1000);
				}
				
				ulong cur_check = 0;
				ulong cur_card_check = 0;
				struct s_reader *rdr;
				for (rdr=first_active_reader; rdr; rdr=rdr->next) {
						if (rdr->client && rdr->client->cc) { //check cccam-cardlist:
								struct cc_data *cc = rdr->client->cc;
								cur_card_check += cc->card_added_count;
								cur_card_check += cc->card_removed_count;
								card_count += ll_count(cc->cards);
						}
						cur_check = crc32(cur_check, (uint8*)&rdr->tcp_connected, sizeof(rdr->tcp_connected));
						cur_check = crc32(cur_check, (uint8*)&rdr->card_status, sizeof(rdr->card_status));
						cur_check = crc32(cur_check, (uint8*)&rdr->hexserial, 8); //check hexserial
						cur_check = crc32(cur_check, (uint8*)&rdr->prid, rdr->nprov * sizeof(rdr->prid[0])); //check providers
						cur_check = crc32(cur_check, (uint8*)&rdr->sa, rdr->nprov * sizeof(rdr->sa[0])); //check provider-SA
						cur_check = crc32(cur_check, (uint8*)&rdr->ftab, sizeof(FTAB)); //check reader 
						cur_check = crc32(cur_check, (uint8*)&rdr->ctab, sizeof(CAIDTAB)); //check caidtab
						cur_check = crc32(cur_check, (uint8*)&rdr->fchid, sizeof(FTAB)); //check chids
						cur_check = crc32(cur_check, (uint8*)&rdr->sidtabok, sizeof(rdr->sidtabok)); //check assigned ok services
						cur_check = crc32(cur_check, (uint8*)&rdr->sidtabno, sizeof(rdr->sidtabno)); //check assigned no services
				}
				
				//check defined services:
				struct s_sidtab *ptr;
		        for (ptr=cfg.sidtab; ptr; ptr=ptr->next) {
		        		cur_check = crc32(cur_check, (uint8*)ptr, sizeof(struct s_sidtab));
				}
				
				//update cardlist if reader config has changed, also set interval to 1s / 30times
				if (cur_check != last_check) {
						i = DEFAULT_SHORT_INTERVAL;
						cs_debug_mask(D_TRACE, "share-update [1] %lu %lu", cur_check, last_check); 
						refresh_shares();
						last_check = cur_check;
						last_card_check = cur_card_check;
				}
				//update cardlist if cccam cards has changed:
				else if (cur_card_check != last_card_check) {
						cs_debug_mask(D_TRACE, "share-update [2] %lu %lu", cur_card_check, last_card_check); 
						refresh_shares();
						last_card_check = cur_card_check;
				}
		}
}

void init_share() {

		reported_carddatas = ll_create();
		//pthread_mutex_init(&cc_shares_lock, NULL);

		share_updater_thread = 0;
		pthread_t temp;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
#ifndef TUXBOX
        pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
#endif
        if (pthread_create(&temp, &attr, (void*)&share_updater, NULL))
        		cs_log("ERROR: can't create share updater thread!");
		else {
        		cs_debug_mask(D_TRACE, "share updater thread started");
        		pthread_detach(temp);
        		share_updater_thread = temp;
        }
        pthread_attr_destroy(&attr);
}            

void done_share() {
		if (share_updater_thread) {
				pthread_cancel(share_updater_thread);
				share_updater_thread = 0;
				
				cc_free_reported_carddata(reported_carddatas, NULL, 0);
				//pthread_mutex_unlock(&cc_shares_lock);
				//pthread_mutex_destroy(&cc_shares_lock);
		}
}
