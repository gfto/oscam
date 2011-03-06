/*
* module-cccshare.h
*
*  Created on: 26.02.2011
*      Author: schlocke
*/
#ifndef MODULECCCSHARE_H_
#define MODULECCCSHARE_H_
     
     
#include <string.h>
#include <stdlib.h>
#include "globals.h"
#include "module-cccam.h"
#include <time.h>
#include "reader-common.h"
#include <poll.h>


void init_share();
void done_share();
void add_share(struct cc_card *card);
void remove_share(struct cc_card *card);

LLIST *get_and_lock_sharelist();
void unlock_sharelist();
void refresh_shares();
                        
int chk_ident(FTAB *ftab, struct cc_card *card);
int card_valid_for_client(struct s_client *cl, struct cc_card *card);

int cc_clear_reported_carddata(LLIST *reported_carddatas, LLIST *except,
                int send_removed);
int cc_free_reported_carddata(LLIST *reported_carddatas, LLIST *except,
                int send_removed);

int send_card_to_clients(struct cc_card *card, struct s_client *one_client);
void send_remove_card_to_clients(struct cc_card *card);

int cc_srv_report_cards(struct s_client *cl);

#endif /* MODULECCCSHARE_H_ */
