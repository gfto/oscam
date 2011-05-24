#include "globals.h"
#ifdef LCDSUPPORT
/*
 * module-lcd.c
 *
 *  Created on: 24.05.2011
 *      Author: alno
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <dirent.h>
#include "module-stat.h"

int8_t running;

void refresh_lcd_file() {

	int16_t cnt = 0, idx = 0, count_r = 0, count_p = 0, count_u = 0;
	char targetfile[256];
	snprintf(targetfile, sizeof(targetfile),"%s%s", get_tmp_dir(), "/oscam.lcd");

	while(running) {

		FILE *fpsave;

		if((fpsave = fopen(targetfile,"w"))){

			struct s_reader *rdr;
			LL_ITER itr = ll_iter_create(configured_readers);
			while((rdr = ll_iter_next(&itr))){
				fprintf(fpsave,"reader%d %s\n", idx, rdr->label);

				if(rdr->typ & R_IS_NETWORK){
					if (rdr->card_status == CARD_INSERTED)
						fprintf(fpsave,"reader%d %s\n", idx, "CONNECTED");
					count_p++;
				} else {
					if (rdr->card_status == CARD_INSERTED)
						fprintf(fpsave,"reader%d %s\n", idx, "CARDOK");
					count_r++;
				}

				idx++;
			}

			idx = 0;
			int16_t i;
			struct s_client *cl;
			for ( i=0, cl=first_client; cl ; cl=cl->next, i++) {
				if (cl->typ=='c'){
					count_u++;
					get_servicename(cl, cl->last_srvid, cl->last_caid);
					fprintf(fpsave,"user%d: %s - %s:%s [%d]\n",
							idx,
							cl->account->usr,
							cl->last_srvidptr && cl->last_srvidptr->prov ? cl->last_srvidptr->prov : "",
							cl->last_srvidptr && cl->last_srvidptr->name ? cl->last_srvidptr->name : "",
							cl->cwlastresptime);


					idx++;
				}
			}

			fprintf(fpsave,"status0: %s\n", CS_VERSION);
			fprintf(fpsave,"status1: OSCam Rev. %s\n", CS_SVN_VERSION);
			//fprintf(fpsave,"status2: %s\n", sec2timeformat(vars, (now - first_client->login)));
			fprintf(fpsave,"status3: proxies:%d\n", count_p);
			fprintf(fpsave,"status4: reader:%d\n", count_r);
			fprintf(fpsave,"status5: user:%d\n", count_u);

			fclose(fpsave);
		}
		idx = 0;
		cs_sleepms(10000);
		cnt++;
	}

}

void start_lcd_thread() {
	running = 1;
	start_thread((void *) &refresh_lcd_file, "LCD");
}

void end_lcd_thread() {
	running = 0;
}

#endif
