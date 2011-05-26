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

	char targetfile[256];
	snprintf(targetfile, sizeof(targetfile),"%s%s", get_tmp_dir(), "/oscam.lcd");

	int32_t seconds = 0, secs = 0, fullmins = 0, mins = 0, fullhours = 0, hours = 0,	days = 0;
	time_t now = time((time_t)0);

	while(running) {
		now = time((time_t)0);
		int16_t cnt = 0, idx = 0, count_r = 0, count_p = 0, count_u = 0;
		FILE *fpsave;

		if((fpsave = fopen(targetfile,"w"))){

			idx = 0;
			int16_t i;
			char *type;
			char *label;
			char *status;

			// Statuslines start
			secs = 0; fullmins = 0; mins = 0; fullhours = 0; hours = 0; days = 0;

			seconds = now - first_client->login;
			secs = seconds % 60;
			if (seconds > 60) {
				fullmins = seconds / 60;
				mins = fullmins % 60;
				if(fullmins > 60) {
					fullhours = fullmins / 60;
					hours = fullhours % 24;
					days = fullhours / 24;
				}
			}

			fprintf(fpsave,"status0: Version: %s\n", CS_VERSION);
			fprintf(fpsave,"status1: Revision: %s\n", CS_SVN_VERSION);
			if(days == 0)
				fprintf(fpsave, "status2: up: %02d:%02d:%02d\n", hours, mins, secs);
			else
				fprintf(fpsave, "status2: up: %02dd %02d:%02d:%02d\n", days, hours, mins, secs);
			fprintf(fpsave,"status3: totals: %d/%d/%d/%d/%d/%d\n", first_client->cwfound, first_client->cwnot, first_client->cwignored, first_client->cwtout, first_client->cwcache, first_client->cwtun);
			fprintf(fpsave,"status4: uptime: %d\n", seconds);
			// Statuslines end

			// Readertable head
			fprintf(fpsave,"Typ| Label      | Idle         | w | s | b | e | St\n");
			fprintf(fpsave,"---+------------+--------------+---+---+---+---+----\n");

			struct s_client *cl;

			// Reader/Proxy table start
			for ( i=0, cl=first_client; cl ; cl=cl->next, i++) {

				if (cl->typ=='r' || cl->typ=='p'){
					type = "";
					label = "";
					status = "OFF";
					secs = 0; fullmins = 0; mins = 0; fullhours = 0; hours = 0; days = 0;

					seconds = now - cl->last;

					if (cl->typ == 'r'){
						type = "R";
						idx = count_r;
						label = cl->reader->label;
						if (cl->reader->card_status == CARD_INSERTED)
							status = "OK";
						count_r++;
					}

					else if (cl->typ == 'p'){
						type = "P";
						idx = count_p;
						label = cl->reader->label;
						if (cl->reader->card_status == CARD_INSERTED)
							status = "CON";
						count_p++;
					}


					secs = seconds % 60;
					if (seconds > 60) {
						fullmins = seconds / 60;
						mins = fullmins % 60;
						if(fullmins > 60) {
							fullhours = fullmins / 60;
							hours = fullhours % 24;
							days = fullhours / 24;
						}
					}

					int16_t written = 0, skipped = 0, blocked = 0, error = 0;

					for (i=0; i<4; i++) {
						error += cl->reader->emmerror[i];
						blocked += cl->reader->emmblocked[i];
						skipped += cl->reader->emmskipped[i];
						written += cl->reader->emmwritten[i];
					}

					if(days == 0) {
						fprintf(fpsave,"%s%d | %-10.10s |     %02d:%02d:%02d |% 3d|% 3d|% 3d|% 3d| %s\n",
								type, idx, label, hours, mins,
								secs, written, skipped, blocked, error, status);
					} else {
						fprintf(fpsave,"%s%d | %-10.10s |% 2dd %02d:%02d:%02d |% 3d|% 3d|% 3d|% 3d| %s\n",
								type, idx, label, days, hours, mins,
								secs, written, skipped, blocked, error, status);
					}

				}
			}

			fprintf(fpsave,"---+------------+--------------+---+---+---+--++----\n");
			// Reader/Proxy table end


			// Usertable start
			fprintf(fpsave,"Typ| Label      | Channel                     | Time\n");
			fprintf(fpsave,"---+------------+-----------------------------+-----\n");

			//Testclient
			fprintf(fpsave,"%s%d | %-10.10s | %-10.10s:%-17.17s| % 4d\n",
					"U",
					1,
					"test",
					"Sky De",
					"Discovery Channel",
					568);



			for ( i=0, cl=first_client; cl ; cl=cl->next, i++) {

				seconds = now - cl->lastecm;

				if (cl->typ == 'c' && seconds < 15){
					type = "U";
					idx = count_u;
					label = cl->account->usr;
					count_u++;

					get_servicename(cl, cl->last_srvid, cl->last_caid);
					fprintf(fpsave,"%s%d | %-10.10s | %-10.10s:%-17.17s| % 4d\n",
							type,
							idx,
							label,
							cl->last_srvidptr && cl->last_srvidptr->prov ? cl->last_srvidptr->prov : "",
									cl->last_srvidptr && cl->last_srvidptr->name ? cl->last_srvidptr->name : "",
											cl->cwlastresptime);

				}
			}
			fprintf(fpsave,"---+------------+-----------------------------+-----\n");
			// Usertable end
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
