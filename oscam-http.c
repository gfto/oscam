//FIXME Not checked on threadsafety yet; after checking please remove this line
#include "globals.h"
#ifdef WEBIF
//
// OSCam HTTP server module
//

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/socket.h>
#include "oscam-http-helpers.c"
#include "module-cccam.h"
#include "module-stat.h"

extern void restart_cardreader(struct s_reader *rdr, int restart);

static int running = 1;

#ifdef CS_ANTICASC
static void kill_ac_client(void)
{
		struct s_client *cl;
		for (cl=first_client->next; cl ; cl=cl->next)
		if (cl->typ=='a') {
			 cs_accounts_chk();
			break;
		}
}
#endif

struct s_reader *get_reader_by_label(char *lbl){
	struct s_reader *rdr;
	for (rdr = first_reader; rdr ; rdr = rdr->next) {
		if (strcmp(lbl, rdr->label) == 0)
			return rdr;
	}
	return NULL;
}

void refresh_oscam(enum refreshtypes refreshtype, struct in_addr in) {

	switch (refreshtype) {
		case REFR_ACCOUNTS:
		cs_log("Refresh Accounts requested by WebIF from %s", inet_ntoa(*(struct in_addr *)&in));

		cs_accounts_chk();
		break;

		case REFR_READERS:
		cs_card_info();
		cs_log("Refresh Reader/Tiers requested by WebIF from %s", inet_ntoa(*(struct in_addr *)&in));
		break;

		case REFR_SERVER:
		cs_log("Refresh Server requested by WebIF from %s", inet_ntoa(*(struct in_addr *)&in));
		//kill(first_client->pid, SIGHUP);
		//todo how I can refresh the server after global settings
		break;

		case REFR_SERVICES:
		cs_log("Refresh Services requested by WebIF from %s", inet_ntoa(*(struct in_addr *)&in));
		//init_sidtab();
		cs_reinit_clients(cfg->account);
		break;

#ifdef CS_ANTICASC
		case REFR_ANTICASC:
		cs_log("Refresh Anticascading requested by WebIF from %s", inet_ntoa(*(struct in_addr *)&in));
		kill_ac_client();
#endif
		default:
			break;
	}
}

void send_oscam_config_global(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in) {
	int i;

	if (strcmp(getParam(params, "action"), "execute") == 0) {
		for(i = 0; i < (*params).paramcount; ++i) {
			if ((strcmp((*params).params[i], "part")) && (strcmp((*params).params[i], "action"))) {
				//tpl_printf(vars, 1, "MESSAGE", "Parameter: %s set to Value: %s<BR>\n", (*params).params[i], (*params).values[i]);
				//we use the same function as used for parsing the config tokens

				chk_t_global((*params).params[i], (*params).values[i]);
			}
		}
		tpl_addVar(vars, 1, "MESSAGE", "<BR><BR><B>Configuration Global done. You should restart Oscam now.</B><BR><BR>");
		if(write_config()==0) refresh_oscam(REFR_SERVER, in);
		else tpl_addVar(vars, 1, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}
	if (cfg->srvip != 0)
	tpl_addVar(vars, 0, "SERVERIP", inet_ntoa(*(struct in_addr *)&cfg->srvip));
	if(cfg->disableuserfile == 1)
		tpl_addVar(vars, 0, "CHKDISABLEUSERFILE", "checked");
	if (cfg->usrfile != NULL) tpl_addVar(vars, 0, "USERFILE", cfg->usrfile);
	if(cfg->disablelog == 1)
		tpl_addVar(vars, 0, "CHKDISABLELOG", "checked");
	if (cfg->logfile != NULL) tpl_addVar(vars, 0, "LOGFILE", cfg->logfile);
	if (cfg->cwlogdir != NULL) tpl_addVar(vars, 0, "CWLOGDIR", cfg->cwlogdir);
	tpl_printf(vars, 0, "USERFILEFLAG", "%d", cfg->usrfileflag);
	tpl_printf(vars, 0, "CLIENTTIMEOUT", "%ld", cfg->ctimeout);
	tpl_printf(vars, 0, "FALLBACKTIMEOUT", "%ld", cfg->ftimeout);
	tpl_printf(vars, 0, "CLIENTMAXIDLE", "%d", cfg->cmaxidle);
	tpl_printf(vars, 0, "CACHEDELAY", "%ld", cfg->delay);
	tpl_printf(vars, 0, "BINDWAIT", "%d", cfg->bindwait);
	tpl_printf(vars, 0, "NETPRIO", "%ld", cfg->netprio);
	if (cfg->clientdyndns)
		tpl_addVar(vars, 0, "CHKCLIENTDYNDNS", "checked");
	tpl_printf(vars, 0, "RESOLVEDELAY", "%d", cfg->resolvedelay);
	tpl_printf(vars, 0, "SLEEP", "%d", cfg->tosleep);
	if (cfg->ulparent == 1)
		tpl_addVar(vars, 0, "UNLOCKPARENTAL", "checked");
	tpl_printf(vars, 0, "NICE", "%d", cfg->nice);
	tpl_printf(vars, 0, "SERIALTIMEOUT", "%d", cfg->srtimeout);
	tpl_printf(vars, 0, "MAXLOGSIZE", "%d", cfg->max_log_size);
	if (cfg->waitforcards == 1)
		tpl_addVar(vars, 0, "WAITFORCARDS", "checked");
	if (cfg->preferlocalcards == 1)
		tpl_addVar(vars, 0, "PREFERLOCALCARDS", "checked");
	if (cfg->saveinithistory == 1)
		tpl_addVar(vars, 0, "SAVEINITHISTORY", "checked");
	if (cfg->reader_restart_seconds)
		tpl_printf(vars, 0, "READERRESTARTSECONDS", "%d", cfg->reader_restart_seconds);

	if (cfg->resolve_gethostbyname == 1)
		tpl_addVar(vars, 0, "RESOLVER1", "selected");
	else
		tpl_addVar(vars, 0, "RESOLVER0", "selected");

	tpl_printf(vars, 0, "FAILBANTIME", "%d", cfg->failbantime);
	tpl_printf(vars, 0, "FAILBANCOUNT", "%d", cfg->failbancount);


#ifdef CS_WITH_DOUBLECHECK
	if(cfg->double_check == 1)
		tpl_addVar(vars, 0, "DCHECKCSELECTED", "selected");
#endif



	webif_write(tpl_getTpl(vars, "CONFIGGLOBAL"), f);
}

void send_oscam_config_loadbalancer(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in) {
	int i;
	if (strcmp(getParam(params, "action"),"execute") == 0) {

		memset(cfg->ser_device, 0, sizeof(cfg->ser_device));
		for(i = 0; i < (*params).paramcount; ++i) {
			if ((strcmp((*params).params[i], "part")) && (strcmp((*params).params[i], "action"))) {
				//tpl_printf(vars, 1, "MESSAGE", "Parameter: %s set to Value: %s<BR>\n", (*params).params[i], (*params).values[i]);
				//we use the same function as used for parsing the config tokens
				if((*params).values[i][0])
					chk_t_global((*params).params[i], (*params).values[i]);
			}
		}
		tpl_addVar(vars, 1, "MESSAGE", "<BR><BR><B>Configuration Loadbalancer done.</B><BR><BR>");
		if(write_config()==0) refresh_oscam(REFR_SERVER, in);
		else tpl_addVar(vars, 1, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}

	tpl_printf(vars, 0, "TMP", "LBMODE%d", cfg->lb_mode);
	tpl_addVar(vars, 0, tpl_getVar(vars, "TMP"), "selected");

	tpl_printf(vars, 0, "LBSAVE", "%d",cfg->lb_save);

	tpl_printf(vars, 0, "LBNBESTREADERS", "%d",cfg->lb_nbest_readers);
	tpl_printf(vars, 0, "LBNFBREADERS", "%d",cfg->lb_nfb_readers);
	tpl_printf(vars, 0, "LBMINECMCOUNT", "%d",cfg->lb_min_ecmcount);
	tpl_printf(vars, 0, "LBMAXECEMCOUNT", "%d",cfg->lb_max_ecmcount);
	tpl_printf(vars, 0, "LBREOPENSECONDS", "%d",cfg->lb_reopen_seconds);

	webif_write(tpl_getTpl(vars, "CONFIGLOADBALANCER"), f);

}

void send_oscam_config_camd33(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in) {
	int i;

	if (strcmp(getParam(params, "action"), "execute") == 0) {
		for(i = 0; i < (*params).paramcount; ++i) {
			if ((strcmp((*params).params[i], "part")) && (strcmp((*params).params[i], "action"))) {
				tpl_printf(vars, 1, "MESSAGE", "Parameter: %s set to Value: %s<BR>\n", (*params).params[i], (*params).values[i]);
				if (strcmp((*params).params[i], "nocrypt") == 0) {
					clear_sip(&cfg->c33_plain);
				}
				//we use the same function as used for parsing the config tokens
				chk_t_camd33((*params).params[i], (*params).values[i]);
			}
		}
		tpl_addVar(vars, 1, "MESSAGE", "<BR><BR><B>Configuration camd33 done. You should restart Oscam now.</B><BR><BR>");
		if(write_config()==0) refresh_oscam(REFR_SERVER, in);
		else tpl_addVar(vars, 1, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}

	if (cfg->c33_port) {
		tpl_printf(vars, 0, "PORT", "%d", cfg->c33_port);
		if (cfg->c33_srvip != 0)
			tpl_addVar(vars, 0, "SERVERIP", inet_ntoa(*(struct in_addr *)&cfg->c33_srvip));
		if (cfg->c33_passive == 1)
			tpl_addVar(vars, 0, "PASSIVE", "checked");

		for (i = 0; i < (int) sizeof(cfg->c33_key); ++i) tpl_printf(vars, 1, "KEY", "%02X",cfg->c33_key[i]);
		struct s_ip *cip;
		char *dot="";
		for (cip = cfg->c33_plain; cip; cip = cip->next) {
			tpl_printf(vars, 1, "NOCRYPT", "%s%s", dot, cs_inet_ntoa(cip->ip[0]));
			if (cip->ip[0] != cip->ip[1]) tpl_printf(vars, 1, "NOCRYPT", "-%s", cs_inet_ntoa(cip->ip[1]));
			dot=",";
		}
	}

	webif_write(tpl_getTpl(vars, "CONFIGCAMD33"), f);
}

void send_oscam_config_camd35(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in) {
	int i;
	if ((strcmp(getParam(params, "action"),"execute") == 0) && (getParam(params, "port"))[0]) {
		for(i = 0; i < (*params).paramcount; ++i) {
			if ((strcmp((*params).params[i], "part")) && (strcmp((*params).params[i], "action"))) {
				tpl_printf(vars, 1, "MESSAGE", "Parameter: %s set to Value: %s<BR>\n", (*params).params[i], (*params).values[i]);
				//we use the same function as used for parsing the config tokens
				chk_t_camd35((*params).params[i], (*params).values[i]);
			}
		}
		tpl_addVar(vars, 1, "MESSAGE", "<BR><BR><B>Configuration camd35 done. You should restart Oscam now.</B><BR><BR>");
		if(write_config()==0) refresh_oscam(REFR_SERVER, in);
		else tpl_addVar(vars, 1, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}

	if (cfg->c35_port) {
		tpl_printf(vars, 0, "PORT", "%d", cfg->c35_port);
		if (cfg->c35_srvip != 0)
			tpl_addVar(vars, 1, "SERVERIP", inet_ntoa(*(struct in_addr *)&cfg->c35_srvip));

		if (cfg->c35_suppresscmd08)
			tpl_addVar(vars, 0, "SUPPRESSCMD08", "checked");
	}
	webif_write(tpl_getTpl(vars, "CONFIGCAMD35"), f);
}

void send_oscam_config_camd35tcp(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in) {
	int i;
	if ((strcmp(getParam(params, "action"),"execute") == 0) && (getParam(params, "port"))[0]) {
		clear_ptab(&cfg->c35_tcp_ptab); /*clear Porttab*/
		for(i = 0; i < (*params).paramcount; ++i) {
			if ((strcmp((*params).params[i], "part")) && (strcmp((*params).params[i], "action"))) {
				tpl_printf(vars, 1, "MESSAGE", "Parameter: %s set to Value: %s<BR>\n", (*params).params[i], (*params).values[i]);
				//we use the same function as used for parsing the config tokens
				chk_t_camd35_tcp((*params).params[i], (*params).values[i]);
			}
		}
		tpl_addVar(vars, 1, "MESSAGE", "<BR><BR><B>Configuration camd35 TCP done. You should restart Oscam now.</B><BR><BR>");
		if(write_config()==0) refresh_oscam(REFR_SERVER, in);
		else tpl_addVar(vars, 1, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}

	int j;
	char *dot1, *dot2;
	if ((cfg->c35_tcp_ptab.nports > 0) && (cfg->c35_tcp_ptab.ports[0].s_port > 0)) {
		dot1 = "";
		for(i = 0; i < cfg->c35_tcp_ptab.nports; ++i) {
			tpl_printf(vars, 1, "PORT", "%s%d@%04X", dot1, cfg->c35_tcp_ptab.ports[i].s_port, cfg->c35_tcp_ptab.ports[i].ftab.filts[0].caid);
			if (cfg->c35_tcp_ptab.ports[i].ftab.filts[0].nprids > 1) {
				tpl_printf(vars, 1, "PORT", ":");
				dot2 = "";
				for (j = 0; j < cfg->c35_tcp_ptab.ports[i].ftab.filts[0].nprids; ++j) {
					tpl_printf(vars, 1, "PORT", "%s%lX", dot2, cfg->c35_tcp_ptab.ports[i].ftab.filts[0].prids[j]);
					dot2 = ",";
				}
			}
			dot1=";";
		}

		if (cfg->c35_tcp_srvip != 0)
			tpl_addVar(vars, 1, "SERVERIP", inet_ntoa(*(struct in_addr *)&cfg->c35_tcp_srvip));

	}
	webif_write(tpl_getTpl(vars, "CONFIGCAMD35TCP"), f);
}

void send_oscam_config_newcamd(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in) {
	int i;
	if (strcmp(getParam(params, "action"),"execute") == 0) {
		clear_ptab(&cfg->ncd_ptab); /*clear Porttab*/
		for(i = 0; i < (*params).paramcount; ++i) {
			if ((strcmp((*params).params[i], "part")) && (strcmp((*params).params[i], "action"))) {
				tpl_printf(vars, 1, "MESSAGE", "Parameter: %s set to Value: %s<BR>\n", (*params).params[i], (*params).values[i]);
				//we use the same function as used for parsing the config tokens
				if (strcmp((*params).params[i], "allowed") == 0) {
					clear_sip(&cfg->ncd_allowed);
				}
				chk_t_newcamd((*params).params[i], (*params).values[i]);
			}
		}
		tpl_addVar(vars, 1, "MESSAGE", "<BR><BR><B>Configuration Newcamd done. You should restart Oscam now.</B><BR><BR>");
		if(write_config()==0) refresh_oscam(REFR_SERVER, in);
		else tpl_addVar(vars, 1, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}

	if ((cfg->ncd_ptab.nports > 0) && (cfg->ncd_ptab.ports[0].s_port > 0)) {

		char *value = mk_t_newcamd_port();
		tpl_addVar(vars, 0, "PORT", value);
		free(value);

		if (cfg->ncd_srvip != 0)
			tpl_addVar(vars, 0, "SERVERIP", inet_ntoa(*(struct in_addr *)&cfg->ncd_srvip));

		for (i = 0; i < 14; i++) tpl_printf(vars, 1, "KEY", "%02X", cfg->ncd_key[i]);

		struct s_ip *cip;
		char *dot = "";
		for (cip = cfg->ncd_allowed; cip; cip = cip->next) {
			tpl_printf(vars, 1, "ALLOWED", "%s%s", dot, cs_inet_ntoa(cip->ip[0]));
			if (cip->ip[0] != cip->ip[1]) tpl_printf(vars, 1, "ALLOWED", "-%s", cs_inet_ntoa(cip->ip[1]));
			dot=",";
		}

		if (cfg->ncd_keepalive)
			tpl_addVar(vars, 0, "KEEPALIVE", "checked");
		if (cfg->ncd_mgclient)
			tpl_addVar(vars, 0, "MGCLIENTCHK", "checked");
	}
	webif_write(tpl_getTpl(vars, "CONFIGNEWCAMD"), f);
}

void send_oscam_config_radegast(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in) {
	int i;
	if (strcmp(getParam(params, "action"),"execute") == 0) {
		for(i = 0; i < (*params).paramcount; ++i) {
			if ((strcmp((*params).params[i], "part")) && (strcmp((*params).params[i], "action"))) {
				tpl_printf(vars, 1, "MESSAGE", "Parameter: %s set to Value: %s<BR>\n", (*params).params[i], (*params).values[i]);
				if (strcmp((*params).params[i], "allowed") == 0) {
					clear_sip(&cfg->rad_allowed);
				}
				//we use the same function as used for parsing the config tokens
				chk_t_radegast((*params).params[i], (*params).values[i]);
			}
		}
		tpl_addVar(vars, 1, "MESSAGE", "<BR><BR><B>Configuration Radegast done. You should restart Oscam now.</B><BR><BR>");
		if(write_config()==0) refresh_oscam(REFR_SERVER, in);
		else tpl_addVar(vars, 1, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}
	tpl_printf(vars, 0, "PORT", "%d", cfg->rad_port);
	if (cfg->rad_srvip != 0)
	tpl_addVar(vars, 0, "SERVERIP", inet_ntoa(*(struct in_addr *)&cfg->rad_srvip));
	tpl_addVar(vars, 0, "USER", cfg->rad_usr);

	struct s_ip *cip;
	char *dot="";
	for (cip=cfg->rad_allowed; cip; cip=cip->next) {
		tpl_printf(vars, 1, "ALLOWED", "%s%s", dot, cs_inet_ntoa(cip->ip[0]));
		if (cip->ip[0] != cip->ip[1])
			tpl_printf(vars, 1, "ALLOWED", "-%s", cs_inet_ntoa(cip->ip[1]));
		dot=",";
	}

	webif_write(tpl_getTpl(vars, "CONFIGRADEGAST"), f);
}

void send_oscam_config_cccam(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in) {
	int i;
	if (strcmp(getParam(params, "action"),"execute") == 0) {
		for(i = 0; i < (*params).paramcount; ++i) {
			if ((strcmp((*params).params[i], "part")) && (strcmp((*params).params[i], "action"))) {
				tpl_printf(vars, 1, "MESSAGE", "Parameter: %s set to Value: %s<BR>\n", (*params).params[i], (*params).values[i]);
				//we use the same function as used for parsing the config tokens
				chk_t_cccam((*params).params[i], (*params).values[i]);
			}
		}
		if(write_config()==0) refresh_oscam(REFR_SERVER, in);
		else tpl_addVar(vars, 1, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}

	tpl_printf(vars, 1, "PORT", "%d", cfg->cc_port);
	tpl_printf(vars, 0, "RESHARE", "%d", cfg->cc_reshare);

	if (!strcmp((char*)cfg->cc_version,"2.0.11")) {
		tpl_addVar(vars, 0, "VERSIONSELECTED0", "selected");
	} else if (!strcmp((char*)cfg->cc_version,"2.1.1")) {
		tpl_addVar(vars, 0, "VERSIONSELECTED1", "selected");
	} else if (!strcmp((char*)cfg->cc_version,"2.1.2")) {
		tpl_addVar(vars, 0, "VERSIONSELECTED2", "selected");
	} else if (!strcmp((char*)cfg->cc_version,"2.1.3")) {
		tpl_addVar(vars, 0, "VERSIONSELECTED3", "selected");
	} else if (!strcmp((char*)cfg->cc_version,"2.1.4")) {
		tpl_addVar(vars, 0, "VERSIONSELECTED4", "selected");
	} else if (!strcmp((char*)cfg->cc_version,"2.2.0")) {
		tpl_addVar(vars, 0, "VERSIONSELECTED5", "selected");
	} else if (!strcmp((char*)cfg->cc_version,"2.2.1")) {
		tpl_addVar(vars, 0, "VERSIONSELECTED6", "selected");
	}

	tpl_printf(vars, 0, "UPDATEINTERVAL", "%d", cfg->cc_update_interval);
	if (cfg->cc_stealth)
		tpl_printf(vars, 0, "STEALTH", "selected");

	tpl_printf(vars, 0, "TMP", "MINIMIZECARDSELECTED%d", cfg->cc_minimize_cards);
	tpl_addVar(vars, 0, tpl_getVar(vars, "TMP"), "selected");

	tpl_printf(vars, 0, "TMP", "RESHAREMODE%d", cfg->cc_reshare_services);
	tpl_addVar(vars, 0, tpl_getVar(vars, "TMP"), "selected");

	if (cfg->cc_ignore_reshare)
		tpl_printf(vars, 0, "IGNORERESHARE", "selected");
	
	if (cfg->cc_keep_connected)
		tpl_printf(vars, 0, "KEEPCONNECTED", "selected");


	webif_write(tpl_getTpl(vars, "CONFIGCCCAM"), f);
}

#ifdef CS_WITH_GBOX
void send_oscam_config_gbox(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in) {
	int i;
	if (strcmp(getParam(params, "action"),"execute") == 0) {
		for(i = 0; i < (*params).paramcount; ++i) {
			if ((strcmp((*params).params[i], "part")) && (strcmp((*params).params[i], "action"))) {
				tpl_printf(vars, 1, "MESSAGE", "Parameter: %s set to Value: %s<BR>\n", (*params).params[i], (*params).values[i]);
				//we use the same function as used for parsing the config tokens
				chk_t_gbox((*params).params[i], (*params).values[i]);
			}
		}
		tpl_addVar(vars, 1, "MESSAGE", "<BR><BR><B>Configuration Gbox done. You should restart Oscam now.</B><BR><BR>");
		if(write_config()==0) refresh_oscam(REFR_SERVER, in);
		else tpl_addVar(vars, 1, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}
	tpl_printf(vars, 0, "MAXDIST", "%d", cfg->maxdist);
	for (i=0;i<4;i++) tpl_printf(vars, 1, "PASSWORD", "%02X", cfg->gbox_pwd[i]);
	tpl_addVar(vars, 0, "IGNORELIST", (char *)cfg->ignorefile);
	tpl_addVar(vars, 0, "ONLINEINFOS", (char *)cfg->gbxShareOnl);
	tpl_addVar(vars, 0, "CARDINFOS", (char *)cfg->cardfile);
	char *dot = "";
	for (i = 0; i < cfg->num_locals; i++) {
		tpl_printf(vars, 1, "LOCALS", "%s%06lX", dot, cfg->locals[i]);
		dot=";";
	}
	webif_write(tpl_getTpl(vars, "CONFIGGBOX"), f);
}
#endif

void send_oscam_config_monitor(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in) {
	int i;
	if (strcmp(getParam(params, "action"),"execute") == 0) {

		//cleanup
		clear_sip(&cfg->mon_allowed);
		clear_sip(&cfg->http_allowed);

		for(i = 0; i < (*params).paramcount; ++i) {
			if ((strcmp((*params).params[i], "part")) && (strcmp((*params).params[i], "action"))) {
				tpl_printf(vars, 1, "MESSAGE", "Parameter: %s set to Value: %s<BR>\n", (*params).params[i], (*params).values[i]);

				//we use the same function as used for parsing the config tokens
				if (strstr((*params).params[i], "http")) {
					chk_t_webif((*params).params[i], (*params).values[i]);
				} else {
					chk_t_monitor((*params).params[i], (*params).values[i]);
				}
			}
		}
		tpl_addVar(vars, 1, "MESSAGE", "<BR><BR><B>Configuration Monitor done. You should restart Oscam now.</B><BR><BR>");
		if(write_config()==0) refresh_oscam(REFR_SERVER, in);
		else tpl_addVar(vars, 1, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}
	tpl_printf(vars, 0, "MONPORT", "%d", cfg->mon_port);
	if (cfg->mon_srvip != 0)
	tpl_addVar(vars, 0, "SERVERIP", inet_ntoa(*(struct in_addr *)&cfg->mon_srvip));
	tpl_printf(vars, 0, "AULOW", "%d", cfg->mon_aulow);
	tpl_printf(vars, 0, "HIDECLIENTTO", "%d", cfg->mon_hideclient_to);
	if(cfg->mon_appendchaninfo)
		tpl_addVar(vars, 0, "APPENDCHANINFO", "checked");

#ifdef WITH_SSL
	if(cfg->http_use_ssl)
		tpl_printf(vars, 0, "HTTPPORT", "+%d", cfg->http_port);
	else
		tpl_printf(vars, 0, "HTTPPORT", "%d", cfg->http_port);
#else
	tpl_printf(vars, 0, "HTTPPORT", "%d", cfg->http_port);
#endif

	tpl_addVar(vars, 0, "HTTPUSER", cfg->http_user);
	tpl_addVar(vars, 0, "HTTPPASSWORD", cfg->http_pwd);

	// css style selector
	if(strlen(cfg->http_css) == 0) {
		tpl_addVar(vars, 0, "CSSOPTIONS", "<option value=\"\" selected>embedded</option>\n");
	} else {
		tpl_addVar(vars, 0, "CSSOPTIONS", "<option value=\"\">embedded</option>\n");
	}

	DIR *hdir;
	struct dirent *entry;
	hdir = opendir(cs_confdir);
	do {
		entry = readdir(hdir);
		if ((entry) && (strstr(entry->d_name, ".css"))) {
			if (strstr(cfg->http_css, entry->d_name)) {
				tpl_printf(vars, 1, "CSSOPTIONS", "<option value=\"%s%s\" selected>%s%s</option>\n",cs_confdir,entry->d_name,cs_confdir,entry->d_name);
			} else {
				tpl_printf(vars, 1, "CSSOPTIONS", "<option value=\"%s%s\">%s%s</option>\n",cs_confdir,entry->d_name,cs_confdir,entry->d_name);
			}
		}
	} while (entry);
	closedir(hdir);

	tpl_printf(vars, 0, "HTTPREFRESH", "%d", cfg->http_refresh);
	tpl_addVar(vars, 0, "HTTPTPL", cfg->http_tpl);
	tpl_addVar(vars, 0, "HTTPSCRIPT", cfg->http_script);
	tpl_addVar(vars, 0, "HTTPJSCRIPT", cfg->http_jscript);

	if (cfg->http_hide_idle_clients > 0) tpl_addVar(vars, 0, "CHECKED", "checked");

	struct s_ip *cip;
	char *dot="";
	for (cip = cfg->mon_allowed; cip; cip = cip->next) {
		tpl_printf(vars, 1, "NOCRYPT", "%s%s", dot, cs_inet_ntoa(cip->ip[0]));
		if (cip->ip[0] != cip->ip[1]) tpl_printf(vars, 1, "NOCRYPT", "-%s", cs_inet_ntoa(cip->ip[1]));
		dot=",";
	}

	dot="";
	for (cip = cfg->http_allowed; cip; cip = cip->next) {
		tpl_printf(vars, 1, "HTTPALLOW", "%s%s", dot, cs_inet_ntoa(cip->ip[0]));
		if (cip->ip[0] != cip->ip[1]) tpl_printf(vars, 1, "HTTPALLOW", "-%s", cs_inet_ntoa(cip->ip[1]));
		dot=",";
	}

	tpl_printf(vars, 0, "HTTPDYNDNS", "%s", cfg->http_dyndns);

	//Monlevel selector
	tpl_printf(vars, 0, "TMP", "MONSELECTED%d", cfg->mon_level);
	tpl_addVar(vars, 0, tpl_getVar(vars, "TMP"), "selected");

	if (cfg->http_full_cfg)
		tpl_addVar(vars, 0, "HTTPSAVEFULLSELECT", "selected");

	if (cfg->http_js_icons)
		tpl_addVar(vars, 0, "HTTPJSICONS", "selected");

	webif_write(tpl_getTpl(vars, "CONFIGMONITOR"), f);
}

void send_oscam_config_serial(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in) {
	int i;
	if (strcmp(getParam(params, "action"),"execute") == 0) {
		//cfg->ser_device[0]='\0';
		memset(cfg->ser_device, 0, sizeof(cfg->ser_device));
		for(i = 0; i < (*params).paramcount; ++i) {
			if ((strcmp((*params).params[i], "part")) && (strcmp((*params).params[i], "action"))) {
				tpl_printf(vars, 1, "MESSAGE", "Parameter: %s set to Value: %s<BR>\n", (*params).params[i], (*params).values[i]);
				//we use the same function as used for parsing the config tokens
				if((*params).values[i][0])
					chk_t_serial((*params).params[i], (*params).values[i]);
			}
		}
		tpl_addVar(vars, 1, "MESSAGE", "<BR><BR><B>Configuration Serial done. You should restart Oscam now.</B><BR><BR>");
		if(write_config()==0) refresh_oscam(REFR_SERVER, in);
		else tpl_addVar(vars, 1, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}

	if (cfg->ser_device[0]){
		char sdevice[512];
		cs_strncpy(sdevice, cfg->ser_device, sizeof(sdevice));
		char *ptr;
		char delimiter[2]; delimiter[0] = 1; delimiter[1] = '\0';
		ptr = strtok(sdevice, delimiter);
		while(ptr != NULL) {
			tpl_printf(vars, 0, "SERIALDEVICE", "%s", ptr);
			tpl_addVar(vars, 1, "DEVICES", tpl_getTpl(vars, "CONFIGSERIALDEVICEBIT"));
			ptr = strtok(NULL, delimiter);
		}
	}

	tpl_printf(vars, 0, "SERIALDEVICE", "%s", "");
	tpl_addVar(vars, 1, "DEVICES", tpl_getTpl(vars, "CONFIGSERIALDEVICEBIT"));

	webif_write(tpl_getTpl(vars, "CONFIGSERIAL"), f);
}

#ifdef HAVE_DVBAPI
void send_oscam_config_dvbapi(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in) {
	int i;
	if (strcmp(getParam(params, "action"),"execute") == 0) {
		for(i = 0; i < (*params).paramcount; ++i) {
			if ((strcmp((*params).params[i], "part")) && (strcmp((*params).params[i], "action"))) {
				tpl_printf(vars, 1, "MESSAGE", "Parameter: %s set to Value: %s<BR>\n", (*params).params[i], (*params).values[i]);
				//we use the same function as used for parsing the config tokens
				chk_t_dvbapi((*params).params[i], (*params).values[i]);
			}
		}
		tpl_addVar(vars, 1, "MESSAGE", "<BR><BR><B>Configuration DVB Api done. You should restart Oscam now.</B><BR><BR>");
		if(write_config()==0) refresh_oscam(REFR_SERVER, in);
		else tpl_addVar(vars, 1, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}

	if (cfg->dvbapi_enabled > 0)
		tpl_addVar(vars, 0, "ENABLEDCHECKED", "checked");

	if (cfg->dvbapi_au > 0)
		tpl_addVar(vars, 0, "AUCHECKED", "checked");

	tpl_printf(vars, 0, "BOXTYPE", "<option value=\"\"%s>None</option>\n", cfg->dvbapi_boxtype == 0 ? " selected" : "");
	for (i=1; i<=BOXTYPES; i++) {
		tpl_printf(vars, 1, "BOXTYPE", "<option%s>%s</option>\n", cfg->dvbapi_boxtype == i ? " selected" : "", boxdesc[i]);
	}

	if(cfg->dvbapi_usr[0])
		tpl_addVar(vars, 0, "USER", cfg->dvbapi_usr);

	//PMT Mode
	tpl_printf(vars, 0, "TMP", "PMTMODESELECTED%d", cfg->dvbapi_pmtmode);
	tpl_addVar(vars, 0, tpl_getVar(vars, "TMP"), "selected");

	webif_write(tpl_getTpl(vars, "CONFIGDVBAPI"), f);
}
#endif

#ifdef CS_ANTICASC
void send_oscam_config_anticasc(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in) {
	int i;
	if (strcmp(getParam(params, "action"),"execute") == 0) {
		for(i = 0; i < (*params).paramcount; ++i) {
			if ((strcmp((*params).params[i], "part")) && (strcmp((*params).params[i], "action"))) {
				tpl_printf(vars, 1, "MESSAGE", "Parameter: %s set to Value: %s<BR>\n", (*params).params[i], (*params).values[i]);
				//we use the same function as used for parsing the config tokens
				chk_t_ac((*params).params[i], (*params).values[i]);
			}
		}
		tpl_addVar(vars, 1, "MESSAGE", "<BR><BR><B>Configuration Anticascading done. You should restart Oscam now.</B><BR><BR>");
		refresh_oscam(REFR_ANTICASC, in);
		if(write_config()==0) refresh_oscam(REFR_SERVER, in);
		else tpl_addVar(vars, 1, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}
	if (cfg->ac_enabled > 0) tpl_addVar(vars, 0, "CHECKED", "checked");
	tpl_printf(vars, 0, "NUMUSERS", "%d", cfg->ac_users);
	tpl_printf(vars, 0, "SAMPLETIME", "%d", cfg->ac_stime);
	tpl_printf(vars, 0, "SAMPLES", "%d", cfg->ac_samples);
	tpl_printf(vars, 0, "PENALTY", "%d", cfg->ac_penalty);
	tpl_addVar(vars, 0, "ACLOGFILE", cfg->ac_logfile);
	tpl_printf(vars, 0, "FAKEDELAY", "%d", cfg->ac_fakedelay);
	tpl_printf(vars, 0, "DENYSAMPLES", "%d", cfg->ac_denysamples);
	webif_write(tpl_getTpl(vars, "CONFIGANTICASC"), f);
}
#endif

void send_oscam_config(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in) {
	char *part = getParam(params, "part");
	if (!strcmp(part,"camd33")) send_oscam_config_camd33(vars, f, params, in);
	else if (!strcmp(part,"camd35")) send_oscam_config_camd35(vars, f, params, in);
	else if (!strcmp(part,"camd35tcp")) send_oscam_config_camd35tcp(vars, f, params, in);
	else if (!strcmp(part,"newcamd")) send_oscam_config_newcamd(vars, f, params, in);
	else if (!strcmp(part,"radegast")) send_oscam_config_radegast(vars, f, params, in);
	else if (!strcmp(part,"cccam")) send_oscam_config_cccam(vars, f, params, in);
#ifdef CS_WITH_GBOX
	else if (!strcmp(part,"gbox")) send_oscam_config_gbox(vars, f, params, in);
#endif
#ifdef HAVE_DVBAPI
	else if (!strcmp(part,"dvbapi")) send_oscam_config_dvbapi(vars, f, params, in);
#endif
#ifdef CS_ANTICASC
	else if (!strcmp(part,"anticasc")) send_oscam_config_anticasc(vars, f, params, in);
#endif
	else if (!strcmp(part,"monitor")) send_oscam_config_monitor(vars, f, params, in);
	else if (!strcmp(part,"serial")) send_oscam_config_serial(vars, f, params, in);
	else if (!strcmp(part,"loadbalancer")) send_oscam_config_loadbalancer(vars, f, params, in);
	else send_oscam_config_global(vars, f, params, in);
}

void send_oscam_reader(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in) {
	struct s_reader *rdr;
	int i;
	//uchar dummy[1]={0x00};

	if ((strcmp(getParam(params, "action"), "disable") == 0) || (strcmp(getParam(params, "action"), "enable") == 0)) {
		rdr = get_reader_by_label(getParam(params, "label"));
		if (strcmp(getParam(params, "action"), "enable") == 0)
			rdr->enable = 1;
		else
			rdr->enable = 0;
		if(write_server()==0)
			refresh_oscam(REFR_READERS, in);
	}

	if (strcmp(getParam(params, "action"), "delete") == 0) {
		rdr = get_reader_by_label(getParam(params, "label"));
		rdr->deleted = 1;

		if(write_server()==0) {
			refresh_oscam(REFR_READERS, in);
			//printf("would kill now PID %d\n", reader[atoi(getParam(params, "reader"))].pid);
			//if(reader[atoi(getParam(params, "reader"))].pid)
			//	kill(reader[atoi(getParam(params, "reader"))].pid, SIGQUIT);
		}
		else
			tpl_addVar(vars, 1, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}

	if (strcmp(getParam(params, "action"), "reread") == 0) {
		rdr = get_reader_by_label(getParam(params, "label"));

		//reset the counters
		for (i = 0; i < 4; i++) {
			rdr->emmerror[i] = 0;
			rdr->emmwritten[i] = 0;
			rdr->emmskipped[i] = 0;
			rdr->emmblocked[i] = 0;
		}
		//write_to_pipe(client[reader[readeridx].cs_idx)].fd_m2c, PIP_ID_CIN, dummy, 1); // do not work for whatever reason
		refresh_oscam(REFR_READERS, in); // refresh all reader because  write pipe seams not work from here
	}

	for (i = 0, rdr = first_reader; rdr && rdr->label[0]; rdr = rdr->next, i++);
	tpl_printf(vars, 0, "NEXTREADER", "Reader-%d", i); //Next Readername

	for (rdr = first_reader; rdr ; rdr = rdr->next) {
		if(rdr->label[0] && rdr->typ && !rdr->deleted) {

			if (rdr->enable)
				tpl_addVar(vars, 0, "READERCLASS", "enabledreader");
			else
				tpl_addVar(vars, 0, "READERCLASS", "disabledreader");

			tpl_addVar(vars, 0, "READERNAME", xml_encode(vars, rdr->label));
			tpl_addVar(vars, 0, "READERNAMEENC", tpl_addTmp(vars, urlencode(rdr->label)));
			tpl_printf(vars, 0, "EMMERRORUK", "%d", rdr->emmerror[UNKNOWN]);
			tpl_printf(vars, 0, "EMMERRORG", "%d", rdr->emmerror[GLOBAL]);
			tpl_printf(vars, 0, "EMMERRORS", "%d", rdr->emmerror[SHARED]);
			tpl_printf(vars, 0, "EMMERRORUQ", "%d", rdr->emmerror[UNIQUE]);

			tpl_printf(vars, 0, "EMMWRITTENUK", "%d", rdr->emmwritten[UNKNOWN]);
			tpl_printf(vars, 0, "EMMWRITTENG", "%d", rdr->emmwritten[GLOBAL]);
			tpl_printf(vars, 0, "EMMWRITTENS", "%d", rdr->emmwritten[SHARED]);
			tpl_printf(vars, 0, "EMMWRITTENUQ", "%d", rdr->emmwritten[UNIQUE]);

			tpl_printf(vars, 0, "EMMSKIPPEDUK", "%d", rdr->emmskipped[UNKNOWN]);
			tpl_printf(vars, 0, "EMMSKIPPEDG", "%d", rdr->emmskipped[GLOBAL]);
			tpl_printf(vars, 0, "EMMSKIPPEDS", "%d", rdr->emmskipped[SHARED]);
			tpl_printf(vars, 0, "EMMSKIPPEDUQ", "%d", rdr->emmskipped[UNIQUE]);

			tpl_printf(vars, 0, "EMMBLOCKEDUK", "%d", rdr->emmblocked[UNKNOWN]);
			tpl_printf(vars, 0, "EMMBLOCKEDG", "%d", rdr->emmblocked[GLOBAL]);
			tpl_printf(vars, 0, "EMMBLOCKEDS", "%d", rdr->emmblocked[SHARED]);
			tpl_printf(vars, 0, "EMMBLOCKEDUQ", "%d", rdr->emmblocked[UNIQUE]);

			if (!cfg->http_js_icons) {
				tpl_addVar(vars, 0, "DELICO", ICDEL);
				tpl_addVar(vars, 0, "STATICO", ICSTA);
				tpl_addVar(vars, 0, "EDIICO", ICEDI);
			}

			if (!(rdr->typ & R_IS_NETWORK)) { //reader is physical
				if (!cfg->http_js_icons)
					tpl_addVar(vars, 0, "REFRICO", ICREF);
				tpl_addVar(vars, 0, "READERREFRESH", tpl_getTpl(vars, "READERREFRESHBIT"));

				if (!cfg->http_js_icons)
					tpl_addVar(vars, 0, "ENTICO", ICENT);
				tpl_addVar(vars, 0, "ENTITLEMENT", tpl_getTpl(vars, "READERENTITLEBIT"));

			} else {
				tpl_addVar(vars, 0, "READERREFRESH","");
				if (rdr->typ == R_CCCAM) {
					if (!cfg->http_js_icons)
						tpl_addVar(vars, 0, "ENTICO", ICENT);
					tpl_addVar(vars, 0, "ENTITLEMENT", tpl_getTpl(vars, "READERENTITLEBIT"));
				} else {
					tpl_addVar(vars, 0, "ENTITLEMENT","");
				}

			}

			if(rdr->enable == 0) {
				if (!cfg->http_js_icons)
					tpl_addVar(vars, 0, "SWITCHICO", ICENA);
				else
					tpl_addVar(vars, 0, "SWITCHICOID", "ICENA");
				tpl_addVar(vars, 0, "SWITCHTITLE", "enable this reader");
				tpl_addVar(vars, 0, "SWITCH", "enable");
			} else {
				if (!cfg->http_js_icons)
					tpl_addVar(vars, 0, "SWITCHICO", ICDIS);
				else
					tpl_addVar(vars, 0, "SWITCHICOID", "ICDIS");
				tpl_addVar(vars, 0, "SWITCHTITLE", "disable this reader");
				tpl_addVar(vars, 0, "SWITCH", "disable");
			}

			tpl_addVar(vars, 0, "CTYP", reader_get_type_desc(rdr, 0));
			tpl_addVar(vars, 1, "READERLIST", tpl_getTpl(vars, "READERSBIT"));
		}
	}

#ifdef CS_WITH_GBOX
	tpl_addVar(vars, 0, "ADDPROTOCOL", "<option>gbox</option>\n");
#endif
#ifdef HAVE_PCSC
	tpl_addVar(vars, 1, "ADDPROTOCOL", "<option>pcsc</option>\n");
#endif
	webif_write(tpl_getTpl(vars, "READERS"), f);
}

void send_oscam_reader_config(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in) {
	int i, ridx=0;
	char *reader_ = getParam(params, "label");
	char *value;

	struct s_reader *rdr;
	for (ridx=0,rdr=first_reader; rdr && rdr->label[0]; rdr=rdr->next, ridx++); //last reader

	if(strcmp(getParam(params, "action"), "Add") == 0) {
		// Add new reader
		struct s_reader *newrdr;
		newrdr = malloc(sizeof(struct s_reader));

		if (newrdr) {
			memset(newrdr, 0, sizeof(struct s_reader));
			for (rdr = first_reader; rdr->next ; rdr = rdr->next); // get last rdr
			rdr->next = newrdr;
			newrdr->next = NULL; // terminate list
			newrdr->enable = 0; // do not start the reader because must configured before
			strcpy(newrdr->pincode, "none");
			for (i = 1; i < CS_MAXCAIDTAB; newrdr->ctab.mask[i++] = 0xffff);
			for (i = 0; i < (*params).paramcount; ++i) {
				if (strcmp((*params).params[i], "action"))
					chk_reader((*params).params[i], (*params).values[i], newrdr);
			}
			reader_ = newrdr->label;
		}


	} else if(strcmp(getParam(params, "action"), "Save") == 0) {

		rdr = get_reader_by_label(getParam(params, "label"));
		char servicelabels[255]="";

		clear_caidtab(&rdr->ctab);
		clear_ftab(&rdr->ftab);
		clear_ftab(&rdr->fchid);

		rdr->grp = 0;
		rdr->auprovid = 0;
		for(i = 0; i < (*params).paramcount; ++i) {
			if ((strcmp((*params).params[i], "reader")) && (strcmp((*params).params[i], "action"))) {
				if (!strcmp((*params).params[i], "services"))
					snprintf(servicelabels + strlen(servicelabels), sizeof(servicelabels), "%s,", (*params).values[i]);
				else
					if(strlen((*params).values[i]) > 0)
						chk_reader((*params).params[i], (*params).values[i], rdr);
			}
			//printf("param %s value %s\n",(*params).params[i], (*params).values[i]);
		}
		chk_reader("services", servicelabels, rdr);

		if(write_server()==0) {
			refresh_oscam(REFR_READERS, in);
			// fixme: restart_cardreader causes segfaults sometimes
			if (rdr->typ & R_IS_NETWORK)
				restart_cardreader(rdr, 1); //physical readers make trouble if re-started
		}
		else
			tpl_addVar(vars, 1, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}

	for (ridx=0,rdr=first_reader; rdr  && strcmp(reader_, rdr->label); rdr=rdr->next, ++ridx);
	tpl_addVar(vars, 0, "READERNAME", rdr->label);

	if(rdr->enable)
		tpl_addVar(vars, 0, "ENABLED", "checked");

	tpl_printf(vars, 0, "ACCOUNT",  "%s", rdr->r_usr);

#ifdef CS_WITH_GBOX
	if (strlen(rdr->gbox_pwd) > 0)
		tpl_printf(vars, 0, "PASSWORD",  "%s", rdr->gbox_pwd);
	else if (strlen(rdr->r_pwd) > 0)
		tpl_printf(vars, 0, "PASSWORD",  "%s", rdr->r_pwd);
	else
		tpl_printf(vars, 0, "PASSWORD",  "%s", "");
#else
	tpl_printf(vars, 0, "PASSWORD",  "%s", rdr->r_pwd);
#endif

	for (i=0; i<14; i++)
		tpl_printf(vars, 1, "NCD_KEY", "%02X", rdr->ncd_key[i]);

	tpl_addVar(vars, 0, "PINCODE", rdr->pincode);
	//tpl_addVar(vars, 0, "EMMFILE", (char *)rdr->emmfile);
	tpl_printf(vars, 0, "INACTIVITYTIMEOUT", "%d", rdr->tcp_ito);
	tpl_printf(vars, 0, "RECEIVETIMEOUT", "%d", rdr->tcp_rto);
	tpl_printf(vars, 0, "DISABLESERVERFILTER", "%d", rdr->ncd_disable_server_filt);

	if(rdr->fallback)
		tpl_addVar(vars, 0, "FALLBACKCHECKED", "checked");

	tpl_printf(vars, 0, "LOGPORT", "%d", rdr->log_port);

	if(rdr->boxid)
		tpl_printf(vars, 0, "BOXID", "%08X", rdr->boxid);

	tpl_addVar(vars, 0, "USER", rdr->r_usr);
	tpl_addVar(vars, 0, "PASS", rdr->r_pwd);

	if(rdr->audisabled)
		tpl_addVar(vars, 0, "AUDISABLED", "checked");

	if(rdr->auprovid)
		tpl_printf(vars, 0, "AUPROVID", "%06lX", rdr->auprovid);

	if(rdr->force_irdeto)
		tpl_addVar(vars, 0, "FORCEIRDETOCHECKED", "checked");

	//aeskey
	int has_aeskey = 0;
	for (i = 0; i < 16 ;i++) {
		if(rdr->aes_key[i]) {
			has_aeskey++;
		}
	}
	if (has_aeskey) {
		for (i = 0; i < 16; i++) tpl_printf(vars, 1, "AESKEY", "%02X", rdr->aes_key[i]);
	}

	//check for tiger
	int tigerkey = 0;
	for (i = 64; i < 120; i++) {
		if(rdr->rsa_mod[i] > 0) {
			tigerkey = 1;
			break;
		}
	}

	if(rdr->has_rsa) {
		if (!tigerkey) {
			for (i = 0; i < 64; i++) tpl_printf(vars, 1, "RSAKEY", "%02X", rdr->rsa_mod[i]);
			for (i = 0; i < 8 ; i++) tpl_printf(vars, 1, "BOXKEY", "%02X", rdr->nagra_boxkey[i]);
		}
	}
	if (tigerkey) {
		for (i = 0; i < 120; i++) tpl_printf(vars, 1, "TIGERRSAKEY", "%02X", rdr->rsa_mod[i]);
		for (i = 0; i < 8 ; i++) tpl_printf(vars, 1, "BOXKEY", "%02X", rdr->nagra_boxkey[i]);
	}

	if ( rdr->atr[0])
		for (i = 0; i < rdr->atrlen/2; i++)
			tpl_printf(vars, 1, "ATR", "%02X", rdr->atr[i]);

	if(rdr->smargopatch)
		tpl_addVar(vars, 0, "SMARGOPATCHCHECKED", "checked");

	if (rdr->detect&0x80)
		tpl_printf(vars, 0, "DETECT", "!%s", RDR_CD_TXT[rdr->detect&0x7f]);
	else
		tpl_printf(vars, 0, "DETECT", "%s", RDR_CD_TXT[rdr->detect&0x7f]);

	tpl_printf(vars, 0, "MHZ", "%d", rdr->mhz);
	tpl_printf(vars, 0, "CARDMHZ", "%d", rdr->cardmhz);

#ifdef CS_WITH_GBOX
	tpl_addVar(vars, 0, "GBOXPWD", (char *)rdr->gbox_pwd);
	tpl_addVar(vars, 0, "PREMIUM", rdr->gbox_prem);
#endif

	tpl_printf(vars, 0, "DEVICE", "%s", rdr->device);
	if(rdr->r_port)
		tpl_printf(vars, 1, "DEVICE", ",%d", rdr->r_port);
	if(rdr->l_port) {
		if(rdr->r_port)
			tpl_printf(vars, 1, "DEVICE", ",%d", rdr->l_port);
		else
			tpl_printf(vars, 1, "DEVICE", ",,%d", rdr->l_port);
	}

	//group
	value = mk_t_group(rdr->grp);
	tpl_printf(vars, 0, "GRP", "%s", value);
	free(value);

	if(rdr->lb_weight)
		tpl_printf(vars, 0, "LBWEIGHT", "%d", rdr->lb_weight);

	//services
	char sidok[MAX_SIDBITS+1];
	sidtabbits2bitchar(rdr->sidtabok, sidok);
	char sidno[MAX_SIDBITS+1];
	sidtabbits2bitchar(rdr->sidtabno,sidno);
	struct s_sidtab *sidtab = cfg->sidtab;
	//build matrix
	i = 0;
	while(sidtab != NULL) {
		tpl_addVar(vars, 0, "SIDLABEL", sidtab->label);
		if(sidok[i]=='1') tpl_addVar(vars, 0, "CHECKED", "checked");
		else tpl_addVar(vars, 0, "CHECKED", "");
		tpl_addVar(vars, 1, "SIDS", tpl_getTpl(vars, "READERCONFIGSIDOKBIT"));
		if(sidno[i]=='1') tpl_addVar(vars, 0, "CHECKED", "checked");
		else tpl_addVar(vars, 0, "CHECKED", "");
		tpl_addVar(vars, 1, "SIDS", tpl_getTpl(vars, "READERCONFIGSIDNOBIT"));
		sidtab=sidtab->next;
		i++;
	}

	// CAID
	value = mk_t_caidtab(&rdr->ctab);
	tpl_addVar(vars, 0, "CAIDS", value);
	free(value);

	// AESkeys
	value = mk_t_aeskeys(rdr);
	tpl_addVar(vars, 0, "AESKEYS", value);
	free(value);

	//ident
	value = mk_t_ftab(&rdr->ftab);
	tpl_printf(vars, 0, "IDENTS", "%s", value);
	free(value);

	//CHID
	value = mk_t_ftab(&rdr->fchid);
	tpl_printf(vars, 0, "CHIDS", "%s", value);
	free(value);

	//class
	CLASSTAB *clstab = &rdr->cltab;
	char *dot="";
	for(i = 0; i < clstab->an; ++i) {
		tpl_printf(vars, 1, "CLASS", "%s%02x", dot, (int)clstab->aclass[i]);
		dot=",";
	}

	for(i = 0; i < clstab->bn; ++i) {
		tpl_printf(vars, 0, "CLASS", "%s!%02x", dot, (int)clstab->bclass[i]);
		dot=",";
	}

	tpl_printf(vars, 0, "SHOWCLS", "%d", rdr->show_cls);
	tpl_printf(vars, 0, "MAXQLEN", "%d", rdr->maxqlen);

	if(rdr->cachemm)
		tpl_printf(vars, 0, "EMMCACHE", "%d,%d,%d", rdr->cachemm, rdr->rewritemm, rdr->logemm);

	//savenano
	int all = 1;
	dot="";
	for(i = 0; i < 256; ++i) {
		if(!(rdr->b_nano[i] & 0x02)) {
			all = 0;
			break;
		}
	}
	if (all == 1) tpl_addVar(vars, 0, "SAVENANO", "all");
	else {
		for(i = 0; i < 256; ++i) {
			if(rdr->b_nano[i] & 0x02) tpl_printf(vars, 1, "SAVENANO", "%s%02x\n", dot, i);
			dot=",";
		}
	}

	//blocknano
	dot="";
	for(i = 0; i < 256; ++i) {
		if(!(rdr->b_nano[i] & 0x01)) {
			all = 0;
			break;
		}
	}
	if (all == 1) tpl_addVar(vars, 0, "BLOCKNANO", "all");
	else {
		for(i = 0; i < 256; ++i) {
			if(rdr->b_nano[i] & 0x01) tpl_printf(vars, 1, "BLOCKNANO", "%s%02x\n", dot, i);
			dot=",";
		}
	}

	if (rdr->blockemm_unknown)
		tpl_addVar(vars, 0, "BLOCKEMMUNKNOWNCHK", "checked");
	if (rdr->blockemm_u)
		tpl_addVar(vars, 0, "BLOCKEMMUNIQCHK", "checked");
	if (rdr->blockemm_s)
		tpl_addVar(vars, 0, "BLOCKEMMSHAREDCHK", "checked");
	if (rdr->blockemm_g)
		tpl_addVar(vars, 0, "BLOCKEMMGLOBALCHK", "checked");

	if (rdr->deprecated)
		tpl_addVar(vars, 0, "DEPRECATEDCHCHECKED", "checked");

	if (!strcmp(rdr->cc_version, "2.0.11")) {
		tpl_addVar(vars, 0, "CCCVERSIONSELECTED0", "selected");
	} else if (!strcmp(rdr->cc_version, "2.1.1")) {
		tpl_addVar(vars, 0, "CCCVERSIONSELECTED1", "selected");
	} else if (!strcmp(rdr->cc_version, "2.1.2")) {
		tpl_addVar(vars, 0, "CCCVERSIONSELECTED2", "selected");
	} else if (!strcmp(rdr->cc_version, "2.1.3")) {
		tpl_addVar(vars, 0, "CCCVERSIONSELECTED3", "selected");
	} else if (!strcmp(rdr->cc_version, "2.1.4")) {
		tpl_addVar(vars, 0, "CCCVERSIONSELECTED4", "selected");
	} else if (!strcmp(rdr->cc_version, "2.2.0")) {
		tpl_addVar(vars, 0, "CCCVERSIONSELECTED5", "selected");
	} else if (!strcmp(rdr->cc_version, "2.2.1")) {
		tpl_addVar(vars, 0, "CCCVERSIONSELECTED6", "selected");
	}

#ifdef LIBUSB
	tpl_addVar(vars, 0, "DEVICEEP", tpl_getTpl(vars, "READERCONFIGDEVICEEPBIT"));

	if(!rdr->device_endpoint) {
		tpl_addVar(vars, 0, "DEVICEOUTEP0", "selected");
	} else if (rdr->device_endpoint == 0x82) {
		tpl_addVar(vars, 0, "DEVICEOUTEP1", "selected");
	} else if (rdr->device_endpoint == 0x81) {
		tpl_addVar(vars, 0, "DEVICEOUTEP2", "selected");
	}
#else
	tpl_addVar(vars, 0, "DEVICEEP", "not avail LIBUSB");
#endif

	tpl_printf(vars, 0, "TMP", "NDSVERSION%d", rdr->ndsversion);
	tpl_addVar(vars, 0, tpl_getVar(vars, "TMP"), "selected");

	tpl_printf(vars, 0, "TMP", "NAGRAREAD%d", rdr->nagra_read);
	tpl_addVar(vars, 0, tpl_getVar(vars, "TMP"), "selected");

	tpl_printf(vars, 0, "CCCMAXHOP", "%d", rdr->cc_maxhop);
	if(rdr->cc_want_emu)
		tpl_addVar(vars, 0, "CCCWANTEMUCHECKED", "checked");

	if(rdr->cc_keepalive)
		tpl_addVar(vars, 0, "KEEPALIVECHECKED", "selected");

	if(rdr->cc_reshare)
		tpl_printf(vars, 0, "RESHARE", "%d", rdr->cc_reshare);

	// Show only parameters which needed for the reader
	switch (rdr->typ) {
		case R_CONSTCW:
			tpl_addVar(vars, 0, "PROTOCOL", "constcw");
			tpl_addVar(vars, 1, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGSTDHWREADERBIT"));
			break;
		case R_DB2COM1:
		case R_DB2COM2:
		case R_MOUSE :
			tpl_addVar(vars, 0, "PROTOCOL", "mouse");
			tpl_addVar(vars, 1, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGSTDHWREADERBIT"));
			break;
		case R_MP35:
			tpl_addVar(vars, 0, "PROTOCOL", "mp35");
			tpl_addVar(vars, 1, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGSTDHWREADERBIT"));
			break;
		case R_SC8in1 :
			tpl_addVar(vars, 0, "PROTOCOL", "sc8in1");
			tpl_addVar(vars, 1, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGSTDHWREADERBIT"));
			break;
		case R_SMART :
			tpl_addVar(vars, 0, "PROTOCOL", "smartreader");
			tpl_addVar(vars, 1, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGSTDHWREADERBIT"));
			break;
		case R_INTERNAL:
			tpl_addVar(vars, 0, "PROTOCOL", "internal");
			tpl_addVar(vars, 1, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGSTDHWREADERBIT"));
			break;
		case R_SERIAL :
			tpl_addVar(vars, 0, "PROTOCOL", "serial");
			tpl_addVar(vars, 1, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGSTDHWREADERBIT"));
			break;
		case R_CAMD35 :
			tpl_addVar(vars, 0, "PROTOCOL", "camd35");
			tpl_addVar(vars, 1, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGCAMD35BIT"));
			break;
		case R_CS378X :
			tpl_addVar(vars, 0, "PROTOCOL", "cs378x");
			tpl_addVar(vars, 1, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGCS378XBIT"));
			break;
		case R_RADEGAST:
			tpl_addVar(vars, 0, "PROTOCOL", "radegast");
			tpl_addVar(vars, 1, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGRADEGASTBIT"));
			break;
		case R_NEWCAMD :
			if ( rdr->ncd_proto == NCD_525 ){
				tpl_addVar(vars, 0, "PROTOCOL", "newcamd525");
				tpl_addVar(vars, 1, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGNCD525BIT"));
			} else if ( rdr->ncd_proto == NCD_524 ) {
				tpl_addVar(vars, 0, "PROTOCOL", "newcamd524");
				tpl_addVar(vars, 1, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGNCD524BIT"));
			}
			break;
		case R_CCCAM :
			tpl_addVar(vars, 0, "PROTOCOL", "cccam");
			tpl_addVar(vars, 1, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGCCCAMBIT"));
			break;
#ifdef CS_WITH_GBOX
		case R_GBOX :
			tpl_addVar(vars, 0, "PROTOCOL", "gbox");
			tpl_addVar(vars, 1, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGGBOXBIT"));
			break;
#endif
#ifdef HAVE_PCSC
		case R_PCSC :
			tpl_addVar(vars, 0, "PROTOCOL", "pcsc");
			tpl_addVar(vars, 1, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGSTDHWREADERBIT"));
			break;
#endif
		default :
			tpl_addVar(vars, 1, "MESSAGE", "<b>Error: protocol not resolvable</b><BR>");
			tpl_printf(vars, 1, "MESSAGE", "<b>Error: protocol number: %d readername: %s readeridx: %d</b><BR>", rdr->typ, rdr->label, ridx);
			break;

	}
	//READERCONFIGMOUSEBIT
	webif_write(tpl_getTpl(vars, "READERCONFIG"), f);
}

void send_oscam_reader_stats(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in, int apicall) {

	tpl_printf(vars, 0, "CALLINGIP", "%s", inet_ntoa(*(struct in_addr *)&in));

	struct s_reader *rdr = get_reader_by_label(getParam(params, "label"));

	if (!apicall)
		tpl_printf(vars, 0, "LABEL", "%s", rdr->label);
	else
		tpl_printf(vars, 0, "READERNAME", "%s", rdr->label);

	char *stxt[]={"found", "cache1", "cache2", "emu",
			"not found", "timeout", "sleeping",
			"fake", "invalid", "corrupt", "no card", "expdate",
			"disabled", "stopped"};

	if (apicall) {
		int i, emmcount = 0;
		char *ttxt[]={"unknown", "unique", "shared", "global"};

		for (i=0; i<4; i++) {
			tpl_addVar(vars, 0, "EMMRESULT", "error");
			tpl_printf(vars, 0, "EMMTYPE", "%s", ttxt[i]);
			tpl_printf(vars, 0, "EMMCOUNT", "%d", rdr->emmerror[i]);
			tpl_addVar(vars, 1, "EMMSTATS", tpl_getTpl(vars, "APIREADERSTATSEMMBIT"));
			emmcount += rdr->emmerror[i];
			tpl_printf(vars, 0, "TOTALERROR", "%d", emmcount);
		}
		emmcount = 0;
		for (i=0; i<4; i++) {
			tpl_addVar(vars, 0, "EMMRESULT", "written");
			tpl_printf(vars, 0, "EMMTYPE", "%s", ttxt[i]);
			tpl_printf(vars, 0, "EMMCOUNT", "%d", rdr->emmwritten[i]);
			tpl_addVar(vars, 1, "EMMSTATS", tpl_getTpl(vars, "APIREADERSTATSEMMBIT"));
			emmcount += rdr->emmwritten[i];
			tpl_printf(vars, 0, "TOTALWRITTEN", "%d", emmcount);
		}
		emmcount = 0;
		for (i=0; i<4; i++) {
			tpl_addVar(vars, 0, "EMMRESULT", "skipped");
			tpl_printf(vars, 0, "EMMTYPE", "%s", ttxt[i]);
			tpl_printf(vars, 0, "EMMCOUNT", "%d", rdr->emmskipped[i]);
			tpl_addVar(vars, 1, "EMMSTATS", tpl_getTpl(vars, "APIREADERSTATSEMMBIT"));
			emmcount += rdr->emmskipped[i];
			tpl_printf(vars, 0, "TOTALSKIPPED", "%d", emmcount);
		}
		emmcount = 0;
		for (i=0; i<4; i++) {
			tpl_addVar(vars, 0, "EMMRESULT", "blocked");
			tpl_printf(vars, 0, "EMMTYPE", "%s", ttxt[i]);
			tpl_printf(vars, 0, "EMMCOUNT", "%d", rdr->emmblocked[i]);
			tpl_addVar(vars, 1, "EMMSTATS", tpl_getTpl(vars, "APIREADERSTATSEMMBIT"));
			emmcount += rdr->emmblocked[i];
			tpl_printf(vars, 0, "TOTALBLOCKED", "%d", emmcount);
		}
	}

	int rc2hide = (-1);
	if (strlen(getParam(params, "hide")) > 0)
			rc2hide = atoi(getParam(params, "hide"));

	int rowcount = 0, ecmcount = 0, lastaccess = 0;
	if (rdr->lb_stat) {

		LL_ITER *it = ll_iter_create(rdr->lb_stat);
		READER_STAT *stat = ll_iter_next(it);
		while (stat) {

			if (!(stat->rc == rc2hide)) {
				struct tm *lt = localtime(&stat->last_received);
				if (!apicall) {
					tpl_printf(vars, 0, "CHANNEL", "%04X:%06lX:%04X", stat->caid, stat->prid, stat->srvid);
					tpl_printf(vars, 0, "CHANNELNAME","%s", xml_encode(vars, get_servicename(stat->srvid, stat->caid)));
					tpl_printf(vars, 0, "RC", "%s", stxt[stat->rc]);
					tpl_printf(vars, 0, "TIME", "%dms", stat->time_avg);
					if (stat->time_stat[stat->time_idx])
						tpl_printf(vars, 0, "TIMELAST", "%dms", stat->time_stat[stat->time_idx]);
					else
						tpl_printf(vars, 0, "TIMELAST", "");
					tpl_printf(vars, 0, "COUNT", "%d", stat->ecm_count);
					if(stat->last_received) {
						tpl_printf(vars, 0, "LAST", "%02d.%02d.%02d %02d:%02d:%02d", lt->tm_mday, lt->tm_mon+1, lt->tm_year%100, lt->tm_hour, lt->tm_min, lt->tm_sec);

					} else {
						tpl_addVar(vars, 0, "LAST","never");
					}
				} else {
					tpl_printf(vars, 0, "ECMCAID", "%04X", stat->caid);
					tpl_printf(vars, 0, "ECMPROVID", "%06lX", stat->prid);
					tpl_printf(vars, 0, "ECMSRVID", "%04X", stat->srvid);
					tpl_addVar(vars, 0, "ECMCHANNELNAME", xml_encode(vars, get_servicename(stat->srvid, stat->caid)));
					tpl_printf(vars, 0, "ECMTIME", "%d", stat->time_avg);
					tpl_printf(vars, 0, "ECMTIMELAST", "%d", stat->time_stat[stat->time_idx]);
					tpl_printf(vars, 0, "ECMRC", "%d", stat->rc);
					tpl_printf(vars, 0, "ECMRCS", "%s", stxt[stat->rc]);
					if(stat->last_received) {
					char tbuffer [30];
					strftime(tbuffer, 30, "%Y-%m-%dT%H:%M:%S%z", lt);
					tpl_addVar(vars, 0, "ECMLAST", tbuffer);
					} else {
						tpl_addVar(vars, 0, "ECMLAST", "");
					}
					tpl_printf(vars, 0, "ECMCOUNT", "%d", stat->ecm_count);
					ecmcount += stat->ecm_count;
					if (stat->last_received > lastaccess)
						lastaccess = stat->last_received;
				}

				if (!apicall) {
					if (stat->rc == 4) {
						tpl_addVar(vars, 1, "READERSTATSROWNOTFOUND", tpl_getTpl(vars, "READERSTATSBIT"));
						tpl_addVar(vars, 0, "READERSTATSNFHEADLINE", "<TR><TD CLASS=\"subheadline\" colspan=\"6\">Not found</TD></TR>\n");
					}
					else
						tpl_addVar(vars, 1, "READERSTATSROWFOUND", tpl_getTpl(vars, "READERSTATSBIT"));
				} else {

					tpl_addVar(vars, 1, "ECMSTATS", tpl_getTpl(vars, "APIREADERSTATSECMBIT"));
				}
			}

		stat = ll_iter_next(it);
		rowcount++;
		}

		ll_iter_release(it);

	} else {
		tpl_addVar(vars, 1, "READERSTATSROW","<TR><TD colspan=\"6\"> No statistics found </TD></TR>");
	}

	tpl_printf(vars, 0, "ROWCOUNT", "%d", rowcount);
	tpl_printf(vars, 0, "LASTACCESS", "%u", lastaccess);
	tpl_printf(vars, 0, "TOTALECM", "%d", ecmcount);

	if(!apicall)
		webif_write(tpl_getTpl(vars, "READERSTATS"), f);
	else
		webif_write(tpl_getTpl(vars, "APIREADERSTATS"), f);
}

void send_oscam_user_config_edit(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in) {
	struct s_auth *account, *ptr;
	char user[128];

	if (strcmp(getParam(params, "action"), "Save As") == 0) cs_strncpy(user, getParam(params, "newuser"), sizeof(user)/sizeof(char));
	else cs_strncpy(user, getParam(params, "user"), sizeof(user)/sizeof(char));

	int i;

	for (account = cfg->account; account != NULL && strcmp(user, account->usr) != 0; account = account->next);

	// Create a new user if it doesn't yet
	if (account == NULL) {
		i = 1;
		while(strlen(user) < 1) {
			snprintf(user, sizeof(user)/sizeof(char) - 1, "NEWUSER%d", i);
			for (account = cfg->account; account != NULL && strcmp(user, account->usr) != 0; account = account->next);
			if(account != NULL) user[0] = '\0';
			++i;
		}
		if (!(account=malloc(sizeof(struct s_auth)))) {
			cs_log("Error allocating memory (errno=%d)", errno);
			return;
		}
		if(cfg->account == NULL) cfg->account = account;
		else {
			for (ptr = cfg->account; ptr != NULL && ptr->next != NULL; ptr = ptr->next);
			ptr->next = account;
		}
		memset(account, 0, sizeof(struct s_auth));
		cs_strncpy((char *)account->usr, user, sizeof(account->usr));
		account->aureader=NULL;
		account->monlvl=cfg->mon_level;
		account->tosleep=cfg->tosleep;
		for (i=1; i<CS_MAXCAIDTAB; account->ctab.mask[i++]=0xffff);
		for (i=1; i<CS_MAXTUNTAB; account->ttab.bt_srvid[i++]=0x0000);
		account->expirationdate=(time_t)NULL;
#ifdef CS_ANTICASC
		account->ac_users=cfg->ac_users;
		account->ac_penalty=cfg->ac_penalty;
		account->ac_idx = account->ac_idx + 1;
#endif
		tpl_addVar(vars, 1, "MESSAGE", "<b>New user has been added with default settings</b><BR>");

		if (write_userdb(cfg->account)==0)
			refresh_oscam(REFR_ACCOUNTS, in);
		else
			tpl_addVar(vars, 1, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
		// need to reget account as writing to disk changes account!
		for (account = cfg->account; account != NULL && strcmp(user, account->usr) != 0; account = account->next);
	}

	if((strcmp(getParam(params, "action"), "Save") == 0) || (strcmp(getParam(params, "action"), "Save As") == 0)) {
		char servicelabels[255]="";
		//clear group
		account->grp = 0;
		//clear caidtab before it re-readed by chk_t
		clear_caidtab(&account->ctab);
		//clear Betatunnel before it re-readed by chk_t
		clear_tuntab(&account->ttab);
		//clear ident before it re-readed by chk_t
		clear_ftab(&account->ftab);
		//clear CHID before it re-readed by chk_t
		clear_ftab(&account->fchid);

		for(i=0;i<(*params).paramcount;i++) {
			if ((strcmp((*params).params[i], "action")) && (strcmp((*params).params[i], "user")) && (strcmp((*params).params[i], "newuser"))) {
				if (!strcmp((*params).params[i], "expdate"))
					account->expirationdate=(time_t)NULL;
				if (!strcmp((*params).params[i], "services"))
					snprintf(servicelabels + strlen(servicelabels), sizeof(servicelabels), "%s,", (*params).values[i]);
				else
					chk_account((*params).params[i], (*params).values[i], account);
			}
		}
		chk_account("services", servicelabels, account);
		tpl_addVar(vars, 1, "MESSAGE", "<B>Settings updated</B><BR><BR>");

		if (write_userdb(cfg->account)==0)
			refresh_oscam(REFR_ACCOUNTS, in);
		else
			tpl_addVar(vars, 1, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}
	for (account = cfg->account; account != NULL && strcmp(user, account->usr) != 0; account = account->next);

	tpl_addVar(vars, 0, "USERNAME", account->usr);
	tpl_addVar(vars, 0, "PASSWORD", account->pwd);
	tpl_addVar(vars, 0, "DESCRIPTION", account->description);

	//Disabled
	if(account->disabled)
		tpl_addVar(vars, 0, "DISABLEDCHECKED", "selected");

	//Expirationdate
	struct tm * timeinfo = localtime (&account->expirationdate);
	char buf [80];
	strftime (buf,80,"%Y-%m-%d",timeinfo);
	if(strcmp(buf,"1970-01-01")) tpl_addVar(vars, 0, "EXPDATE", buf);

	if(account->allowedtimeframe[0] && account->allowedtimeframe[1]) {
		tpl_printf(vars, 0, "ALLOWEDTIMEFRAME", "%02d:%02d-%02d:%02d",
				account->allowedtimeframe[0]/60,
				account->allowedtimeframe[0]%60,
				account->allowedtimeframe[1]/60,
				account->allowedtimeframe[1]%60 );
	}

	//Group
	char *value = mk_t_group(account->grp);
	tpl_addVar(vars, 0, "GROUPS", value);
	free(value);

	//Hostname
	tpl_addVar(vars, 0, "DYNDNS", (char *)account->dyndns);

	//Uniq
	tpl_printf(vars, 0, "TMP", "UNIQSELECTED%d", account->uniq);
	tpl_addVar(vars, 0, tpl_getVar(vars, "TMP"), "selected");

	//Sleep
	if(!account->tosleep) tpl_addVar(vars, 0, "SLEEP", "0");
	else tpl_printf(vars, 0, "SLEEP", "%d", account->tosleep);
	//Monlevel selector
	tpl_printf(vars, 0, "TMP", "MONSELECTED%d", account->monlvl);
	tpl_addVar(vars, 0, tpl_getVar(vars, "TMP"), "selected");

	//AU Selector
	if (!account->aureader) tpl_addVar(vars, 0, "AUSELECTED", "selected");
	if (account->autoau == 1) tpl_addVar(vars, 0, "AUTOAUSELECTED", "selected");
	struct s_reader *rdr;
	for (rdr=first_reader; rdr ; rdr=rdr->next) {
		if(!rdr->device[0]) break;
		tpl_addVar(vars, 0, "READERNAME", rdr->label);
		if (account->aureader == rdr) tpl_addVar(vars, 0, "SELECTED", "selected");
		else tpl_addVar(vars, 0, "SELECTED", "");
		tpl_addVar(vars, 1, "RDROPTION", tpl_getTpl(vars, "USEREDITRDRSELECTED"));
	}

	/* SERVICES */
	//services - first we have to move the long sidtabok/sidtabno to a binary array
	char sidok[MAX_SIDBITS+1];
	sidtabbits2bitchar(account->sidtabok,sidok);
	char sidno[MAX_SIDBITS+1];
	sidtabbits2bitchar(account->sidtabno,sidno);
	struct s_sidtab *sidtab = cfg->sidtab;
	//build matrix
	i=0;
	while(sidtab != NULL) {
		tpl_addVar(vars, 0, "SIDLABEL", sidtab->label);
		if(sidok[i]=='1') tpl_addVar(vars, 0, "CHECKED", "checked");
		else tpl_addVar(vars, 0, "CHECKED", "");
		tpl_addVar(vars, 1, "SIDS", tpl_getTpl(vars, "USEREDITSIDOKBIT"));
		if(sidno[i]=='1') tpl_addVar(vars, 0, "CHECKED", "checked");
		else tpl_addVar(vars, 0, "CHECKED", "");
		tpl_addVar(vars, 1, "SIDS", tpl_getTpl(vars, "USEREDITSIDNOBIT"));
		sidtab=sidtab->next;
		i++;
	}

	// CAID
	value = mk_t_caidtab(&account->ctab);
	tpl_addVar(vars, 0, "CAIDS", value);
	free(value);

	//ident
	value = mk_t_ftab(&account->ftab);
	tpl_printf(vars, 0, "IDENTS", "%s", value);
	free(value);

	//CHID
	value = mk_t_ftab(&account->fchid);
	tpl_printf(vars, 0, "CHIDS", "%s", value);
	free(value);

	//Betatunnel
	value = mk_t_tuntab(&account->ttab);
	tpl_addVar(vars, 0, "BETATUNNELS", value);
	free(value);

	//SUPPRESSCMD08
	if (account->c35_suppresscmd08)
		tpl_addVar(vars, 0, "SUPPRESSCMD08", "selected");

	//Sleepsend
	tpl_printf(vars, 0, "SLEEPSEND", "%d", account->c35_sleepsend);

	//Keepalive
	if (account->ncd_keepalive)
		tpl_addVar(vars, 0, "KEEPALIVE", "selected");

#ifdef CS_ANTICASC
	tpl_printf(vars, 0, "AC_USERS", "%d", account->ac_users);
	tpl_printf(vars, 0, "AC_PENALTY", "%d", account->ac_penalty);
#endif

	tpl_printf(vars, 0, "CCCMAXHOPS", "%d", account->cccmaxhops);
	tpl_printf(vars, 0, "CCCRESHARE", "%d", account->cccreshare);

	//Failban
	tpl_printf(vars, 0, "FAILBAN", "%d", account->failban);

	webif_write(tpl_getTpl(vars, "USEREDIT"), f);
}

void send_oscam_user_config(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in) {
	struct s_auth *account, *account2;
	char *user = getParam(params, "user");
	int found = 0;
	int hideclient = 10;

	if (cfg->mon_hideclient_to > 10)
	hideclient = cfg->mon_hideclient_to;

	if (strcmp(getParam(params, "action"), "reinit") == 0) {
		if(!cfg->http_readonly)
			refresh_oscam(REFR_ACCOUNTS, in);
	}

	if (strcmp(getParam(params, "action"), "delete") == 0) {
		if(cfg->http_readonly) {
			tpl_addVar(vars, 1, "MESSAGE", "<b>Webif is in readonly mode. No deletion will be made!</b><BR>");
		} else {
			account = cfg->account;
			if(strcmp(account->usr, user) == 0) {
				cfg->account = account->next;
				free(account);
				found = 1;
			} else if (account->next != NULL) {
				do {
					if(strcmp(account->next->usr, user) == 0) {
						account2 = account->next;
						account->next = account2->next;
						free(account2);
						found = 1;
						break;
					}
				}while ((account = account->next) && (account->next != NULL));
			}

			if (found > 0) {
				tpl_addVar(vars, 1, "MESSAGE", "<b>Account has been deleted!</b><BR>");

				if (write_userdb(cfg->account)==0)
					refresh_oscam(REFR_ACCOUNTS, in);
				else
					tpl_addVar(vars, 1, "MESSAGE", "<B>Write Config failed</B><BR><BR>");

			} else tpl_addVar(vars, 1, "MESSAGE", "<b>Sorry but the specified user doesn't exist. No deletion will be made!</b><BR>");
		}
	}



	if ((strcmp(getParam(params, "action"), "disable") == 0) || (strcmp(getParam(params, "action"), "enable") == 0)) {
		for (account=cfg->account; (account); account=account->next) {
			if(strcmp(getParam(params, "user"), account->usr) == 0) {
				if(strcmp(getParam(params, "action"), "disable") == 0)
				account->disabled = 1;
				else
				account->disabled = 0;
				found = 1;
			}
		}

		if (found > 0) {
			tpl_addVar(vars, 1, "MESSAGE", "<b>Account has been switched!</b><BR>");
			if (write_userdb(cfg->account)==0)
				refresh_oscam(REFR_ACCOUNTS, in);
		} else tpl_addVar(vars, 1, "MESSAGE", "<b>Sorry but the specified user doesn't exist. No deletion will be made!</b><BR>");
	}


	if (strcmp(getParam(params, "action"), "resetstats") == 0) {
		for (account=cfg->account; (account); account=account->next) {
			if(strcmp(getParam(params, "user"), account->usr) == 0) {
				clear_account_stats(account);
			}
		}
	}


	if (strcmp(getParam(params, "action"), "resetserverstats") == 0) {
		clear_system_stats();
	}

	if (strcmp(getParam(params, "action"), "resetalluserstats") == 0) {
		clear_all_account_stats();
	}

	/* List accounts*/
	char *status = "offline";
	char *expired = "";
	char *classname="offline";
	char *lastchan="&nbsp;";
	time_t now = time((time_t)0);
	int isec = 0, isonline = 0;

	//for (account=cfg->account; (account); account=account->next) {
	for (account=cfg->account; (account); account=account->next) {
		//clear for next client
		expired = ""; classname = "offline"; status = "offline";
		isonline = 0;
		tpl_addVar(vars, 0, "CWOK", "");
		tpl_addVar(vars, 0, "CWNOK", "");
		tpl_addVar(vars, 0, "CWIGN", "");
		tpl_addVar(vars, 0, "CWTOUT", "");
		tpl_addVar(vars, 0, "CWCACHE", "");
		tpl_addVar(vars, 0, "CWTUN", "");
		tpl_addVar(vars, 0, "CLIENTPROTO","");
		tpl_addVar(vars, 0, "IDLESECS","");
		tpl_addVar(vars, 0, "CWLASTRESPONSET","");
		tpl_addVar(vars, 0, "EMMOK","");
		tpl_addVar(vars, 0, "EMMNOK","");
		tpl_addVar(vars, 0, "CLIENTPROTO","");
		tpl_addVar(vars, 0, "LASTCHANNEL", "");

		if(account->expirationdate && account->expirationdate<time(NULL)) {
			expired = " (expired)";
			classname = "expired";
		}
		if(account->disabled != 0) {
			expired = " (disabled)";
			classname = "disabled";
			if (!cfg->http_js_icons)
				tpl_addVar(vars, 0, "SWITCHICO", ICENA);
			else
				tpl_addVar(vars, 0, "SWITCHICOID", "ICENA");
			tpl_addVar(vars, 0, "SWITCHTITLE", "enable this account");
			tpl_addVar(vars, 0, "SWITCH", "enable");
		} else {
			if (!cfg->http_js_icons)
				tpl_addVar(vars, 0, "SWITCHICO", ICDIS);
			else
				tpl_addVar(vars, 0, "SWITCHICOID", "ICDIS");
			tpl_addVar(vars, 0, "SWITCHTITLE", "disable this account");
			tpl_addVar(vars, 0, "SWITCH", "disable");
		}

		//search account in active clients
		int secs = 0, fullmins =0, mins =0, hours =0, lastresponsetm = 0;
		char *proto = "";

		struct s_client *cl;
		for (cl=first_client; cl ; cl=cl->next) {
		 if (cl->account && !strcmp(cl->account->usr, account->usr)) {
			//set client to offline depending on hideclient_to
			if ((now - cl->lastecm) < hideclient) {
				status = "<b>online</b>"; classname="online";
				isonline = 1;
				proto = monitor_get_proto(cl);
				lastchan = xml_encode(vars, get_servicename(cl->last_srvid, cl->last_caid));
				lastresponsetm = cl->cwlastresptime;
				isec = now - cl->last;
				if(isec > 0) {
					secs = isec % 60;
					if (isec > 60) {
						fullmins = isec / 60;
						mins = fullmins % 60;
						if(fullmins > 60) hours = fullmins / 60;
					}
				}
			}
		 }
		}
		tpl_printf(vars, 0, "CWOK", "%d", account->cwfound);
		tpl_printf(vars, 0, "CWNOK", "%d", account->cwnot);
		tpl_printf(vars, 0, "CWIGN", "%d", account->cwignored);
		tpl_printf(vars, 0, "CWTOUT", "%d", account->cwtout);
		tpl_printf(vars, 0, "CWCACHE", "%d", account->cwcache);
		tpl_printf(vars, 0, "CWTUN", "%d", account->cwtun);
		tpl_printf(vars, 0, "EMMOK", "%d", account->emmok);
		tpl_printf(vars, 0, "EMMNOK", "%d", account->emmnok);

		if ( isonline > 0 || ((isonline == 0) && (!cfg->http_hide_idle_clients))) {
			tpl_addVar(vars, 0, "LASTCHANNEL", lastchan);
			tpl_printf(vars, 0, "CWLASTRESPONSET", "%d", lastresponsetm);
			tpl_addVar(vars, 0, "CLIENTPROTO", proto);
			tpl_printf(vars, 0, "IDLESECS", "%02d:%02d:%02d", hours, mins, secs);

		}

		tpl_addVar(vars, 0, "CLASSNAME", classname);
		tpl_addVar(vars, 0, "USER", xml_encode(vars, account->usr));
		tpl_addVar(vars, 0, "USERENC", tpl_addTmp(vars, urlencode(account->usr)));
		tpl_addVar(vars, 0, "DESCRIPTION", xml_encode(vars, account->description));
		tpl_addVar(vars, 0, "STATUS", status);
		tpl_addVar(vars, 0, "EXPIRED", expired);

		if (!cfg->http_js_icons) {
			tpl_addVar(vars, 0, "DELICO", ICDEL);
			tpl_addVar(vars, 0, "EDIICO", ICEDI);
			tpl_addVar(vars, 0, "RESICO", ICRES);
		}

		tpl_addVar(vars, 1, "USERCONFIGS", tpl_getTpl(vars, "USERCONFIGLISTBIT"));
		isec = 0;
		lastchan = "&nbsp;";
	}

	if ((strcmp(getParam(params, "part"), "adduser") == 0) && (!cfg->http_readonly)) {
		tpl_addVar(vars, 1, "NEWUSERFORM", tpl_getTpl(vars, "ADDNEWUSER"));
	} else {
		if(cfg->http_refresh > 0) {
			tpl_printf(vars, 0, "REFRESHTIME", "%d", cfg->http_refresh);
			tpl_addVar(vars, 0, "REFRESHURL", "userconfig.html");
			tpl_addVar(vars, 0, "REFRESH", tpl_getTpl(vars, "REFRESH"));
		}
	}
	tpl_printf(vars, 1, "TOTAL_CWOK", "%ld", first_client->cwfound);
	tpl_printf(vars, 1, "TOTAL_CWNOK", "%ld", first_client->cwnot);
	tpl_printf(vars, 1, "TOTAL_CWIGN", "%ld", first_client->cwignored);
	tpl_printf(vars, 1, "TOTAL_CWTOUT", "%ld", first_client->cwtout);
	tpl_printf(vars, 1, "TOTAL_CWCACHE", "%ld", first_client->cwcache);
	tpl_printf(vars, 1, "TOTAL_CWTUN", "%ld", first_client->cwtun);
	
	webif_write(tpl_getTpl(vars, "USERCONFIGLIST"), f);
}

char *strend(char *ch) {
	while (*ch) ch++;
	return ch;
}

void send_oscam_entitlement(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in, int apicall) {

	//just to stop the guys open tedious tickets for warnings related to unused variables xD
	tpl_printf(vars, 0, "CALLINGIP", "%s", inet_ntoa(*(struct in_addr *)&in));
	tpl_printf(vars, 0, "ISAPICALL", "%d", apicall);
	//**************

	/* build entitlements from reader init history */
	char *reader_ = getParam(params, "label");

	if (cfg->saveinithistory && strlen(reader_) > 0) {
		struct s_reader *rdr = get_reader_by_label(getParam(params, "label"));

		if (rdr->typ == R_CCCAM && rdr->enable == 1) {

			tpl_addVar(vars, 0, "READERNAME", rdr->label);

			int caidcount = 0;
			int providercount = 0;
			int nodecount = 0;

			char *provider = "";

			struct cc_card *card;
			struct s_client *rc = rdr->client;
			struct cc_data *rcc = (rc)?rc->cc:NULL;

			if (rcc && rcc->cards) {
				pthread_mutex_lock(&rcc->cards_busy);
				char *buf = malloc(4000);
				uint8 serbuf[8];

				LL_ITER *it = ll_iter_create(rcc->cards);
				while ((card = ll_iter_next(it))) {

					if (!apicall) {
						tpl_printf(vars, 0, "HOST", "%s:%d", rdr->device, rdr->r_port);
						tpl_printf(vars, 0, "CAID", "%04X", card->caid);
					} else {
						tpl_addVar(vars, 0, "APIHOST", rdr->device);
						tpl_printf(vars, 0, "APIHOSTPORT", "%d", rdr->r_port);
						tpl_printf(vars, 0, "APICARDNUMBER", "%d", caidcount);
						tpl_printf(vars, 0, "APICAID", "%04X", card->caid);
					}

					if (cc_UA_valid(card->hexserial)) { //Add UA:
						cc_UA_cccam2oscam(card->hexserial, serbuf, card->caid);
						tpl_printf(vars, 1, "HOST", "<BR>\nUA_Oscam:%s", cs_hexdump(0, serbuf, 8));
						tpl_printf(vars, 1, "HOST", "<BR>\nUA_CCcam:%s", cs_hexdump(0, card->hexserial, 8));
					}


					int cs = get_cardsystem(card->caid);
					
					if (cs)
						tpl_addVar(vars, 0, "SYSTEM", cardsystem[cs-1].desc);
					else
						tpl_addVar(vars, 0, "SYSTEM", "???");

                    tpl_printf(vars, 0, "SHAREID", "%08X", card->id);
                    tpl_printf(vars, 0, "REMOTEID", "%08X", card->remote_id);
					tpl_printf(vars, 0, "UPHOPS", "%d", card->hop);
					tpl_printf(vars, 0, "MAXDOWN", "%d", card->maxdown);

					LL_ITER *pit = ll_iter_create(card->providers);
					char *p = buf;
					*p = 0;
					struct cc_provider *prov;

					providercount = 0;

					if (!apicall)
						tpl_addVar(vars, 0, "PROVIDERS", "");
					else
						tpl_addVar(vars, 0, "PROVIDERLIST", "");

					while ((prov = ll_iter_next(pit))) {
						provider = xml_encode(vars, get_provider(card->caid, prov->prov));

						if (!apicall) {
							sprintf(p, "%s", provider);
							p = strend(p);
							//add SA:
							if (prov->sa[0] || prov->sa[1] || prov->sa[2] || prov->sa[3]) {
								sprintf(p, " SA:%02X%02X%02X%02X", prov->sa[0], prov->sa[1], prov->sa[2], prov->sa[3]);
								p = strend(p);
							}
							sprintf(p, "<BR>\n");
							p = strend(p);

						} else {
							if (prov->sa[0] || prov->sa[1] || prov->sa[2] || prov->sa[3])
								tpl_printf(vars, 0, "APIPROVIDERSA", "%02X%02X%02X%02X", prov->sa[0], prov->sa[1], prov->sa[2], prov->sa[3]);
							else
								tpl_addVar(vars, 0, "APIPROVIDERSA","");
							tpl_printf(vars, 0, "APIPROVIDERCAID", "%04X", card->caid);
							tpl_printf(vars, 0, "APIPROVIDERPROVID", "%06X", prov->prov);
							tpl_printf(vars, 0, "APIPROVIDERNUMBER", "%d", providercount);
							tpl_addVar(vars, 0, "APIPROVIDERNAME", xml_encode(vars, provider));
							tpl_addVar(vars, 1, "PROVIDERLIST", tpl_getTpl(vars, "APICCCAMCARDPROVIDERBIT"));
						}
						providercount++;
						tpl_printf(vars, 0, "APITOTALPROVIDERS", "%d", providercount);
					}

					if (!apicall) tpl_addVar(vars, 1, "PROVIDERS", provider);

					ll_iter_release(pit);
					LL_ITER *nit = ll_iter_create(card->remote_nodes);
					p = buf;
					*p = 0;
					uint8 *node;

					nodecount = 0;
					tpl_addVar(vars, 0, "NODELIST", "");

					while ((node = ll_iter_next(nit))) {

						if (!apicall) {
							sprintf(p, "%02X%02X%02X%02X%02X%02X%02X%02X<BR>\n",
									node[0], node[1], node[2], node[3], node[4], node[5], node[6], node[7]);
							p = strend(p);

						} else {
							tpl_printf(vars, 0, "APINODE", "%02X%02X%02X%02X%02X%02X%02X%02X", node[0], node[1], node[2], node[3], node[4], node[5], node[6], node[7]);
							tpl_printf(vars, 0, "APINODENUMBER", "%d", nodecount);
							tpl_addVar(vars, 1, "NODELIST", tpl_getTpl(vars, "APICCCAMCARDNODEBIT"));
						}
						nodecount++;
						tpl_printf(vars, 0, "APITOTALNODES", "%d", nodecount);
					}

					if (!apicall) tpl_addVar(vars, 0, "NODES", buf);

					ll_iter_release(nit);

					if (!apicall)
						tpl_addVar(vars, 1, "CCCAMSTATSENTRY", tpl_getTpl(vars, "ENTITLEMENTCCCAMENTRYBIT"));
					else
						tpl_addVar(vars, 1, "CARDLIST", tpl_getTpl(vars, "APICCCAMCARDBIT"));

					caidcount++;
				}

				ll_iter_release(it);
				free(buf);
				pthread_mutex_unlock(&rcc->cards_busy);

				if (!apicall) {
					tpl_printf(vars, 0, "TOTALS", "card count=%d", caidcount);
					tpl_addVar(vars, 0, "ENTITLEMENTCONTENT", tpl_getTpl(vars, "ENTITLEMENTCCCAMBIT"));
				} else {
					tpl_printf(vars, 0, "APITOTALCARDS", "%d", caidcount);
				}

			} else {
				if (!apicall) {
					tpl_addVar(vars, 0, "ENTITLEMENTCONTENT", tpl_getTpl(vars, "ENTITLEMENTGENERICBIT"));
					tpl_addVar(vars, 0, "LOGHISTORY", "no cardfile found<BR>\n");
				} else {
					tpl_printf(vars, 0, "APITOTALCARDS", "%d", caidcount);
				}
			}

		} else {
			tpl_addVar(vars, 0, "LOGHISTORY", "->");
			// normal non-cccam reader
			FILE *fp;
			char filename[256];
			char buffer[128];

			int ridx;
			for (ridx=0,rdr=first_reader; rdr  && strcmp(reader_, rdr->label); rdr=rdr->next, ridx++);

			snprintf(filename, sizeof(filename), "%s/reader%d", get_tmp_dir(), ridx);
			fp = fopen(filename, "r");

			if (fp) {
				while (fgets(buffer, 128, fp) != NULL) {
					tpl_printf(vars, 1, "LOGHISTORY", "%s<BR>\n", buffer);
				}
				fclose(fp);
			}
			tpl_addVar(vars, 0, "READERNAME", rdr->label);
			tpl_addVar(vars, 0, "ENTITLEMENTCONTENT", tpl_getTpl(vars, "ENTITLEMENTGENERICBIT"));
		}

	} else {
		tpl_addVar(vars, 0, "LOGHISTORY",
				"You have to set saveinithistory=1 in your config to see Entitlements!<BR>\n");
		tpl_addVar(vars, 0, "ENTITLEMENTCONTENT", tpl_getTpl(vars, "ENTITLEMENTGENERICBIT"));
	}

	if (!apicall)
		webif_write(tpl_getTpl(vars, "ENTITLEMENTS"), f);
	else
		webif_write(tpl_getTpl(vars, "APICCCAMCARDLIST"), f);
}

void send_oscam_status(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in, int apicall) {
	int i;
	char *usr;
	int lsec, isec, con, cau;
	time_t now = time((time_t)0);
	struct tm *lt;

	if (strcmp(getParam(params, "action"), "kill") == 0) {
		struct s_client *cl = get_client_by_tid(atol(getParam(params, "threadid")));
		if (cl) {
			kill_thread(cl);
			cs_log("Client %s killed by WebIF from %s", cl->account->usr, inet_ntoa(*(struct in_addr *)&in));
		}
	}

	if (strcmp(getParam(params, "action"), "restart") == 0) {
		struct s_reader *rdr = get_reader_by_label(getParam(params, "label"));
		if(rdr)	{
			restart_cardreader(rdr, 1);
			cs_log("Reader %s restarted by WebIF from %s", rdr->label, inet_ntoa(*(struct in_addr *)&in));
		}
	}

	if (strcmp(getParam(params, "action"), "resetstat") == 0) {
		struct s_reader *rdr = get_reader_by_label(getParam(params, "label"));
		if(rdr) {
			clear_reader_stat(rdr);
			cs_log("Reader %s stats resetted by WebIF from %s", rdr->label, inet_ntoa(*(struct in_addr *)&in));
		}
	}

	char *debuglvl = getParam(params, "debug");
	if(strlen(debuglvl) > 0) {
#ifndef WITH_DEBUG
		cs_log("*** Warning: Debug Support not compiled in ***");
#else
		cs_dblevel = atoi(debuglvl);
		cs_log("%s debug_level=%d", "all", cs_dblevel);
#endif
	}

	if(getParamDef(params, "hide", NULL)) {
		ulong clidx;
		clidx = atol(getParamDef(params, "hide", NULL));
		struct s_client *hideidx = get_client_by_tid(clidx);
		if(hideidx)
			hideidx->wihidden = 1;
	}

	char *hideidle = getParam(params, "hideidle");
	if(strlen(hideidle) > 0) {
		if (atoi(hideidle) == 2) {
			struct s_client *cl;
			for (cl=first_client; cl ; cl=cl->next)
				cl->wihidden = 0;
		}
		else {
			int oldval = cfg->http_hide_idle_clients;
			chk_t_webif("httphideidleclients", hideidle);
			if(oldval != cfg->http_hide_idle_clients) {
				refresh_oscam(REFR_SERVER, in);
			}
		}
	}

	if(cfg->http_hide_idle_clients > 0) tpl_addVar(vars, 0, "HIDEIDLECLIENTSSELECTED1", "selected");
	else tpl_addVar(vars, 0, "HIDEIDLECLIENTSSELECTED0", "selected");

	int user_count_all = 0, user_count_active = 0;
	int reader_count_all = 0, reader_count_active = 0;
	int proxy_count_all = 0, proxy_count_active = 0;
	
	struct s_client *cl;
	for (i=0, cl=first_client; cl ; cl=cl->next, i++) {

		// Reset template variables
		tpl_addVar(vars, 0, "CLIENTLBVALUE","");
		tpl_addVar(vars, 0, "LASTREADER", "");

		if (cl->typ=='c')
			user_count_all++;
		else if (cl->typ=='p')
			proxy_count_all++;
		else if (cl->typ=='r')
			reader_count_all++;

		if (cl->wihidden != 1) {

			if((cfg->http_hide_idle_clients == 1) && (cl->typ == 'c') && ((now - cl->lastecm) > cfg->mon_hideclient_to)) continue;

			if (cl->typ=='c')
				user_count_active++;
			else if (cl->typ=='r' && cl->reader->card_status==CARD_INSERTED)
				reader_count_active++;
			else if (cl->typ=='p' && (cl->reader->card_status==CARD_INSERTED ||cl->reader->tcp_connected))
				proxy_count_active++;
			
			lsec=now-cl->login;
			isec=now-cl->last;
			usr=username(cl);

			if (((cl->typ=='r') || (cl->typ=='p')) && (con=get_ridx(cl->reader)>=0)) usr=cl->reader->label;

			if (cl->dup) con=2;
			else if ((cl->tosleep) && (now-cl->lastswitch>cl->tosleep)) con=1;
			else con=0;

			if( (cau=get_ridx(cl->aureader)+1) && (now-cl->lastemm)/60 > cfg->mon_aulow) cau=-cau;

			lt=localtime(&cl->login);

			tpl_printf(vars, 0, "HIDEIDX", "%ld", cl->thread);

			if(!cfg->http_js_icons)
				tpl_addVar(vars, 0, "HIDEICON", ICHID);

			if(cl->typ == 'c' && !cfg->http_readonly) {
				//tpl_printf(vars, 0, "CSIDX", "%d&nbsp;", i);
				if(cfg->http_js_icons)
					tpl_printf(vars, 0, "CSIDX", "<A HREF=\"status.html?action=kill&threadid=%ld\" TITLE=\"Kill this client\"><IMG HEIGHT=\"16\" WIDTH=\"16\" ID=\"ICKIL\" SRC=\"\" ALT=\"Kill\"></A>", cl->thread);
				else
					tpl_printf(vars, 0, "CSIDX", "<A HREF=\"status.html?action=kill&threadid=%ld\" TITLE=\"Kill this client\"><IMG HEIGHT=\"16\" WIDTH=\"16\" ID=\"ICKIL\" SRC=\"%s\" ALT=\"Kill\"></A>", cl->thread, ICKIL);
			}
			else if((cl->typ == 'p') && !cfg->http_readonly) {
				//tpl_printf(vars, 0, "CLIENTPID", "%d&nbsp;", cl->ridx);
				if(cfg->http_js_icons)
					tpl_printf(vars, 0, "CSIDX", "<A HREF=\"status.html?action=restart&label=%s\" TITLE=\"Restart this reader/ proxy\"><IMG HEIGHT=\"16\" WIDTH=\"16\" ID=\"ICKIL\" SRC=\"\" ALT=\"Restart\"></A>", cl->reader->label);
				else
					tpl_printf(vars, 0, "CSIDX", "<A HREF=\"status.html?action=restart&label=%s\" TITLE=\"Restart this reader/ proxy\"><IMG HEIGHT=\"16\" WIDTH=\"16\" ID=\"ICKIL\" SRC=\"%s\" ALT=\"Restart\"></A>", cl->reader->label, ICKIL);
			}
			else {
				tpl_printf(vars, 0, "CSIDX", "%8X&nbsp;", cl->thread);
			}

			tpl_printf(vars, 0, "CLIENTTYPE", "%c", cl->typ);
			tpl_printf(vars, 0, "CLIENTCNR", "%d", get_threadnum(cl));
			tpl_addVar(vars, 0, "CLIENTUSER", xml_encode(vars, usr));
			if (cl->typ == 'c')	tpl_addVar(vars, 0, "CLIENTDESCRIPTION", xml_encode(vars, cl->account->description));
			tpl_printf(vars, 0, "CLIENTCAU", "%d", cau);
			tpl_printf(vars, 0, "CLIENTCRYPTED", "%d", cl->crypted);
			tpl_addVar(vars, 0, "CLIENTIP", cs_inet_ntoa(cl->ip));
			tpl_printf(vars, 0, "CLIENTPORT", "%d", cl->port);
			char *proto = monitor_get_proto(cl);

			if ((strcmp(proto,"newcamd") == 0) && (cl->typ == 'c'))
				tpl_printf(vars, 0, "CLIENTPROTO","%s (%s)", proto, get_ncd_client_name(cl->ncd_client_id));
			else if (((strcmp(proto,"cccam") == 0) || (strcmp(proto,"cccam ext") == 0))) {
			//else if ((strcmp(proto,"cccam") == 0) || (strcmp(proto,"cccam ext") == 0)) {
				struct cc_data *cc = cl->cc;
				if(cc) {
					tpl_printf(vars, 0, "CLIENTPROTO", "%s (%s-%s)", proto, cc->remote_version, cc->remote_build);
					if(strcmp(proto,"cccam ext") == 0)
						tpl_addVar(vars, 0, "CLIENTPROTOTITLE", cc->remote_oscam);
					else
						tpl_addVar(vars, 0, "CLIENTPROTOTITLE", ""); //unset tpl var
				}
			}
			else {
				tpl_addVar(vars, 0, "CLIENTPROTO", proto);
				tpl_addVar(vars, 0, "CLIENTPROTOTITLE", "");
			}

			int secs = 0, fullmins =0, mins =0, fullhours =0, hours =0, days =0;
			if (!apicall) {
				tpl_printf(vars, 0, "CLIENTLOGINDATE", "%02d.%02d.%02d", lt->tm_mday, lt->tm_mon+1, lt->tm_year%100);
				tpl_printf(vars, 1, "CLIENTLOGINDATE", " %02d:%02d:%02d", lt->tm_hour, lt->tm_min, lt->tm_sec);

				if(lsec > 0) {
					secs = lsec % 60;
					if (lsec > 60) {
						fullmins = lsec / 60;
						mins = fullmins % 60;
						if(fullmins > 60) {
							fullhours = fullmins / 60;
							hours = fullhours % 24;
							days = fullhours / 24;
						}
					}
				}
				if(days == 0)
					tpl_printf(vars, 0, "CLIENTLOGINSECS", "%02d:%02d:%02d", hours, mins, secs);
				else
					tpl_printf(vars, 0, "CLIENTLOGINSECS", "%02dd %02d:%02d:%02d", days, hours, mins, secs);

			} else {
				char tbuffer [30];
				strftime(tbuffer, 30, "%Y-%m-%dT%H:%M:%S%z", lt);
				tpl_printf(vars, 0, "CLIENTLOGINDATE", "%s", tbuffer);
				tpl_printf(vars, 0, "CLIENTLOGINSECS", "%d", lsec);
			}

			if (isec < cfg->mon_hideclient_to || cfg->mon_hideclient_to == 0) {

				if (((cl->typ!='r') || (cl->typ!='p')) && (cl->lastreader[0])) {
					tpl_printf(vars, 0, "CLIENTLBVALUE", "by %s", cl->lastreader);
					tpl_printf(vars, 1, "CLIENTLBVALUE", "&nbsp;(%dms)", cl->cwlastresptime);
					if (apicall)
						tpl_addVar(vars, 0, "LASTREADER", cl->lastreader);
				}

				tpl_printf(vars, 0, "CLIENTCAID", "%04X", cl->last_caid);
				tpl_printf(vars, 0, "CLIENTSRVID", "%04X", cl->last_srvid);
				tpl_printf(vars, 0, "CLIENTLASTRESPONSETIME", "%d", cl->cwlastresptime);

				int j, found = 0;
				struct s_srvid *srvid = cfg->srvid;

				while (srvid != NULL) {
					if (srvid->srvid == cl->last_srvid) {
						for (j=0; j < srvid->ncaid; j++) {
							if (srvid->caid[j] == cl->last_caid) {
								found = 1;
								break;
							}
						}
					}
					if (found == 1)
						break;
					else
						srvid = srvid->next;
				}

				if (found == 1) {
					tpl_printf(vars, 0, "CLIENTSRVPROVIDER","%s: ", xml_encode(vars, srvid->prov));
					tpl_addVar(vars, 0, "CLIENTSRVNAME", xml_encode(vars, srvid->name));
					tpl_addVar(vars, 0, "CLIENTSRVTYPE", xml_encode(vars, srvid->type));
					tpl_addVar(vars, 0, "CLIENTSRVDESCRIPTION", xml_encode(vars, srvid->desc));
				} else {
					tpl_addVar(vars, 0, "CLIENTSRVPROVIDER","");
					tpl_addVar(vars, 0, "CLIENTSRVNAME","");
					tpl_addVar(vars, 0, "CLIENTSRVTYPE","");
					tpl_addVar(vars, 0, "CLIENTSRVDESCRIPTION","");
				}

			} else {
				tpl_addVar(vars, 0, "CLIENTCAID", "0000");
				tpl_addVar(vars, 0, "CLIENTSRVID", "0000");
				tpl_addVar(vars, 0, "CLIENTSRVPROVIDER","");
				tpl_addVar(vars, 0, "CLIENTSRVNAME","");
				tpl_addVar(vars, 0, "CLIENTSRVTYPE","");
				tpl_addVar(vars, 0, "CLIENTSRVDESCRIPTION","");
				tpl_addVar(vars, 0, "CLIENTLBVALUE","");

			}

			if (!apicall) {
			secs = 0, fullmins =0, mins =0, fullhours =0, hours =0, days =0;
			if(isec > 0) {
				secs = isec % 60;
				if (isec > 60) {
					fullmins = isec / 60;
					mins = fullmins % 60;
					if(fullmins > 60) {
						fullhours = fullmins / 60;
						hours = fullhours % 24;
						days = fullhours / 24;
					}
				}
			}
			if(days == 0)
				tpl_printf(vars, 0, "CLIENTIDLESECS", "%02d:%02d:%02d", hours, mins, secs);
			else
				tpl_printf(vars, 0, "CLIENTIDLESECS", "%02dd %02d:%02d:%02d", days, hours, mins, secs);
			} else {
				tpl_printf(vars, 0, "CLIENTIDLESECS", "%d", isec);
			}


			if(con == 2) tpl_addVar(vars, 0, "CLIENTCON", "Duplicate");
			else if (con == 1) tpl_addVar(vars, 0, "CLIENTCON", "Sleep");
			else
			{
				char *txt = "OK";
				if (cl->typ == 'r' || cl->typ == 'p') //reader or proxy
				{
					struct s_reader *rdr = cl->reader;
							if (rdr->lbvalue)
								tpl_printf(vars, 0, "CLIENTLBVALUE", "<A HREF=\"status.html?action=resetstat&label=%s\" TITLE=\"Reset statistics for this reader/ proxy\">%d</A>", rdr->label, rdr->lbvalue);
							else
								tpl_printf(vars, 0, "CLIENTLBVALUE", "<A HREF=\"status.html?action=resetstat&label=%s\" TITLE=\"Reset statistics for this reader/ proxy\">%s</A>", rdr->label, "no data");

							switch(rdr->card_status)
							{
							case NO_CARD: txt = "OFF"; break;
							case CARD_NEED_INIT: txt = "NEEDINIT"; break;
							case CARD_INSERTED:
								if (cl->typ=='p')
									txt = "CONNECTED";
								else
									txt = "CARDOK";
								break;
							case CARD_FAILURE: txt = "ERROR"; break;
							default: txt = "UNDEF";
							}
				}
				tpl_addVar(vars, 0, "CLIENTCON", txt);
			}

			if (!apicall){
				// select right suborder
				if (cl->typ == 'c') {
					tpl_addVar(vars, 1, "CLIENTSTATUS", tpl_getTpl(vars, "CLIENTSTATUSBIT"));
					tpl_printf(vars, 0, "CLIENTHEADLINE", "<TR><TD CLASS=\"subheadline\" colspan=\"17\">Clients %d/%d</TD></TR>\n",
							user_count_active, user_count_all);
				}
				else if (cl->typ == 'r') {
					tpl_addVar(vars, 1, "READERSTATUS", tpl_getTpl(vars, "CLIENTSTATUSBIT"));
					tpl_printf(vars, 0, "READERHEADLINE", "<TR><TD CLASS=\"subheadline\" colspan=\"17\">Readers %d/%d</TD></TR>\n",
							reader_count_active, reader_count_all);
				}
				else if (cl->typ == 'p') {
					tpl_addVar(vars, 1, "PROXYSTATUS", tpl_getTpl(vars, "CLIENTSTATUSBIT"));
					tpl_printf(vars, 0, "PROXYHEADLINE", "<TR><TD CLASS=\"subheadline\" colspan=\"17\">Proxies %d/%d</TD></TR>\n",
							proxy_count_active, proxy_count_all);
				}
				else
					tpl_addVar(vars, 1, "SERVERSTATUS", tpl_getTpl(vars, "CLIENTSTATUSBIT"));

			} else {
				tpl_addVar(vars, 1, "APISTATUSBITS", tpl_getTpl(vars, "APISTATUSBIT"));
			}

		}
		if (cl->next == NULL)
			break;
	}
	//tpl_printf(vars, 0, "USERCOUNTALL", "%d", user_count_all);
	//tpl_printf(vars, 0, "USERCOUNTACTIVE", "%d", user_count_active);

	//tpl_printf(vars, 0, "READERCOUNTALL", "%d", reader_count_all);
	//tpl_printf(vars, 0, "READERCOUNTACTIVE", "%d", reader_count_active);

	//tpl_printf(vars, 0, "PROXYCOUNTALL", "%d", proxy_count_all);
	//tpl_printf(vars, 0, "PROXYCOUNTACTIVE", "%d", proxy_count_active);

#ifdef CS_LOGHISTORY
	for (i=(loghistidx+3) % CS_MAXLOGHIST; i!=loghistidx; i=(i+1) % CS_MAXLOGHIST) {
		char *p_usr, *p_txt;
		p_usr=(char *)(loghist+(i*CS_LOGHISTSIZE));
		p_txt=p_usr+32;

		if (!apicall) {
			if (p_txt[0]) tpl_printf(vars, 1, "LOGHISTORY", "<span class=\"%s\">%s</span><br>\n", p_usr, p_txt+8);
		} else {
			if (strcmp(getParam(params, "appendlog"), "1") == 0)
				tpl_printf(vars, 1, "LOGHISTORY", "%s", p_txt+8);
		}
	}
#else
	tpl_addVar(vars, 0, "LOGHISTORY", "the flag CS_LOGHISTORY is not set in your binary<BR>\n");
#endif

	// Debuglevel Selector
	tpl_addVar(vars, 0, "NEXTPAGE", "status.html");
	tpl_printf(vars, 0, "ACTDEBUG", "%d", cs_dblevel);
	tpl_addVar(vars, 0, "SDEBUG", tpl_getTpl(vars, "DEBUGSELECT"));

	if(!apicall)
		webif_write(tpl_getTpl(vars, "STATUS"), f);
	else
		webif_write(tpl_getTpl(vars, "APISTATUS"), f);

}

void send_oscam_services_edit(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in) {
	struct s_sidtab *sidtab,*ptr;
	char label[128];
	int i;

	cs_strncpy(label, strtolower(getParam(params, "service")), sizeof(label)/sizeof(char));

	for (sidtab = cfg->sidtab; sidtab != NULL && strcmp(label, sidtab->label) != 0; sidtab=sidtab->next);

	if (sidtab == NULL) {
		i = 1;
		while(strlen(label) < 1) {
			snprintf(label, sizeof(label)/sizeof(char) - 1, "newservice%d", i);
			for (sidtab = cfg->sidtab; sidtab != NULL && strcmp(label, sidtab->label) != 0; sidtab = sidtab->next);
			if(sidtab != NULL) label[0] = '\0';
			++i;
		}
		if (!(sidtab=malloc(sizeof(struct s_sidtab)))) {
			cs_log("Error allocating memory (errno=%d)", errno);
			return;
		}

		if(cfg->sidtab == NULL) cfg->sidtab = sidtab;
		else {
			for (ptr = cfg->sidtab; ptr != NULL && ptr->next != NULL; ptr = ptr->next);
			ptr->next = sidtab;
		}
		memset(sidtab, 0, sizeof(struct s_sidtab));
		cs_strncpy((char *)sidtab->label, label, sizeof(sidtab->label));

		tpl_addVar(vars, 1, "MESSAGE", "<b>New service has been added</b><BR>");
		if (write_services()==0) refresh_oscam(REFR_SERVICES, in);
		else tpl_addVar(vars, 1, "MESSAGE", "<b>Writing services to disk failed!</b><BR>");

		for (sidtab = cfg->sidtab; sidtab != NULL && strcmp(label, sidtab->label) != 0; sidtab=sidtab->next);
	}

	if (strcmp(getParam(params, "action"), "Save") == 0) {
		for(i=0;i<(*params).paramcount;i++) {
			if ((strcmp((*params).params[i], "action")) && (strcmp((*params).params[i], "service"))) {
				chk_sidtab((*params).params[i], (*params).values[i], sidtab);
			}
		}
		tpl_addVar(vars, 1, "MESSAGE", "<B>Services updated</B><BR><BR>");
		if (write_services()==0) refresh_oscam(REFR_SERVICES, in);
		else tpl_addVar(vars, 1, "MESSAGE", "<B>Write Config failed</B><BR><BR>");

		for (sidtab = cfg->sidtab; sidtab != NULL && strcmp(label, sidtab->label) != 0; sidtab=sidtab->next);
	}

	tpl_addVar(vars, 0, "LABEL", sidtab->label);
	tpl_addVar(vars, 0, "LABELENC", urlencode(sidtab->label));

	for (i=0; i<sidtab->num_caid; i++) {
		if (i==0) tpl_printf(vars, 0, "CAIDS", "%04X", sidtab->caid[i]);
		else tpl_printf(vars, 1, "CAIDS", ",%04X", sidtab->caid[i]);
	}
	for (i=0; i<sidtab->num_provid; i++) {
		if (i==0) tpl_printf(vars, 0, "PROVIDS", "%06lX", sidtab->provid[i]);
		else tpl_printf(vars, 1, "PROVIDS", ",%06lX", sidtab->provid[i]);
	}
	for (i=0; i<sidtab->num_srvid; i++) {
		if (i==0) tpl_printf(vars, 0, "SRVIDS", "%04X", sidtab->srvid[i]);
		else tpl_printf(vars, 1, "SRVIDS", ",%04X", sidtab->srvid[i]);
	}
	webif_write(tpl_getTpl(vars, "SERVICEEDIT"), f);
}

void send_oscam_services(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in) {
	struct s_sidtab *sidtab, *sidtab2;
	char *service = getParam(params, "service");
	int i, found = 0;

	if (strcmp(getParam(params, "action"), "delete") == 0) {
		if(cfg->http_readonly) {
			tpl_addVar(vars, 1, "MESSAGE", "<b>Sorry, Webif is in readonly mode. No deletion will be made!</b><BR>");
		} else {
			sidtab=cfg->sidtab;
			if(strcmp(sidtab->label, service) == 0) {
				cfg->sidtab = sidtab->next;
				free(sidtab);
				found = 1;
			} else if (sidtab->next != NULL) {
				do {
					if(strcmp(sidtab->next->label, service) == 0) {
						sidtab2 = sidtab->next;
						sidtab->next = sidtab2->next;
						free(sidtab2);
						found = 1;
						break;
					}
				} while ((sidtab = sidtab->next) && (sidtab->next != NULL));
			}
			if (found > 0) {
				tpl_addVar(vars, 1, "MESSAGE", "<b>Service has been deleted!</b><BR>");
				if (write_services() == 0) refresh_oscam(REFR_SERVICES, in);
				else tpl_addVar(vars, 1, "MESSAGE", "<b>Writing services to disk failed!</b><BR>");
			} else tpl_addVar(vars, 1, "MESSAGE", "<b>Sorry but the specified service doesn't exist. No deletion will be made!</b><BR>");
		}
	}

	sidtab = cfg->sidtab;
	// Show List
	while(sidtab != NULL) {
		tpl_printf(vars, 0, "SID","");
		if ((strcmp(getParam(params, "service"), sidtab->label) == 0) && (strcmp(getParam(params, "action"), "list") == 0) ) {
			tpl_printf(vars, 0, "SIDCLASS","sidlist");
			tpl_printf(vars, 1, "SID", "<div style=\"float:right;background-color:red;color:white\"><A HREF=\"services.html\" style=\"color:white;text-decoration:none\">X</A></div>");
			for (i=0; i<sidtab->num_srvid; i++) {
				tpl_printf(vars, 1, "SID", "%04X : %s<BR>", sidtab->srvid[i], xml_encode(vars, get_servicename(sidtab->srvid[i], sidtab->caid[0])));
			}
		} else {
			tpl_printf(vars, 0, "SIDCLASS","");
			tpl_printf(vars, 0, "SID","<A HREF=\"services.html?service=%s&action=list\">Show Services</A>",tpl_addTmp(vars, urlencode(sidtab->label)));
		}
		tpl_addVar(vars, 0, "LABELENC", tpl_addTmp(vars, urlencode(sidtab->label)));
		tpl_addVar(vars, 0, "LABEL", xml_encode(vars, sidtab->label));
		tpl_addVar(vars, 0, "SIDLIST", tpl_getTpl(vars, "SERVICECONFIGSIDBIT"));

		if (!cfg->http_js_icons) {
			tpl_addVar(vars, 0, "EDIICO", ICEDI);
			tpl_addVar(vars, 0, "DELICO", ICDEL);
		}

		tpl_addVar(vars, 1, "SERVICETABS", tpl_getTpl(vars, "SERVICECONFIGLISTBIT"));
		sidtab=sidtab->next;
	}
	webif_write(tpl_getTpl(vars, "SERVICECONFIGLIST"), f);
}

void send_oscam_savetpls(struct templatevars *vars, FILE *f) {
	if(strlen(cfg->http_tpl) > 0) {
		tpl_printf(vars, 0, "CNT", "%d", tpl_saveIncludedTpls(cfg->http_tpl));
		tpl_addVar(vars, 0, "PATH", cfg->http_tpl);
	} else tpl_addVar(vars, 0, "CNT", "0");
	webif_write(tpl_getTpl(vars, "SAVETEMPLATES"), f);
}

void send_oscam_shutdown(struct templatevars *vars, FILE *f, struct uriparams *params) {
	if (strcmp(getParam(params, "action"), "Shutdown") == 0) {
		tpl_addVar(vars, 0, "STYLESHEET", CSS);
		tpl_printf(vars, 0, "REFRESHTIME", "%d", SHUTDOWNREFRESH);
		tpl_addVar(vars, 0, "REFRESHURL", "status.html");
		tpl_addVar(vars, 0, "REFRESH", tpl_getTpl(vars, "REFRESH"));
		tpl_printf(vars, 0, "SECONDS", "%d", SHUTDOWNREFRESH);
		webif_write(tpl_getTpl(vars, "SHUTDOWN"), f);
		running = 0;

		cs_exit_oscam();
	}
	else if (strcmp(getParam(params, "action"), "Restart") == 0) {
		tpl_addVar(vars, 0, "STYLESHEET", CSS);
		tpl_printf(vars, 0, "REFRESHTIME", "%d", 2);
		tpl_addVar(vars, 0, "REFRESHURL", "status.html");
		tpl_addVar(vars, 0, "REFRESH", tpl_getTpl(vars, "REFRESH"));
		tpl_printf(vars, 0, "SECONDS", "%d", 2);
		webif_write(tpl_getTpl(vars, "SHUTDOWN"), f);
		running = 0;
		
		cs_restart_oscam();
		
	} else {
		webif_write(tpl_getTpl(vars, "PRESHUTDOWN"), f);
	}
}

void send_oscam_script(struct templatevars *vars, FILE *f) {

	char *result = "not found";
	int rc = 0;
	if(!cfg->http_readonly) {
		if(cfg->http_script[0]) {
			tpl_addVar(vars, 0, "SCRIPTNAME",cfg->http_script);
			rc = system(cfg->http_script);
			if(rc == -1) {
				result = "done";
			} else {
				result = "failed";
			}
		} else {
			tpl_addVar(vars, 0, "SCRIPTNAME", "no script defined");
		}
		tpl_addVar(vars, 0, "SCRIPTRESULT", result);
		tpl_printf(vars, 0, "CODE", "%d", rc);
	} else {
		tpl_addVar(vars, 1, "MESSAGE", "<b>Sorry, Webif is in readonly mode. No script execution possible!</b><BR>");
	}
	webif_write(tpl_getTpl(vars, "SCRIPT"), f);

}

void send_oscam_scanusb(struct templatevars *vars, FILE *f) {
	FILE *fp;
	int err=0;
	char path[1035];

	fp = popen("lsusb -v | egrep '^Bus|^ *iSerial|^ *iProduct'", "r");
	if (fp == NULL) {
		tpl_addVar(vars, 0, "USBENTRY", "Failed to run lusb");
		tpl_printf(vars, 0, "USBENTRY", "%s", path);
		tpl_addVar(vars, 1, "USBBIT", tpl_getTpl(vars, "SCANUSBBIT"));
		err = 1;
	}

	if(!err) {
		while (fgets(path, sizeof(path)-1, fp) != NULL) {
			tpl_addVar(vars, 0, "USBENTRYCLASS", "");
			if (strstr(path,"Bus ")) {
				tpl_printf(vars, 0, "USBENTRY", "%s", path);
				tpl_addVar(vars, 0, "USBENTRYCLASS", "CLASS=\"scanusbsubhead\"");
			} else {
				tpl_printf(vars, 0, "USBENTRY", "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;%s", path);
			}
			tpl_addVar(vars, 1, "USBBIT", tpl_getTpl(vars, "SCANUSBBIT"));
		}
	}
	pclose(fp);
	webif_write(tpl_getTpl(vars, "SCANUSB"), f);
}

void send_oscam_files(struct templatevars *vars, FILE *f, struct uriparams *params) {

	int writable=0;

	char *stoplog = getParam(params, "stoplog");
	if(strlen(stoplog) > 0)
		cfg->disablelog = atoi(stoplog);

	char *stopusrlog = getParam(params, "stopusrlog");
	if(strlen(stopusrlog) > 0)
		cfg->disableuserfile = atoi(stopusrlog);

	char *debuglvl = getParam(params, "debug");
	if(strlen(debuglvl) > 0)
#ifndef WITH_DEBUG
		cs_log("*** Warning: Debug Support not compiled in ***");
#else
		cs_dblevel = atoi(debuglvl);
		cs_log("%s debug_level=%d", "all", cs_dblevel);
#endif

	char targetfile[256];

	if (strcmp(getParam(params, "part"), "conf") == 0) {
		snprintf(targetfile, 255,"%s%s", cs_confdir, "oscam.conf");
		writable = 1;
	}
	else if (strcmp(getParam(params, "part"), "version") == 0)
		snprintf(targetfile, 255,"%s%s", get_tmp_dir(), "/oscam.version");
	else if (strcmp(getParam(params, "part"), "user") == 0) {
		snprintf(targetfile, 255,"%s%s", cs_confdir, "oscam.user");
		writable = 1;
	}
	else if (strcmp(getParam(params, "part"), "server") == 0) {
		snprintf(targetfile, 255,"%s%s", cs_confdir, "oscam.server");
		writable = 1;
	}
	else if (strcmp(getParam(params, "part"), "services") == 0) {
		snprintf(targetfile, 255,"%s%s", cs_confdir, "oscam.services");
		writable = 1;
	}
	else if (strcmp(getParam(params, "part"), "srvid") == 0) {
		snprintf(targetfile, 255,"%s%s", cs_confdir, "oscam.srvid");
		writable = 1;
	}
	else if (strcmp(getParam(params, "part"), "provid") == 0) {
		snprintf(targetfile, 255,"%s%s", cs_confdir, "oscam.provid");
		writable = 1;
	}
	else if (strcmp(getParam(params, "part"), "tiers") == 0) {
		snprintf(targetfile, 255,"%s%s", cs_confdir, "oscam.tiers");
		writable = 1;
	}
	else if (strcmp(getParam(params, "part"), "logfile") == 0) {
		snprintf(targetfile, 255,"%s", cfg->logfile);

		if (strcmp(getParam(params, "clear"), "logfile") == 0) {
			if(strlen(targetfile) > 0) {
				FILE *file = fopen(targetfile,"w");
				fclose(file);
			}
		}

		// Debuglevel Selector
		tpl_addVar(vars, 0, "NEXTPAGE", "files.html");
		tpl_addVar(vars, 0, "CUSTOMPARAM", "&part=logfile");
		tpl_printf(vars, 0, "ACTDEBUG", "%d", cs_dblevel);
		tpl_addVar(vars, 0, "SDEBUG", tpl_getTpl(vars, "DEBUGSELECT"));

		if(!cfg->disablelog)
			tpl_printf(vars, 0, "SLOG", "<BR><A CLASS=\"debugl\" HREF=\"files.html?part=logfile&stoplog=%d\">%s</A><SPAN CLASS=\"debugt\">&nbsp;&nbsp;|&nbsp;&nbsp;</SPAN>\n", 1, "Stop Log");
		else
			tpl_printf(vars, 0, "SLOG", "<BR><A CLASS=\"debugl\" HREF=\"files.html?part=logfile&stoplog=%d\">%s</A><SPAN CLASS=\"debugt\">&nbsp;&nbsp;|&nbsp;&nbsp;</SPAN>\n", 0, "Start Log");

		tpl_printf(vars, 0, "SCLEAR", "<A CLASS=\"debugl\" HREF=\"files.html?part=logfile&clear=logfile\">%s</A><BR><BR>\n", "Clear Log");
	}
	else if (strcmp(getParam(params, "part"), "userfile") == 0) {
		snprintf(targetfile, 255,"%s", cfg->usrfile);
		if (strcmp(getParam(params, "clear"), "usrfile") == 0) {
			if(strlen(targetfile) > 0) {
				FILE *file = fopen(targetfile,"w");
				fclose(file);
			}
		}

		if(!cfg->disableuserfile)
			tpl_printf(vars, 0, "SLOG", "<A HREF=\"files.html?part=userfile&stopusrlog=%d\">%s</A>&nbsp;&nbsp;|&nbsp;&nbsp;\n", 1, "Stop Log");
		else
			tpl_printf(vars, 0, "SLOG", "<A HREF=\"files.html?part=userfile&stopusrlog=%d\">%s</A>&nbsp;&nbsp;|&nbsp;&nbsp;\n", 0, "Start Log");

		tpl_printf(vars, 0, "SCLEAR", "<A HREF=\"files.html?part=userfile&clear=usrfile\">%s</A><BR><BR>\n", "Clear Log");
		tpl_addVar(vars, 0, "FILTER", "<FORM ACTION=\"files.html\" method=\"get\">\n");
		tpl_addVar(vars, 1, "FILTER", "<INPUT name=\"part\" type=\"hidden\" value=\"userfile\">\n");
		tpl_addVar(vars, 1, "FILTER", "<SELECT name=\"filter\">\n");
		tpl_printf(vars, 1, "FILTER", "<OPTION value=\"%s\">%s</OPTION>\n", "all", "all");

		struct s_auth *account;
		for (account = cfg->account; (account); account = account->next) {
			tpl_printf(vars, 1, "FILTER", "<OPTION value=\"%s\" %s>%s</OPTION>\n", account->usr, strcmp(getParam(params, "filter"), account->usr) ? "":"selected", account->usr);
		}
		tpl_addVar(vars, 1, "FILTER", "</SELECT><input type=\"submit\" name=\"action\" value=\"Filter\" title=\"Filter for a specific user\"></FORM>\n");

	}
#ifdef CS_ANTICASC
	else if (strcmp(getParam(params, "part"), "anticasc") == 0)
		snprintf(targetfile, 255,"%s", cfg->ac_logfile);
#endif

#ifdef HAVE_DVBAPI
	else if (strcmp(getParam(params, "part"), "dvbapi") == 0) {
		snprintf(targetfile, 255, "%s%s", cs_confdir, "oscam.dvbapi");
		writable = 1;
	}
#endif


	if (!strstr(targetfile, "/dev/")) {

		if (strcmp(getParam(params, "action"), "Save") == 0) {
			if((strlen(targetfile) > 0) && (file_exists(targetfile) == 1)) {
				FILE *fpsave;
				char *fcontent = getParam(params, "filecontent");

				if((fpsave = fopen(targetfile,"w"))){
					fprintf(fpsave,"%s",fcontent);
					fclose(fpsave);

#ifdef HAVE_DVBAPI
					 if (strcmp(getParam(params, "part"), "dvbapi") == 0)
						 dvbapi_read_priority();
#endif
				}
			}
		}

		if((strlen(targetfile) > 0) && (file_exists(targetfile) == 1)) {
			FILE *fp;
			char buffer[256];

			if((fp = fopen(targetfile,"r")) == NULL) return;
			while (fgets(buffer, sizeof(buffer), fp) != NULL)
				if (!strcmp(getParam(params, "filter"), "all"))
					tpl_printf(vars, 1, "FILECONTENT", "%s", buffer);
				else
					if(strstr(buffer,getParam(params, "filter")))
						tpl_printf(vars, 1, "FILECONTENT", "%s", buffer);
			fclose (fp);
		} else {
			tpl_addVar(vars, 1, "FILECONTENT", "File not exist");
		}
	} else {
		tpl_addVar(vars, 1, "FILECONTENT", "File not valid");
	}

	tpl_addVar(vars, 0, "PART", getParam(params, "part"));

	if (!writable) {
		tpl_addVar(vars, 0, "WRITEPROTECTION", "You cannot change content of this file");
		tpl_addVar(vars, 0, "BTNDISABLED", "DISABLED");
	}


	webif_write(tpl_getTpl(vars, "FILE"), f);
}

void send_oscam_failban(struct templatevars *vars, FILE *f, struct uriparams *params) {

	uint ip2delete = 0;
	LLIST_D__ITR itr;
	V_BAN *v_ban_entry = llist_itr_init(cfg->v_list, &itr);

	if (strcmp(getParam(params, "action"), "delete") == 0) {
		sscanf(getParam(params, "intip"), "%u", &ip2delete);
		while (v_ban_entry) {
			if (v_ban_entry->v_ip == ip2delete) {
				free(v_ban_entry);
				llist_itr_remove(&itr);
				break;
			}
			v_ban_entry = llist_itr_next(&itr);
		}
	}

	time_t now = time((time_t)0);
	v_ban_entry = llist_itr_init(cfg->v_list, &itr);

	while (v_ban_entry) {

		if (!cfg->http_js_icons)
			tpl_addVar(vars, 0, "DELICO", ICDEL);
		tpl_printf(vars, 0, "IPADDRESS", "%s", cs_inet_ntoa(v_ban_entry->v_ip));

		struct tm *st ;
		st = localtime(&v_ban_entry->v_time);

		tpl_printf(vars, 0, "VIOLATIONDATE", "%02d.%02d.%02d %02d:%02d:%02d",
				st->tm_mday, st->tm_mon+1,
				st->tm_year%100, st->tm_hour,
				st->tm_min, st->tm_sec);

		tpl_printf(vars, 0, "VIOLATIONCOUNT", "%d", v_ban_entry->v_count);

		int lsec = (cfg->failbantime * 60) - (now - v_ban_entry->v_time);
		int secs = 0, fullmins =0, mins =0, fullhours =0, hours =0, days =0;
		if(lsec > 0) {
			secs = lsec % 60;
			if (lsec > 60) {
				fullmins = lsec / 60;
				mins = fullmins % 60;
				if(fullmins > 60) {
					fullhours = fullmins / 60;
					hours = fullhours % 24;
					days = fullhours / 24;
				}
			}
		}
		if(days == 0)
			tpl_printf(vars, 0, "LEFTTIME", "%02d:%02d:%02d", hours, mins, secs);
		else
			tpl_printf(vars, 0, "LEFTTIME", "%02dd %02d:%02d:%02d", days, hours, mins, secs);

		tpl_printf(vars, 0, "INTIP", "%u", v_ban_entry->v_ip);
		tpl_addVar(vars, 1, "FAILBANROW", tpl_getTpl(vars, "FAILBANBIT"));
		v_ban_entry = llist_itr_next(&itr);
	}

	webif_write(tpl_getTpl(vars, "FAILBAN"), f);
}

void send_oscam_api(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in) {
	if (strcmp(getParam(params, "part"), "status") == 0) {
		send_oscam_status(vars, f, params, in, 1);
	}
	else if (strcmp(getParam(params, "part"), "entitlement") == 0) {

		if (strcmp(getParam(params, "label"),"")) {
			struct s_reader *rdr = get_reader_by_label(getParam(params, "label"));
			if (rdr) {
				if (rdr->typ == R_CCCAM && rdr->enable == 1) {
					send_oscam_entitlement(vars, f, params, in, 1);
				} else {
					//Send Errormessage
					tpl_addVar(vars, 0, "APIERRORMESSAGE", "no cccam reader or disabled");
					webif_write(tpl_getTpl(vars, "APIERROR"), f);
				}
			} else {
				//Send Errormessage
				tpl_addVar(vars, 0, "APIERRORMESSAGE", "reader not exist");
				webif_write(tpl_getTpl(vars, "APIERROR"), f);
			}
		} else {
			//Send Errormessage
			tpl_addVar(vars, 0, "APIERRORMESSAGE", "no reader selected");
			webif_write(tpl_getTpl(vars, "APIERROR"), f);
		}
	}
	else if (strcmp(getParam(params, "part"), "readerstats") == 0) {
		if (strcmp(getParam(params, "label"),"")) {
			struct s_reader *rdr = get_reader_by_label(getParam(params, "label"));
			if (rdr) {
				send_oscam_reader_stats(vars, f, params, in, 1);
			} else {
				//Send Errormessage
				tpl_addVar(vars, 0, "APIERRORMESSAGE", "reader not exist");
				webif_write(tpl_getTpl(vars, "APIERROR"), f);
			}
		} else {
			//Send Errormessage
			tpl_addVar(vars, 0, "APIERRORMESSAGE", "no reader selected");
			webif_write(tpl_getTpl(vars, "APIERROR"), f);
		}
	}
	else {
		tpl_addVar(vars, 0, "APIERRORMESSAGE", "part not found");
		webif_write(tpl_getTpl(vars, "APIERROR"), f);
	}
}

void webif_parse_request(struct uriparams *params, char *pch) {
	/* Parse url parameters; parsemode = 1 means parsing next param, parsemode = -1 parsing next
	 value; pch2 points to the beginning of the currently parsed string, pch is the current position */

	char *pch2;
	int parsemode = 1;

	pch2=pch;
	while(pch[0] != '\0') {
		if((parsemode == 1 && pch[0] == '=') || (parsemode == -1 && pch[0] == '&')) {
			pch[0] = '\0';
			urldecode(pch2);
			if(parsemode == 1) {
				if(params->paramcount >= MAXGETPARAMS) break;
				++params->paramcount;
				params->params[params->paramcount-1] = pch2;
			} else {
				params->values[params->paramcount-1] = pch2;
			}
			parsemode = -parsemode;
			pch2 = pch + 1;
		}
		++pch;
	}
	/* last value wasn't processed in the loop yet... */
	if(parsemode == -1 && params->paramcount <= MAXGETPARAMS) {
		urldecode(pch2);
		params->values[params->paramcount-1] = pch2;
	}
}

int process_request(FILE *f, struct in_addr in) {

	cur_client()->last = time((time_t)0); //reset last busy time

	int ok=0,v=cv();
	struct s_ip *p_ip;
	in_addr_t addr = cs_inet_order(in.s_addr);

	for (p_ip = cfg->http_allowed; (p_ip) && (!ok); p_ip = p_ip->next)
		ok =((addr >= p_ip->ip[0]) && (addr <= p_ip->ip[1]))?v:0;

	if (!ok && cfg->http_dyndns[0]) {
		if(cfg->http_dynip && cfg->http_dynip == addr) {
			ok = v;

		} else {

			if (cfg->resolve_gethostbyname) {

				pthread_mutex_lock(&gethostbyname_lock);
				struct hostent *rht;
				struct sockaddr_in udp_sa;

				rht = gethostbyname((const char *) cfg->http_dyndns);
				if (rht) {
					memcpy(&udp_sa.sin_addr, rht->h_addr, sizeof(udp_sa.sin_addr));
					cfg->http_dynip = cs_inet_order(udp_sa.sin_addr.s_addr);
					cs_debug_mask(D_TRACE, "WebIf: dynip resolved %s access from %s",
												inet_ntoa(*(struct in_addr *)&cfg->http_dynip),
												inet_ntoa(*(struct in_addr *)&addr));
					if (cfg->http_dynip == addr)
						ok = v;
				} else {
					cs_log("can't resolve %s", cfg->http_dyndns);
				}
				pthread_mutex_unlock(&gethostbyname_lock);

			} else {

				struct addrinfo hints, *res = NULL;
				memset(&hints, 0, sizeof(hints));
				hints.ai_socktype = SOCK_STREAM;
				hints.ai_family = AF_INET;
				hints.ai_protocol = IPPROTO_TCP;

				int err = getaddrinfo((const char*)cfg->http_dyndns, NULL, &hints, &res);
				if (err != 0 || !res || !res->ai_addr) {
					cs_log("can't resolve %s, error: %s", cfg->http_dyndns, err ? gai_strerror(err) : "unknown");
				}
				else {
					cfg->http_dynip = cs_inet_order(((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr);
					cs_debug_mask(D_TRACE, "WebIf: dynip resolved %s access from %s",
							inet_ntoa(*(struct in_addr *)&cfg->http_dynip),
							inet_ntoa(*(struct in_addr *)&addr));
					if (cfg->http_dynip == addr)
						ok = v;
				}
				if (res) freeaddrinfo(res);

			}
		}
	}

	if (!ok) {
		send_error(f, 403, "Forbidden", NULL, "Access denied.");
		cs_log("unauthorized access from %s flag %d", inet_ntoa(*(struct in_addr *)&in), v);
		return 0;
	}

	int authok = 0;
	char expectednonce[64];

	char *method, *path, *protocol;
	char *pch, *tmp;
	/* List of possible pages */
	char *pages[]= {
		"/config.html",
		"/readers.html",
		"/entitlements.html",
		"/status.html",
		"/userconfig.html",
		"/readerconfig.html",
		"/services.html",
		"/user_edit.html",
		"/site.css",
		"/services_edit.html",
		"/savetemplates.html",
		"/shutdown.html",
		"/script.html",
		"/scanusb.html",
		"/files.html",
		"/readerstats.html",
		"/failban.html",
		"/oscam.js",
		"/oscamapi.html"};

	int pagescnt = sizeof(pages)/sizeof(char *); // Calculate the amount of items in array

	int pgidx = -1;
	int i;
	struct uriparams params;
	params.paramcount = 0;

	/* First line always includes the GET/POST request */
	char *saveptr1=NULL;
	int n, bufsize=0;
	char *filebuf = NULL;
	char buf2[1024];
	struct pollfd pfd2[1];

	while (1) {
		if ((n=webif_read(buf2, sizeof(buf2), f)) <= 0) {
			cs_debug_mask(D_CLIENT, "webif read error %d", n);
#ifdef WITH_SSL
			if (cfg->http_use_ssl)
				ERR_print_errors_fp(stderr);
#endif
			return -1;
		}

		filebuf = realloc(filebuf, bufsize+n+1);

		memcpy(filebuf+bufsize, buf2, n);
		bufsize+=n;

		//max request size 100kb
		if (bufsize>102400) {
			cs_log("error: too much data received from %s", inet_ntoa(*(struct in_addr *)&in));
			free(filebuf);
			return -1;
		}

#ifdef WITH_SSL
		if (cfg->http_use_ssl) {
			int len = 0;
			len = SSL_pending((SSL*)f);

			if (len>0)
				continue;

			pfd2[0].fd = SSL_get_fd((SSL*)f);

		} else
#endif
			pfd2[0].fd = fileno(f);

		pfd2[0].events = (POLLIN | POLLPRI);

		int rc = poll(pfd2, 1, 100);
		if (rc>0)
			continue;

		break;
	}

	if (!filebuf) {
		cs_log("error: no data received");
		return -1;
	}

	filebuf[bufsize]='\0';
	char *buf=filebuf;

	method = strtok_r(buf, " ", &saveptr1);
	path = strtok_r(NULL, " ", &saveptr1);
	protocol = strtok_r(NULL, "\r", &saveptr1);
	if(method == NULL || path == NULL || protocol == NULL) return -1;
	tmp=protocol+strlen(protocol)+2;

	pch=path;
	/* advance pointer to beginning of query string */
	while(pch[0] != '?' && pch[0] != '\0') ++pch;
	if(pch[0] == '?') {
		pch[0] = '\0';
		++pch;
	}

	/* Map page to our static page definitions */
	for (i=0; i<pagescnt; i++) {
		if (!strcmp(path, pages[i])) pgidx = i;
	}

	webif_parse_request(&params, pch);

	if(strlen(cfg->http_user) == 0 || strlen(cfg->http_pwd) == 0) authok = 1;
	else calculate_nonce(expectednonce, sizeof(expectednonce)/sizeof(char));

	char *str1, *saveptr=NULL;

	for (str1=strtok_r(tmp, "\n", &saveptr); str1; str1=strtok_r(NULL, "\n", &saveptr)) {
		if (strlen(str1)==1) {
			if (strcmp(method, "POST")==0) {
				webif_parse_request(&params, str1+2);
			}
			break;
		}
		if(authok == 0 && strlen(str1) > 50 && strncmp(str1, "Authorization:", 14) == 0 && strstr(str1, "Digest") != NULL) {
			authok = check_auth(str1, method, path, expectednonce);
		}
	}

	if(authok != 1) {
		char temp[1024];
		strcpy(temp, "WWW-Authenticate: Digest algorithm=\"MD5\", realm=\"");
		strcat(temp, AUTHREALM);
		strcat(temp, "\", qop=\"auth\", opaque=\"\", nonce=\"");
		strcat(temp, expectednonce);
		strcat(temp, "\"");
		if(authok == 2) strcat(temp, ", stale=true");
		send_headers(f, 401, "Unauthorized", temp, "text/html");
		free(filebuf);
		return 0;
	}

	/*build page*/
	if(pgidx == 8) {
		send_headers(f, 200, "OK", NULL, "text/css");
		send_file(f, 1);
	} else if (pgidx == 17) {
		send_headers(f, 200, "OK", NULL, "text/javascript");
		send_file(f, 2);
	} else {
		if (pgidx == 18)
			send_headers(f, 200, "OK", NULL, "text/xml");
		else
			send_headers(f, 200, "OK", NULL, "text/html");
		time_t t;
		struct templatevars *vars = tpl_create();
		struct tm *lt;
		struct tm *st;
		time(&t);

		lt = localtime(&t);

		tpl_addVar(vars, 0, "CS_VERSION", CS_VERSION);
		tpl_addVar(vars, 0, "CS_SVN_VERSION", CS_SVN_VERSION);
		tpl_addVar(vars, 0, "ICO", ICMAI);
		if(cfg->http_refresh > 0 && (pgidx == 3 || pgidx == -1)) {
			tpl_printf(vars, 0, "REFRESHTIME", "%d", cfg->http_refresh);
			tpl_addVar(vars, 0, "REFRESHURL", "status.html");
			tpl_addVar(vars, 0, "REFRESH", tpl_getTpl(vars, "REFRESH"));
		}

		if (cfg->http_js_icons && (pgidx == -1 || pgidx == 1 || pgidx == 3 || pgidx == 4 || pgidx == 6 || pgidx == 16)) {
			tpl_printf(vars, 0, "ICONS", "var ICSTA =\"%s\";\n", ICSTA);
			tpl_printf(vars, 1, "ICONS", "var ICDEL =\"%s\";\n", ICDEL);
			tpl_printf(vars, 1, "ICONS", "var ICEDI =\"%s\";\n", ICEDI);
			tpl_printf(vars, 1, "ICONS", "var ICENT =\"%s\";\n", ICENT);
			tpl_printf(vars, 1, "ICONS", "var ICREF =\"%s\";\n", ICREF);
			tpl_printf(vars, 1, "ICONS", "var ICKIL =\"%s\";\n", ICKIL);
			tpl_printf(vars, 1, "ICONS", "var ICDIS =\"%s\";\n", ICDIS);
			tpl_printf(vars, 1, "ICONS", "var ICENA =\"%s\";\n", ICENA);
			tpl_printf(vars, 1, "ICONS", "var ICHID =\"%s\";\n", ICHID);
			tpl_printf(vars, 1, "ICONS", "var ICRES =\"%s\";\n", ICRES);
			tpl_addVar(vars, 0, "ONLOADSCRIPT", " onload=\"load_Icons()\"");
		}

		tpl_printf(vars, 0, "CURDATE", "%02d.%02d.%02d", lt->tm_mday, lt->tm_mon+1, lt->tm_year%100);
		tpl_printf(vars, 0, "CURTIME", "%02d:%02d:%02d", lt->tm_hour, lt->tm_min, lt->tm_sec);
		st = localtime(&first_client->login);
		tpl_printf(vars, 0, "STARTDATE", "%02d.%02d.%02d", st->tm_mday, st->tm_mon+1, st->tm_year%100);
		tpl_printf(vars, 0, "STARTTIME", "%02d:%02d:%02d", st->tm_hour, st->tm_min, st->tm_sec);
		tpl_printf(vars, 0, "PROCESSID", "%d", server_pid);

		char tbuffer [30];
		strftime(tbuffer, 30, "%Y-%m-%dT%H:%M:%S%z", st);
		tpl_printf(vars, 0, "APISTARTTIME", "%s", tbuffer);// XMLAPI

		time_t now = time((time_t)0);
		tpl_printf(vars, 0, "APIUPTIME", "%u", now - first_client->login);// XMLAPI

		int lsec = now - first_client->login;
		int secs = 0, fullmins = 0, mins = 0, fullhours = 0, hours = 0, days = 0;
		if(lsec > 0) {
			secs = lsec % 60;
			if (lsec > 60) {
				fullmins = lsec / 60;
				mins = fullmins % 60;
				if(fullmins > 60) {
					fullhours = fullmins / 60;
					hours = fullhours % 24;
					days = fullhours / 24;
				}
			}
		}
		if(days == 0)
			tpl_printf(vars, 0, "UPTIME", "%02d:%02d:%02d", hours, mins, secs);
		else
			tpl_printf(vars, 0, "UPTIME", "%02dd %02d:%02d:%02d", days, hours, mins, secs);

		tpl_printf(vars, 0, "CURIP", "%s", inet_ntoa(*(struct in_addr *)&in));
		if(cfg->http_readonly)
			tpl_addVar(vars, 1, "BTNDISABLED", "DISABLED");

		switch(pgidx) {
			case 0: send_oscam_config(vars, f, &params, in); break;
			case 1: send_oscam_reader(vars, f, &params, in); break;
			case 2: send_oscam_entitlement(vars, f, &params, in, 0); break;
			case 3: send_oscam_status(vars, f, &params, in, 0); break;
			case 4: send_oscam_user_config(vars, f, &params, in); break;
			case 5: send_oscam_reader_config(vars, f, &params, in); break;
			case 6: send_oscam_services(vars, f, &params, in); break;
			case 7: send_oscam_user_config_edit(vars, f, &params, in); break;
			//case  8: css file
			case 9: send_oscam_services_edit(vars, f, &params, in); break;
			case 10: send_oscam_savetpls(vars, f); break;
			case 11: send_oscam_shutdown(vars, f, &params); break;
			case 12: send_oscam_script(vars, f); break;
			case 13: send_oscam_scanusb(vars, f); break;
			case 14: send_oscam_files(vars, f, &params); break;
			case 15: send_oscam_reader_stats(vars, f, &params, in, 0); break;
			case 16: send_oscam_failban(vars, f, &params); break;
			//case  17: js file
			case 18: send_oscam_api(vars, f, &params, in); break;
			default: send_oscam_status(vars, f, &params, in, 0); break;
		}
		tpl_clear(vars);
	}
	free(filebuf);
	return 0;
}

#ifdef WITH_SSL
SSL_CTX *webif_init_ssl() {
	SSL_library_init();
	SSL_load_error_strings();

	SSL_METHOD *meth;
	SSL_CTX *ctx;

	static const char *cs_cert="oscam.pem";
 
	meth = SSLv23_server_method();
 
	ctx = SSL_CTX_new(meth);

	char path[128];

	if (cfg->http_cert[0]==0)
		sprintf(path, "%s%s", cs_confdir, cs_cert);
	else
		strcpy(path, cfg->http_cert);

	if (!ctx) {
		ERR_print_errors_fp(stderr);
		return NULL;
       }

	if (SSL_CTX_use_certificate_file(ctx, path, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}
 
	if (SSL_CTX_use_PrivateKey_file(ctx, path, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}
 
       if (!SSL_CTX_check_private_key(ctx)) {
		cs_log("SSL: Private key does not match the certificate public key");
		return NULL;
	}
	cs_log("load ssl certificate file %s", path);
	return ctx;
}
#endif

void http_srv() {
	struct s_client * cl = cs_fork(first_client->ip);
	if (cl == NULL) return;
	cl->thread = pthread_self();
	pthread_setspecific(getclient, cl);
	cl->typ = 'h';
	int i,sock, reuse = 1;
	struct sockaddr_in sin;
	struct sockaddr_in remote;
	socklen_t len = sizeof(remote);
	char *tmp;

	/* Prepare lookup array for conversion between ascii and hex */
	tmp = malloc(3 * sizeof(char));
	for(i = 0; i < 256; i++) {
		snprintf(tmp, 3,"%02x", i);
		memcpy(hex2ascii[i], tmp, 2);
	}
	free(tmp);
	/* Create random string for nonce value generation */
	srand(time(NULL));
	create_rand_str(noncekey,32);

	/* Startup server */
	if((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		cs_log("HTTP Server: Creating socket failed! (errno=%d)", errno);
		return;
	}
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
		cs_log("HTTP Server: Setting SO_REUSEADDR via setsockopt failed! (errno=%d)", errno);
	}

	memset(&sin, 0, sizeof sin);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(cfg->http_port);
	if((bind(sock, (struct sockaddr *) &sin, sizeof(sin))) < 0) {
		cs_log("HTTP Server couldn't bind on port %d (errno=%d). Not starting HTTP!", cfg->http_port, errno);
		close(sock);
		return;
	}
	if (listen(sock, SOMAXCONN) < 0) {
		cs_log("HTTP Server: Call to listen() failed! (errno=%d)", errno);
		close(sock);
		return;
	}
	cs_log("HTTP Server listening on port %d%s", cfg->http_port, cfg->http_use_ssl ? " (SSL)" : "");
	struct pollfd pfd2[1];
	int rc;
	pfd2[0].fd = sock;
	pfd2[0].events = (POLLIN | POLLPRI);

#ifdef WITH_SSL
	SSL_CTX *ctx = NULL;
	if (cfg->http_use_ssl)
		ctx = webif_init_ssl();

	if (ctx==NULL)
		cfg->http_use_ssl = 0;
#endif

	while (running) {
		int s;

		rc = poll(pfd2, 1, 1000);

		if (rc > 0) {
			if((s = accept(sock, (struct sockaddr *) &remote, &len)) < 0) {
				cs_log("HTTP Server: Error calling accept() (errno=%d).", errno);
				break;
			}
#ifdef WITH_SSL
			if (cfg->http_use_ssl) {
				SSL *ssl;
				ssl = SSL_new(ctx);
				SSL_set_fd(ssl, s);
				if (SSL_accept(ssl) != -1)
					process_request((FILE *)ssl, remote.sin_addr);
				else {
					cfg->http_use_ssl=0;
					FILE *f;
					f = fdopen(s, "r+");
					send_error(f, 200, "Bad Request", NULL, "This web server is running in SSL mode.");
					fclose(f);
					cfg->http_use_ssl=1;
				}
				SSL_shutdown(ssl);
				close(s);
				SSL_free(ssl);
			} else
#endif
			{
				FILE *f;
				f = fdopen(s, "r+");
				process_request(f, remote.sin_addr);
				fflush(f);
				fclose(f);
				shutdown(s, SHUT_WR);
				close(s);
			}
		}
	}
#ifdef WITH_SSL
	if (cfg->http_use_ssl)
		SSL_CTX_free(ctx);
#endif
	cs_log("HTTP Server: Shutdown requested from %s", inet_ntoa(*(struct in_addr *)&remote.sin_addr));
	close(sock);
	//exit(SIGQUIT);
}
#endif
