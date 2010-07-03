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

extern struct s_reader *reader;

static int running = 1;
static struct s_auth 	*fork_account; //hold the initial pointer

void refresh_oscam(enum refreshtypes refreshtype, struct in_addr in) {
	int i;
	switch (refreshtype) {
		case REFR_ACCOUNTS:
		cs_log("Refresh Accounts requested by WebIF from %s", inet_ntoa(*(struct in_addr *)&in));
		kill(client[0].pid, SIGHUP);
		init_userdb(&fork_account);
#ifdef CS_ANTICASC
		for (i=0; i<CS_MAXPID; i++)
		if (client[i].typ=='a') {
			kill(client[i].pid, SIGHUP);
			break;
		}
#endif
		break;

		case REFR_READERS:
		kill(client[0].pid, SIGUSR2);
		cs_log("Refresh Reader/Tiers requested by WebIF from %s", inet_ntoa(*(struct in_addr *)&in));
		break;

		case REFR_SERVER:
		cs_log("Refresh Server requested by WebIF from %s", inet_ntoa(*(struct in_addr *)&in));
		//kill(client[0].pid, SIGHUP);
		//todo how I can refresh the server after global settings
		break;

		case REFR_SERVICES:
		cs_log("Refresh Services requested by WebIF from %s", inet_ntoa(*(struct in_addr *)&in));
		//init_sidtab();
		kill(client[0].pid, SIGHUP);
		break;

#ifdef CS_ANTICASC
		case REFR_ANTICASC:
		cs_log("Refresh Anticascading requested by WebIF from %s", inet_ntoa(*(struct in_addr *)&in));
		for (i=0; i<CS_MAXPID; i++)
		if (client[i].typ=='a') {
			kill(client[i].pid, SIGHUP);
			break;
		}
		break;
#endif
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
	if (cfg->pidfile != NULL) tpl_addVar(vars, 0, "PIDFILE", cfg->pidfile);
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
	if (cfg->reader_auto_loadbalance)
		tpl_addVar(vars, 0, "READERAUTOLOADBALANCE", "checked");


	fputs(tpl_getTpl(vars, "CONFIGGLOBAL"), f);
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

	fputs(tpl_getTpl(vars, "CONFIGCAMD33"), f);
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
		if (cfg->c35_tcp_srvip != 0)
			tpl_addVar(vars, 1, "SERVERIP", inet_ntoa(*(struct in_addr *)&cfg->c35_tcp_srvip));

		if (cfg->c35_suppresscmd08)
			tpl_addVar(vars, 0, "SUPPRESSCMD08", "checked");
	}
	fputs(tpl_getTpl(vars, "CONFIGCAMD35"), f);
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

		//SUPPRESSCMD08
		if (cfg->c35_suppresscmd08)
			tpl_addVar(vars, 0, "SUPPRESSCMD08", "checked");
	}
	fputs(tpl_getTpl(vars, "CONFIGCAMD35TCP"), f);
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
	int j;
	char *dot1, *dot2;
	if ((cfg->ncd_ptab.nports > 0) && (cfg->ncd_ptab.ports[0].s_port > 0)) {
		dot1 = "";
		for(i = 0; i < cfg->ncd_ptab.nports; ++i) {
			tpl_printf(vars, 1, "PORT", "%s%d@%04X", dot1, cfg->ncd_ptab.ports[i].s_port, cfg->ncd_ptab.ports[i].ftab.filts[0].caid);

			if (cfg->ncd_ptab.ports[i].ftab.filts[0].nprids > 1) {
				tpl_printf(vars, 1, "PORT", ":");
				dot2 = "";
				for (j = 0; j < cfg->ncd_ptab.ports[i].ftab.filts[0].nprids; ++j) {
					tpl_printf(vars, 1, "PORT", "%s%06X", dot2, cfg->ncd_ptab.ports[i].ftab.filts[0].prids[j]);
					dot2 = ",";
				}
			}
			dot1=";";
		}


		if (cfg->ncd_srvip != 0)
			tpl_addVar(vars, 0, "SERVERIP", inet_ntoa(*(struct in_addr *)&cfg->ncd_srvip));

		for (i=0;i<14;i++) tpl_printf(vars, 1, "KEY", "%02X", cfg->ncd_key[i]);

		struct s_ip *cip;
		char *dot="";
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
	fputs(tpl_getTpl(vars, "CONFIGNEWCAMD"), f);
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
		if (cip->ip[0] != cip->ip[1]) tpl_printf(vars, 1, "ALLOWED", "-%s", cs_inet_ntoa(cip->ip[1]));
		dot=",";
	}

	fputs(tpl_getTpl(vars, "CONFIGRADEGAST"), f);
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
	}

	fputs(tpl_getTpl(vars, "CONFIGCCCAM"), f);
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
	fputs(tpl_getTpl(vars, "CONFIGGBOX"), f);
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
	tpl_printf(vars, 0, "HTTPPORT", "%d", cfg->http_port);
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

	fputs(tpl_getTpl(vars, "CONFIGMONITOR"), f);
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
		tpl_addVar(vars, 1, "MESSAGE", "<BR><BR><B>Configuration Monitor done. You should restart Oscam now.</B><BR><BR>");
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

	fputs(tpl_getTpl(vars, "CONFIGSERIAL"), f);
}

#ifdef HAVE_DVBAPI
void send_oscam_config_dvbapi(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in) {
	int i;
	if (strcmp(getParam(params, "action"),"execute") == 0) {
		//clear tables
		clear_caidtab(&cfg->dvbapi_prioritytab);
		clear_caidtab(&cfg->dvbapi_ignoretab);
		clear_caidtab(&cfg->dvbapi_delaytab);
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

	i = 0;
	char *dot = "";
	while(cfg->dvbapi_prioritytab.caid[i]) {
		tpl_printf(vars, 1, "PRIORITY", "%s%04X", dot, cfg->dvbapi_prioritytab.caid[i]);
		if(cfg->dvbapi_prioritytab.mask[i])
			tpl_printf(vars, 1, "PRIORITY", ":%06lX", cfg->dvbapi_prioritytab.mask[i]);
		dot = ",";
		i++;
	}

	i = 0;
	dot = "";
	while(cfg->dvbapi_ignoretab.caid[i]) {
		tpl_printf(vars, 1, "IGNORE", "%s%04X", dot, cfg->dvbapi_ignoretab.caid[i]);
		if(cfg->dvbapi_ignoretab.mask[i])
			tpl_printf(vars, 1, "IGNORE", ":%06lX", cfg->dvbapi_ignoretab.mask[i]);
		dot = ",";
		i++;
	}

	i = 0;
	dot = "";
	while(cfg->dvbapi_delaytab.caid[i]) {
		tpl_printf(vars, 1, "CWDELAY", "%s%04X", dot, cfg->dvbapi_delaytab.caid[i]);
		tpl_printf(vars, 1, "CWDELAY", ":%d", cfg->dvbapi_delaytab.mask[i]);
		dot = ",";
		i++;
	}

	fputs(tpl_getTpl(vars, "CONFIGDVBAPI"), f);
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
	fputs(tpl_getTpl(vars, "CONFIGANTICASC"), f);
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
	else send_oscam_config_global(vars, f, params, in);
}

void send_oscam_reader(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in) {
	int readeridx, isphysical = 0;
	char *ctyp;
	int i;
	//uchar dummy[1]={0x00};

	if (strcmp(getParam(params, "action"), "delete") == 0) {
		reader[atoi(getParam(params, "reader"))].deleted = 1;
		if(write_server()==0) {
			refresh_oscam(REFR_READERS, in);
			//printf("would kill now PID %d\n", reader[atoi(getParam(params, "reader"))].pid);
			if(reader[atoi(getParam(params, "reader"))].pid)
				kill(reader[atoi(getParam(params, "reader"))].pid, SIGQUIT);
		}
		else
			tpl_addVar(vars, 1, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}

	if (strcmp(getParam(params, "action"), "reread") == 0) {
		readeridx = atoi(getParam(params, "ridx"));
		//reset the counters
		for (i = 0; i < 4; i++) {
			reader[readeridx].emmerror[i] = 0;
			reader[readeridx].emmwritten[i] = 0;
			reader[readeridx].emmskipped[i] = 0;
			reader[readeridx].emmblocked[i] = 0;
		}
		//write_to_pipe(client[reader[readeridx].cs_idx)].fd_m2c, PIP_ID_CIN, dummy, 1); // do not work for whatever reason
		refresh_oscam(REFR_READERS, in); // refresh all reader because  write pipe seams not work from here
	}

	for(readeridx = 0; readeridx < CS_MAXREADER && reader[readeridx].label[0]; readeridx++);
	tpl_printf(vars, 0, "NEXTREADER", "Reader-%d", readeridx); //Next Readername

	for(readeridx = 0; readeridx < CS_MAXREADER; readeridx++) {
		isphysical = 0;

		if(reader[readeridx].label[0] && reader[readeridx].typ && !reader[readeridx].deleted) {

			tpl_printf(vars, 0, "READERIDX", "%d", readeridx);
			tpl_addVar(vars, 0, "READERNAME", reader[readeridx].label);
			tpl_addVar(vars, 0, "READERNAMEENC", tpl_addTmp(vars, urlencode(reader[readeridx].label)));

			switch(reader[readeridx].typ) {
			case R_MOUSE :
				ctyp = "mouse";
				isphysical = 1;
				break;
			case R_INTERNAL:
				ctyp = "intern";
				isphysical = 1;
				break;
			case R_SMART :
				ctyp = "smartreader";
				isphysical = 1;
				break;
			case R_SERIAL :
				ctyp = "serial";
				isphysical = 1;
				break;
			case R_DB2COM1 :
				ctyp = "dbox COM1";
				isphysical = 1;
				break;
			case R_DB2COM2 :
				ctyp = "dbox COM2";
				isphysical = 1;
				break;
			case R_CAMD35 : ctyp="camd 3.5x";break;
			case R_CAMD33 : ctyp="camd 3.3x";break;
			case R_NEWCAMD : ctyp="newcamd"; break;
			case R_RADEGAST: ctyp="radegast"; break;
#ifdef CS_WITH_GBOX
			case R_GBOX : ctyp="gbox"; break;
#endif
#ifdef HAVE_PCSC
			case R_PCSC :
				ctyp="pcsc";
				isphysical = 1;
				break;
#endif
			case R_CCCAM : ctyp="cccam"; break;
			case R_CS378X : ctyp="cs378x"; break;
			default : ctyp="unknown"; break;
			}

			tpl_printf(vars, 0, "EMMERRORUK", "%d", reader[readeridx].emmerror[UNKNOWN]);
			tpl_printf(vars, 0, "EMMERRORG", "%d", reader[readeridx].emmerror[GLOBAL]);
			tpl_printf(vars, 0, "EMMERRORS", "%d", reader[readeridx].emmerror[SHARED]);
			tpl_printf(vars, 0, "EMMERRORUQ", "%d", reader[readeridx].emmerror[UNIQUE]);

			tpl_printf(vars, 0, "EMMWRITTENUK", "%d", reader[readeridx].emmwritten[UNKNOWN]);
			tpl_printf(vars, 0, "EMMWRITTENG", "%d", reader[readeridx].emmwritten[GLOBAL]);
			tpl_printf(vars, 0, "EMMWRITTENS", "%d", reader[readeridx].emmwritten[SHARED]);
			tpl_printf(vars, 0, "EMMWRITTENUQ", "%d", reader[readeridx].emmwritten[UNIQUE]);

			tpl_printf(vars, 0, "EMMSKIPPEDUK", "%d", reader[readeridx].emmskipped[UNKNOWN]);
			tpl_printf(vars, 0, "EMMSKIPPEDG", "%d", reader[readeridx].emmskipped[GLOBAL]);
			tpl_printf(vars, 0, "EMMSKIPPEDS", "%d", reader[readeridx].emmskipped[SHARED]);
			tpl_printf(vars, 0, "EMMSKIPPEDUQ", "%d", reader[readeridx].emmskipped[UNIQUE]);

			tpl_printf(vars, 0, "EMMBLOCKEDUK", "%d", reader[readeridx].emmblocked[UNKNOWN]);
			tpl_printf(vars, 0, "EMMBLOCKEDG", "%d", reader[readeridx].emmblocked[GLOBAL]);
			tpl_printf(vars, 0, "EMMBLOCKEDS", "%d", reader[readeridx].emmblocked[SHARED]);
			tpl_printf(vars, 0, "EMMBLOCKEDUQ", "%d", reader[readeridx].emmblocked[UNIQUE]);

			tpl_addVar(vars, 0, "DELICO", ICDEL);

			if (isphysical == 1) {
				tpl_printf(vars, 0, "RIDX", "%d", readeridx);
				tpl_addVar(vars, 0, "REFRICO", ICREF);
				tpl_addVar(vars, 0, "READERREFRESH", tpl_getTpl(vars, "READERREFRESHBIT"));

				tpl_addVar(vars, 0, "ENTICO", ICENT);
				tpl_addVar(vars, 0, "ENTITLEMENT", tpl_getTpl(vars, "READERENTITLEBIT"));

			} else {
				tpl_printf(vars, 0, "RIDX", "");
				tpl_addVar(vars, 0, "READERREFRESH","");
				if (reader[readeridx].typ == R_CCCAM) {
					tpl_addVar(vars, 0, "ENTICO", ICENT);
					tpl_addVar(vars, 0, "ENTITLEMENT", tpl_getTpl(vars, "READERENTITLEBIT"));
				} else {
					tpl_addVar(vars, 0, "ENTITLEMENT","");
				}

			}

			tpl_addVar(vars, 0, "CTYP", ctyp);
			tpl_addVar(vars, 0, "EDIICO", ICEDI);
			tpl_addVar(vars, 1, "READERLIST", tpl_getTpl(vars, "READERSBIT"));
		}
	}
	fputs(tpl_getTpl(vars, "READERS"), f);
}

void send_oscam_reader_config(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in) {
	int i, ridx=0;
	char *reader_ = getParam(params, "reader");
	char *value;

	for(ridx = 0; ridx < CS_MAXREADER && reader[ridx].label[0]; ridx++); //last reader

	if(strcmp(getParam(params, "action"), "Add") == 0) {
		// Add new reader
		memset(&reader[ridx], 0, sizeof(struct s_reader));
		reader[ridx].enable = 1;
		reader[ridx].tcp_rto = 30;
		reader[ridx].show_cls = 10;
		reader[ridx].maxqlen = CS_MAXQLEN;
		reader[ridx].mhz = 357;
		reader[ridx].cardmhz = 357;
		reader[ridx].deprecated = 0;
		reader[ridx].cachecm = 1;
		strcpy(reader[ridx].pincode, "none");
		for (i = 1; i < CS_MAXCAIDTAB; reader[ridx].ctab.mask[i++] = 0xffff);
		for (i = 0; i < (*params).paramcount; ++i) {
			if (strcmp((*params).params[i], "action"))
				chk_reader((*params).params[i], (*params).values[i], &reader[ridx]);
		}
		reader_ = reader[ridx].label;

	} else if(strcmp(getParam(params, "action"), "Save") == 0) {
		for(ridx = 0; ridx < CS_MAXREADER && strcmp(reader_, reader[ridx].label) != 0; ++ridx);
		char servicelabels[255]="";
		clear_caidtab(&reader[ridx].ctab);
		clear_ftab(&reader[ridx].ftab);
		for(i = 0; i < (*params).paramcount; ++i) {
			if ((strcmp((*params).params[i], "reader")) && (strcmp((*params).params[i], "action"))) {
				if (!strcmp((*params).params[i], "services"))
					snprintf(servicelabels + strlen(servicelabels), sizeof(servicelabels), "%s,", (*params).values[i]);
				else
					chk_reader((*params).params[i], (*params).values[i], &reader[ridx]);
			}
		}
		chk_reader("services", servicelabels, &reader[ridx]);
		if(write_server()==0) refresh_oscam(REFR_READERS, in);
		else tpl_addVar(vars, 1, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}

	for(ridx = 0; ridx < CS_MAXREADER && strcmp(reader_, reader[ridx].label) != 0; ++ridx);

	tpl_addVar(vars, 0, "READERNAME", reader[ridx].label);
	if(reader[ridx].enable)
		tpl_addVar(vars, 0, "ENABLED", "checked");

	tpl_printf(vars, 0, "ACCOUNT",  "%s,%s\n", reader[ridx].r_usr, reader[ridx].r_pwd);
	for (i=0; i<14; i++) tpl_printf(vars, 1, "NCD_KEY", "%02X", reader[ridx].ncd_key[i]);
	tpl_addVar(vars, 0, "PINCODE", reader[ridx].pincode);
	//tpl_addVar(vars, 0, "EMMFILE", (char *)reader[ridx].emmfile);
	tpl_printf(vars, 0, "INACTIVITYTIMEOUT", "%d", reader[ridx].tcp_ito);
	tpl_printf(vars, 0, "RECEIVETIMEOUT", "%d", reader[ridx].tcp_rto);
	tpl_printf(vars, 0, "DISABLESERVERFILTER", "%d", reader[ridx].ncd_disable_server_filt);
	if(reader[ridx].fallback)
		tpl_addVar(vars, 0, "FALLBACKCHECKED", "checked");
	tpl_printf(vars, 0, "LOGPORT", "%d", reader[ridx].log_port);
	tpl_printf(vars, 0, "BOXID", "%08X", reader[ridx].boxid);
	tpl_addVar(vars, 0, "USER", reader[ridx].r_usr);
	tpl_addVar(vars, 0, "PASS", reader[ridx].r_pwd);

	if(reader[ridx].force_irdeto)
		tpl_addVar(vars, 0, "FORCEIRDETOCHECKED", "checked");

	if(reader[ridx].has_rsa) {
		for (i = 0; i < 64; i++) tpl_printf(vars, 1, "RSAKEY", "%02X", reader[ridx].rsa_mod[i]);
		for (i = 0; i < 8 ; i++) tpl_printf(vars, 1, "BOXKEY", "%02X", reader[ridx].nagra_boxkey[i]);
	}
	if ( reader[ridx].atr[0])
		for (i = 0; i < reader[ridx].atrlen/2; i++)
			tpl_printf(vars, 1, "ATR", "%02X", reader[ridx].atr[i]);

	if(reader[ridx].smargopatch)
		tpl_addVar(vars, 0, "SMARGOPATCHCHECKED", "checked");

	if (reader[ridx].detect&0x80)
		tpl_printf(vars, 0, "DETECT", "!%s", RDR_CD_TXT[reader[ridx].detect&0x7f]);
	else
		tpl_printf(vars, 0, "DETECT", "%s", RDR_CD_TXT[reader[ridx].detect&0x7f]);

	tpl_printf(vars, 0, "MHZ", "%d", reader[ridx].mhz);
	tpl_printf(vars, 0, "CARDMHZ", "%d", reader[ridx].cardmhz);

#ifdef CS_WITH_GBOX
	tpl_addVar(vars, 0, "GBOXPWD", (char *)reader[ridx].gbox_pwd);
	tpl_addVar(vars, 0, "PREMIUM", reader[ridx].gbox_prem);
#endif

	tpl_printf(vars, 0, "DEVICE", "%s", reader[ridx].device);
	if(reader[ridx].r_port)
		tpl_printf(vars, 1, "DEVICE", ",%d", reader[ridx].r_port);
	if(reader[ridx].l_port) {
		if(reader[ridx].r_port)
			tpl_printf(vars, 1, "DEVICE", ",%d", reader[ridx].l_port);
		else
			tpl_printf(vars, 1, "DEVICE", ",,%d", reader[ridx].l_port);
	}

	//group
	value = mk_t_group((ulong*)reader[ridx].grp);
	tpl_printf(vars, 0, "GRP", "%s", value);
	free(value);

	if(reader[ridx].lb_weight)
		tpl_printf(vars, 0, "LBWEIGHT", "%d", reader[ridx].lb_weight);

	//services
	char sidok[33];
	long2bitchar(reader[ridx].sidtabok, sidok);
	char sidno[33];
	long2bitchar(reader[ridx].sidtabno,sidno);
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
	value = mk_t_caidtab(&reader[ridx].ctab);
	tpl_addVar(vars, 0, "CAIDS", value);
	free(value);

	//ident
	value = mk_t_ftab(&reader[ridx].ftab);
	tpl_printf(vars, 0, "IDENTS", "%s\n", value);
	free(value);

	//class
	CLASSTAB *clstab = &reader[ridx].cltab;
	char *dot="";
	for(i = 0; i < clstab->an; ++i) {
		tpl_printf(vars, 1, "CLASS", "%s%02x", dot, (int)clstab->aclass[i]);
		dot=",";
	}
	for(i = 0; i < clstab->bn; ++i) {
		tpl_printf(vars, 0, "CLASS", "%s!%02x", dot, (int)clstab->bclass[i]);
		dot=",";
	}

	//chid
	int j;
	dot="";
	FTAB *ftab = &reader[ridx].fchid;
	for (i = 0; i < ftab->nfilts; ++i) {
		tpl_printf(vars, 1, "CHIDS", "%s%04X", dot, ftab->filts[i].caid);
		dot=":";
		for (j = 0; j < ftab->filts[i].nprids; ++j) {
			tpl_printf(vars, 1, "CHIDS", "%s%06lX", dot, ftab->filts[i].prids[j]);
			dot=",";
		}
		dot=";";
	}

	tpl_printf(vars, 0, "SHOWCLS", "%d", reader[ridx].show_cls);
	tpl_printf(vars, 0, "MAXQLEN", "%d", reader[ridx].maxqlen);

	if(reader[ridx].cachemm)
		tpl_printf(vars, 0, "EMMCACHE", "%d,%d,%d", reader[ridx].cachemm, reader[ridx].rewritemm, reader[ridx].logemm);

	//savenano
	int all = 1;
	dot="";
	for(i = 0; i < 256; ++i) {
		if(!(reader[ridx].b_nano[i] & 0x02)) {
			all = 0;
			break;
		}
	}
	if (all == 1) tpl_addVar(vars, 0, "SAVENANO", "all");
	else {
		for(i = 0; i < 256; ++i) {
			if(reader[ridx].b_nano[i] & 0x02) tpl_printf(vars, 1, "SAVENANO", "%s%02x\n", dot, i);
			dot=",";
		}
	}

	//blocknano
	dot="";
	for(i = 0; i < 256; ++i) {
		if(!(reader[ridx].b_nano[i] & 0x01)) {
			all = 0;
			break;
		}
	}
	if (all == 1) tpl_addVar(vars, 0, "BLOCKNANO", "all");
	else {
		for(i = 0; i < 256; ++i) {
			if(reader[ridx].b_nano[i] & 0x01) tpl_printf(vars, 1, "BLOCKNANO", "%s%02x\n", dot, i);
			dot=",";
		}
	}

	if (reader[ridx].cachecm)
		tpl_addVar(vars, 0, "ECMCACHECHECKED", "checked");

	if (reader[ridx].blockemm_unknown)
		tpl_addVar(vars, 0, "BLOCKEMMUNKNOWNCHK", "checked");
	if (reader[ridx].blockemm_u)
		tpl_addVar(vars, 0, "BLOCKEMMUNIQCHK", "checked");
	if (reader[ridx].blockemm_s)
		tpl_addVar(vars, 0, "BLOCKEMMSHAREDCHK", "checked");
	if (reader[ridx].blockemm_g)
		tpl_addVar(vars, 0, "BLOCKEMMGLOBALCHK", "checked");

	if (reader[ridx].deprecated)
		tpl_addVar(vars, 0, "DEPRECATEDCHCHECKED", "checked");

	if (!strcmp(reader[ridx].cc_version, "2.0.11")) {
		tpl_addVar(vars, 0, "CCCVERSIONSELECTED0", "selected");
	} else if (!strcmp(reader[ridx].cc_version, "2.1.1")) {
		tpl_addVar(vars, 0, "CCCVERSIONSELECTED1", "selected");
	} else if (!strcmp(reader[ridx].cc_version, "2.1.2")) {
		tpl_addVar(vars, 0, "CCCVERSIONSELECTED2", "selected");
	} else if (!strcmp(reader[ridx].cc_version, "2.1.3")) {
		tpl_addVar(vars, 0, "CCCVERSIONSELECTED3", "selected");
	} else if (!strcmp(reader[ridx].cc_version, "2.1.4")) {
		tpl_addVar(vars, 0, "CCCVERSIONSELECTED4", "selected");
	}

	tpl_printf(vars, 0, "CCCMAXHOP", "%d", reader[ridx].cc_maxhop);
	if (reader[ridx].cc_disable_retry_ecm)
		tpl_addVar(vars, 0, "CCCDISABLERETRYECMCHECKED", "checked");
	if (reader[ridx].cc_disable_auto_block)
		tpl_addVar(vars, 0, "CCCDISABLEAUTOBLOCKCHECKED", "checked");
	if(reader[ridx].cc_want_emu)
		tpl_addVar(vars, 0, "CCCWANTEMUCHECKED", "checked");

	// Show only parameters which needed for the reader
	switch (reader[ridx].typ) {
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
			if ( reader[ridx].ncd_proto == NCD_525 ){
				tpl_addVar(vars, 0, "PROTOCOL", "newcamd525");
				tpl_addVar(vars, 1, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGNCD525BIT"));
			} else if ( reader[ridx].ncd_proto == NCD_524 ) {
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
			tpl_printf(vars, 1, "MESSAGE", "<b>Error: protocol number: %d readername: %s readeridx: %d</b><BR>", reader[ridx].typ, reader[ridx].label, ridx);
			break;

	}
	//READERCONFIGMOUSEBIT
	fputs(tpl_getTpl(vars, "READERCONFIG"), f);
}

void send_oscam_user_config_edit(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in) {
	struct s_auth *account, *ptr;
	char user[128];

	if (strcmp(getParam(params, "action"), "Save As") == 0) cs_strncpy(user, getParam(params, "newuser"), sizeof(user)/sizeof(char));
	else cs_strncpy(user, getParam(params, "user"), sizeof(user)/sizeof(char));

	int i;

	for (account = fork_account; account != NULL && strcmp(user, account->usr) != 0; account = account->next);

	// Create a new user if it doesn't yet
	if (account == NULL) {
		i = 1;
		while(strlen(user) < 1) {
			snprintf(user, sizeof(user)/sizeof(char) - 1, "NEWUSER%d", i);
			for (account = fork_account; account != NULL && strcmp(user, account->usr) != 0; account = account->next);
			if(account != NULL) user[0] = '\0';
			++i;
		}
		if (!(account=malloc(sizeof(struct s_auth)))) {
			cs_log("Error allocating memory (errno=%d)", errno);
			return;
		}
		if(fork_account == NULL) fork_account = account;
		else {
			for (ptr = fork_account; ptr != NULL && ptr->next != NULL; ptr = ptr->next);
			ptr->next = account;
		}
		memset(account, 0, sizeof(struct s_auth));
		cs_strncpy((char *)account->usr, user, sizeof(account->usr));
		account->au=(-1);
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
		if (write_userdb(fork_account)==0) refresh_oscam(REFR_ACCOUNTS, in);
		else tpl_addVar(vars, 1, "MESSAGE", "<b>Writing configuration to disk failed!</b><BR>");
		// need to reget account as writing to disk changes account!
		for (account = fork_account; account != NULL && strcmp(user, account->usr) != 0; account = account->next);
	}

	if((strcmp(getParam(params, "action"), "Save") == 0) || (strcmp(getParam(params, "action"), "Save As") == 0)) {
		char servicelabels[255]="";
		//clear group
		account->grp = 0;
		//clear caidtab before it re-readed by chk_t
		clear_caidtab(&account->ctab);

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
		if (write_userdb(fork_account)==0) refresh_oscam(REFR_ACCOUNTS, in);
		else tpl_addVar(vars, 1, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}
	for (account = fork_account; account != NULL && strcmp(user, account->usr) != 0; account = account->next);

	tpl_addVar(vars, 0, "USERNAME", account->usr);
	tpl_addVar(vars, 0, "PASSWORD", account->pwd);

	//Disabled
	if(account->disabled)
	tpl_addVar(vars, 0, "DISABLEDCHECKED", "selected");

	//Expirationdate
	struct tm * timeinfo = localtime (&account->expirationdate);
	char buf [80];
	strftime (buf,80,"%Y-%m-%d",timeinfo);
	if(strcmp(buf,"1970-01-01")) tpl_addVar(vars, 0, "EXPDATE", buf);

	//Group
	char *value = mk_t_group((ulong*)account->grp);
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
	if (!account->au) tpl_addVar(vars, 0, "AUSELECTED", "selected");
	if (account->autoau == 1) tpl_addVar(vars, 0, "AUTOAUSELECTED", "selected");
	int ridx;
	for (ridx=0; ridx<CS_MAXREADER; ridx++) {
		if(!reader[ridx].device[0]) break;
		tpl_addVar(vars, 0, "READERNAME", reader[ridx].label);
		if (account->au == ridx) tpl_addVar(vars, 0, "SELECTED", "selected");
		else tpl_addVar(vars, 0, "SELECTED", "");
		tpl_addVar(vars, 1, "RDROPTION", tpl_getTpl(vars, "USEREDITRDRSELECTED"));
	}

	/* SERVICES */
	//services - first we have to move the long sidtabok/sidtabno to a binary array
	char sidok[33];
	long2bitchar(account->sidtabok,sidok);
	char sidno[33];
	long2bitchar(account->sidtabno,sidno);
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
	tpl_printf(vars, 0, "IDENTS", "%s\n", value);
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

	fputs(tpl_getTpl(vars, "USEREDIT"), f);
}

void send_oscam_user_config(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in) {
	struct s_auth *account, *account2;
	char *user = getParam(params, "user");
	int i, found = 0;
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
			account=fork_account;
			if(strcmp(account->usr, user) == 0) {
				fork_account = account->next;
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
				if (write_userdb(fork_account)==0) refresh_oscam(REFR_ACCOUNTS, in);
				else tpl_addVar(vars, 1, "MESSAGE", "<b>Writing configuration to disk failed!</b><BR>");
			} else tpl_addVar(vars, 1, "MESSAGE", "<b>Sorry but the specified user doesn't exist. No deletion will be made!</b><BR>");
		}
	}



	if ((strcmp(getParam(params, "action"), "disable") == 0) || (strcmp(getParam(params, "action"), "enable") == 0)) {
		for (account=fork_account; (account); account=account->next) {
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
			if (write_userdb(fork_account)==0) refresh_oscam(REFR_ACCOUNTS, in);
			else tpl_addVar(vars, 1, "MESSAGE", "<b>Writing configuration to disk failed!</b><BR>");
		} else tpl_addVar(vars, 1, "MESSAGE", "<b>Sorry but the specified user doesn't exist. No deletion will be made!</b><BR>");
	}

	/* List accounts*/
	char *status = "offline";
	char *expired = "";
	char *classname="offline";
	char *lastchan="&nbsp;";
	time_t now = time((time_t)0);
	int isec = 0, isonline = 0;

	//for (account=cfg->account; (account); account=account->next) {
	for (account=fork_account; (account); account=account->next) {
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
			tpl_addVar(vars, 0, "SWITCHICO", ICENA);
			tpl_addVar(vars, 0, "SWITCHTITLE", "enable this account");
			tpl_addVar(vars, 0, "SWITCH", "enable");
		} else {
			tpl_addVar(vars, 0, "SWITCHICO", ICDIS);
			tpl_addVar(vars, 0, "SWITCHTITLE", "disable this account");
			tpl_addVar(vars, 0, "SWITCH", "disable");
		}

		//search account in active clients
		int cwok = 0, cwnok = 0, cwign = 0, cwtout = 0, cwcache = 0, cwtun = 0, emmok = 0, emmnok = 0;
		int secs = 0, fullmins =0, mins =0, hours =0, lastresponsetm = 0;
		char *proto = "";

		for (i=0; i<CS_MAXPID; i++)
		if (!strcmp(client[i].usr, account->usr)) {
			//set client to offline depending on hideclient_to
			if ((now - client[i].lastecm) < hideclient) {
				status = "<b>online</b>"; classname="online";
				isonline = 1;
				proto = monitor_get_proto(i);
				lastchan = get_servicename(client[i].last_srvid, client[i].last_caid);
				lastresponsetm = client[i].cwlastresptime;
				isec = now - client[i].last;
				if(isec > 0) {
					secs = isec % 60;
					if (isec > 60) {
						fullmins = isec / 60;
						mins = fullmins % 60;
						if(fullmins > 60) hours = fullmins / 60;
					}
				}
			}

			cwok += client[i].cwfound;
			cwnok += client[i].cwnot;
			cwign += client[i].cwignored;
			cwtout += client[i].cwtout;
			cwcache += client[i].cwcache;
			cwtun += client[i].cwtun;
			emmok += client[i].emmok;
			emmnok += client[i].emmnok;
		}

		if ( isonline > 0 ) {
			tpl_printf(vars, 0, "CWOK", "%d", cwok);
			tpl_printf(vars, 0, "CWNOK", "%d", cwnok);
			tpl_printf(vars, 0, "CWIGN", "%d", cwign);
			tpl_printf(vars, 0, "CWTOUT", "%d", cwtout);
			tpl_printf(vars, 0, "CWCACHE", "%d", cwcache);
			tpl_printf(vars, 0, "CWTUN", "%d", cwtun);
			tpl_printf(vars, 0, "EMMOK", "%d", emmok);
			tpl_printf(vars, 0, "EMMNOK", "%d", emmnok);
			tpl_addVar(vars, 0, "LASTCHANNEL", lastchan);
			tpl_printf(vars, 0, "CWLASTRESPONSET", "%d", lastresponsetm);
			tpl_addVar(vars, 0, "CLIENTPROTO", proto);
			tpl_printf(vars, 0, "IDLESECS", "%02d:%02d:%02d", hours, mins, secs);

		}

		tpl_addVar(vars, 0, "CLASSNAME", classname);
		tpl_addVar(vars, 0, "USER", account->usr);
		tpl_addVar(vars, 0, "USERENC", tpl_addTmp(vars, urlencode(account->usr)));
		tpl_addVar(vars, 0, "STATUS", status);
		tpl_addVar(vars, 0, "EXPIRED", expired);
		tpl_addVar(vars, 0, "DELICO", ICDEL);
		tpl_addVar(vars, 0, "EDIICO", ICEDI);

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

	fputs(tpl_getTpl(vars, "USERCONFIGLIST"), f);
}

void send_oscam_entitlement(struct templatevars *vars, FILE *f, struct uriparams *params) {
	/* build entitlements from reader init history */
	int ridx;
	char *reader_ = getParam(params, "reader");
#ifdef CS_RDR_INIT_HIST	
	char *p;
	if(strlen(reader_) > 0) {
		for (ridx=0; ridx<CS_MAXREADER && strcmp(reader_, reader[ridx].label) != 0; ridx++);
		if(ridx<CS_MAXREADER) {

			if (reader[ridx].typ == R_CCCAM) {

				//struct cc_data *ctest = reader[ridx].cc;

				//tpl_printf(vars, 1, "LOGHISTORY", "peer node id: %s<BR>\n", cs_hexdump(0, ctest->peer_node_id, 8));
				//tpl_printf(vars, 1, "LOGHISTORY", "node id: %s<BR>\n", cs_hexdump(0, ctest->node_id, 8));
				//tpl_printf(vars, 1, "LOGHISTORY", "card cnt: %d<BR><BR>\n", ctest->card_count);

				char fname[40];
				snprintf(fname, sizeof(fname), "/tmp/.oscam/caidinfos.%d", ridx);
				FILE *file = fopen(fname, "r");
				if (file) {
					uint16 caid = 0;
					uint8 hop = 0;
					char ascprovid[7];
					char *provider="";
					do {
						if (fread(&caid, 1, sizeof(caid), file) <= 0)
							break;
						if (fread(&hop, 1, sizeof(hop), file) <= 0)
							break;
						tpl_printf(vars, 1, "LOGHISTORY", "caid: %04X hop: %d<BR>\n", caid, hop);
						uint8 count = 0;
						if (fread(&count, 1, sizeof(count), file) <= 0)
							break;
						uint8 prov[3];
						int revcount = count;
						while (count > 0) {
							if (fread(prov, 1, sizeof(prov), file) <= 0)
								break;
							snprintf(ascprovid, sizeof(ascprovid), "%02X%02X%02X", prov[0], prov[1], prov[2]);
							provider = get_provider(caid, a2i(ascprovid, 3));

							tpl_printf(vars, 1, "LOGHISTORY", "&nbsp;&nbsp;-- Provider %d: %s -- %s<BR>\n",
									revcount - count, ascprovid, provider);
							count--;
						}
						tpl_addVar(vars, 1, "LOGHISTORY", "<BR>\n");
					} while (1);
					fclose(file);
					tpl_printf(vars, 1, "LOGHISTORY", "cardfile end<BR>\n");
				} else {
					tpl_printf(vars, 1, "LOGHISTORY", "no cardfile found<BR>\n");
				}

			} else {
				for (p=(char *)reader[ridx].init_history; *p; p+=strlen(p)+1) {
					tpl_printf(vars, 1, "LOGHISTORY", "%s<BR>\n", p);
				}
			}
		}
		tpl_addVar(vars, 0, "READERNAME", reader_);
	}
#else
	if (cfg->saveinithistory && strlen(reader_) > 0) {
		for (ridx=0; ridx<CS_MAXREADER && strcmp(reader_, reader[ridx].label) != 0; ridx++);

		if (reader[ridx].typ == R_CCCAM) {

			//struct cc_data *ctest = reader[ridx].cc;

			//tpl_printf(vars, 1, "LOGHISTORY", "peer node id: %s<BR>\n", cs_hexdump(0, ctest->peer_node_id, 8));
			//tpl_printf(vars, 1, "LOGHISTORY", "node id: %s<BR>\n", cs_hexdump(0, ctest->node_id, 8));
			//tpl_printf(vars, 1, "LOGHISTORY", "card cnt: %d<BR><BR>\n", ctest->card_count);

			char fname[40];
			snprintf(fname, sizeof(fname), "/tmp/.oscam/caidinfos.%d", ridx);
			FILE *file = fopen(fname, "r");
			if (file) {
				uint16 caid = 0;
				uint8 hop = 0;
				char ascprovid[7];
				char *provider="";
				do {
					if (fread(&caid, 1, sizeof(caid), file) <= 0)
						break;
					if (fread(&hop, 1, sizeof(hop), file) <= 0)
						break;
					tpl_printf(vars, 1, "LOGHISTORY", "caid: %04X hop: %d<BR>\n", caid, hop);
					uint8 count = 0;
					if (fread(&count, 1, sizeof(count), file) <= 0)
						break;
					uint8 prov[3];
					int revcount = count;
					while (count > 0) {
						if (fread(prov, 1, sizeof(prov), file) <= 0)
							break;
						snprintf(ascprovid, sizeof(ascprovid), "%02X%02X%02X", prov[0], prov[1], prov[2]);
						provider = get_provider(caid, a2i(ascprovid, 3));

						tpl_printf(vars, 1, "LOGHISTORY", "&nbsp;&nbsp;-- Provider %d: %s -- %s<BR>\n",
								revcount - count, ascprovid, provider);
						count--;
					}
					tpl_addVar(vars, 1, "LOGHISTORY", "<BR>\n");
				} while (1);
				fclose(file);
			} else {
				tpl_printf(vars, 1, "LOGHISTORY", "no cardfile found<BR>\n");
			}

		} else {
			FILE *fp;
			char filename[32];
			char buffer[128];
			snprintf(filename, sizeof(filename), "/tmp/.oscam/reader%d", reader[ridx].ridx);
			fp = fopen(filename, "r");

			if (fp) {
				while(fgets(buffer, 128, fp) != NULL) {
					tpl_printf(vars, 1, "LOGHISTORY", "%s<BR>\n", buffer);
				}
				fclose(fp);
			}
			tpl_addVar(vars, 0, "READERNAME", reader_);
		}
	} else {
		tpl_addVar(vars, 0, "LOGHISTORY", "You have to set saveinithistory=1 in your config to see Entitlements!<BR>\n");
	}
#endif
	fputs(tpl_getTpl(vars, "ENTITLEMENTS"), f);
}

void send_oscam_status(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in) {
	int i;
	char *usr;
	int lsec, isec, cnr, con, cau;
	time_t now = time((time_t)0);
	struct tm *lt;

	if (strcmp(getParam(params, "action"), "kill") == 0)
		kill(atoi(getParam(params, "pid")), SIGQUIT);

	char *debuglvl = getParam(params, "debug");
	if(strlen(debuglvl) > 0) {
		int lvl = atoi(debuglvl);
		if (cfg->debuglvl != lvl) {
			cfg->debuglvl = lvl;
			kill(client[0].pid, SIGUSR1);
		}
	}

	char *hideidx = getParam(params, "hide");
	if(strlen(hideidx) > 0)
	client[atoi(hideidx)].wihidden = 1;

	char *hideidle = getParam(params, "hideidle");
	if(strlen(hideidle) > 0) {
		if (atoi(hideidle) == 2) {
			for (i=0; i<CS_MAXPID; i++)
			client[i].wihidden = 0;
		} else {
			int oldval = cfg->http_hide_idle_clients;
			chk_t_webif("httphideidleclients", hideidle);
			if(oldval != cfg->http_hide_idle_clients) {
				refresh_oscam(REFR_SERVER, in);
			}
		}
	}

	if(cfg->http_hide_idle_clients > 0) tpl_addVar(vars, 0, "HIDEIDLECLIENTSSELECTED1", "selected");
	else tpl_addVar(vars, 0, "HIDEIDLECLIENTSSELECTED0", "selected");

	for (i=0; i<CS_MAXPID; i++) {
		if (client[i].pid && client[i].wihidden != 1) {

			if((cfg->http_hide_idle_clients == 1) && (client[i].typ == 'c') && ((now - client[i].lastecm) > cfg->mon_hideclient_to)) continue;

			lsec=now-client[i].login;
			isec=now-client[i].last;
			usr=client[i].usr;

			if (((client[i].typ=='r') || (client[i].typ=='p')) && (con=cs_idx2ridx(i))>=0) usr=reader[con].label;

			if (client[i].dup) con=2;
			else if ((client[i].tosleep) && (now-client[i].lastswitch>client[i].tosleep)) con=1;
			else con=0;

			if (i-cdiff>0) cnr=i-cdiff;
			else cnr=(i>1) ? i-1 : 0;

			if( (cau=client[i].au+1) && (now-client[i].lastemm)/60 > cfg->mon_aulow) cau=-cau;

			lt=localtime(&client[i].login);

			tpl_printf(vars, 0, "HIDEIDX", "%d", i);
			tpl_addVar(vars, 0, "HIDEICON", ICHID);
			if((client[i].typ == 'c' || client[i].typ == 'r' || client[i].typ == 'p') && !cfg->http_readonly) {
				tpl_printf(vars, 0, "CLIENTPID", "%d&nbsp;", client[i].pid);
				tpl_printf(vars, 1, "CLIENTPID", "<A HREF=\"status.html?action=kill&pid=%d\" TITLE=\"Kill this client\"><IMG SRC=\"%s\" ALT=\"Kill\" STYLE=\"float:right\"></A>", client[i].pid, ICKIL);
			} else {
				tpl_printf(vars, 0, "CLIENTPID", "%d&nbsp;", client[i].pid);
			}

			tpl_printf(vars, 0, "CLIENTTYPE", "%c", client[i].typ);
			tpl_printf(vars, 0, "CLIENTCNR", "%d", cnr);
			tpl_addVar(vars, 0, "CLIENTUSER", usr);
			tpl_printf(vars, 0, "CLIENTCAU", "%d", cau);
			tpl_printf(vars, 0, "CLIENTCRYPTED", "%d", client[i].crypted);
			tpl_printf(vars, 0, "CLIENTIP", "%s", cs_inet_ntoa(client[i].ip));
			tpl_printf(vars, 0, "CLIENTPORT", "%d", client[i].port);
			tpl_addVar(vars, 0, "CLIENTPROTO", monitor_get_proto(i));
			tpl_printf(vars, 0, "CLIENTLOGINDATE", "%02d.%02d.%02d", lt->tm_mday, lt->tm_mon+1, lt->tm_year%100);
			tpl_printf(vars, 0, "CLIENTLOGINTIME", "%02d:%02d:%02d", lt->tm_hour, lt->tm_min, lt->tm_sec);

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
			tpl_printf(vars, 0, "CLIENTLOGINSECS", "%02d:%02d:%02d", hours, mins, secs);
			else
			tpl_printf(vars, 0, "CLIENTLOGINSECS", "%02dd %02d:%02d:%02d", days, hours, mins, secs);

			tpl_printf(vars, 0, "CLIENTCAID", "%04X", client[i].last_caid);
			tpl_printf(vars, 0, "CLIENTSRVID", "%04X", client[i].last_srvid);

			int j, found = 0;
			struct s_srvid *srvid = cfg->srvid;

			while (srvid != NULL) {
				if (srvid->srvid == client[i].last_srvid) {
					for (j=0; j < srvid->ncaid; j++) {
						if (srvid->caid[j] == client[i].last_caid) {
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
				tpl_printf(vars, 0, "CLIENTSRVPROVIDER","%s : ", srvid->prov);
				tpl_addVar(vars, 0, "CLIENTSRVNAME", srvid->name);
				tpl_addVar(vars, 0, "CLIENTSRVTYPE", srvid->type);
				tpl_addVar(vars, 0, "CLIENTSRVDESCRIPTION", srvid->desc);
			} else {
				tpl_addVar(vars, 0, "CLIENTSRVPROVIDER","");
				tpl_printf(vars, 0, "CLIENTSRVNAME","");
				tpl_addVar(vars, 0, "CLIENTSRVTYPE","");
				tpl_addVar(vars, 0, "CLIENTSRVDESCRIPTION","");
			}

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
			if(con == 2) tpl_printf(vars, 0, "CLIENTCON", "Duplicate");
			else if (con == 1) tpl_printf(vars, 0, "CLIENTCON", "Sleep");
			else
			{
				char *txt = "OK";
				if (client[i].typ == 'r' || client[i].typ == 'p') //reader or proxy
				{
					int ridx;
					for (ridx = 0; ridx < CS_MAXREADER; ridx++)
					{
						if(reader[ridx].pid == client[i].pid)
						{
							switch(reader[ridx].card_status)
							{
								case NO_CARD: txt = "OFF"; break;
								case CARD_NEED_INIT: txt = "NEEDINIT"; break;
								case CARD_INSERTED:
									if (client[i].typ=='p')
										txt = "CONNECTED";
									else
										txt = "CARDOK";
									break;
								case CARD_FAILURE: txt = "ERROR"; break;
								default: txt = "UNDEF";
							}
						}
					}

				}
				tpl_printf(vars, 0, "CLIENTCON", txt);
			}
			tpl_addVar(vars, 1, "CLIENTSTATUS", tpl_getTpl(vars, "CLIENTSTATUSBIT"));
		}
	}

#ifdef CS_LOGHISTORY
	for (i=(*loghistidx+3) % CS_MAXLOGHIST; i!=*loghistidx; i=(i+1) % CS_MAXLOGHIST) {
		char *p_usr, *p_txt;
		p_usr=(char *)(loghist+(i*CS_LOGHISTSIZE));
		p_txt=p_usr+32;
		if (p_txt[0]) tpl_printf(vars, 1, "LOGHISTORY", "%s<BR>\n", p_txt+8);
	}
#else
	tpl_addVar(vars, 0, "LOGHISTORY", "the flag CS_LOGHISTORY is not set in your binary<BR>\n");
#endif

	tpl_printf(vars, 0, "SDEBUG", "<SPAN CLASS=\"debugt\"> %s&nbsp;%d to&nbsp;</SPAN>\n", "Switch Debug from", cfg->debuglvl);
	tpl_addVar(vars, 1, "SDEBUG", "<A CLASS=\"debugl\" HREF=\"status.html?debug=0\" title=\"no debugging (default)\">0</A>&nbsp;\n");
	tpl_addVar(vars, 1, "SDEBUG", "<A CLASS=\"debugl\" HREF=\"status.html?debug=1\" title=\"detailed error messages\">1</A>&nbsp;\n");
	tpl_addVar(vars, 1, "SDEBUG", "<A CLASS=\"debugl\" HREF=\"status.html?debug=2\" title=\"ATR parsing info, ECM dumps, CW dumps\">2</A>&nbsp;\n");
	tpl_addVar(vars, 1, "SDEBUG", "<A CLASS=\"debugl\" HREF=\"status.html?debug=4\" title=\"traffic from/to the reader\">4</A>&nbsp;\n");
	tpl_addVar(vars, 1, "SDEBUG", "<A CLASS=\"debugl\" HREF=\"status.html?debug=8\" title=\"traffic from/to the clients\">8</A>&nbsp;\n");
	tpl_addVar(vars, 1, "SDEBUG", "<A CLASS=\"debugl\" HREF=\"status.html?debug=16\" title=\"traffic to the reader-device on IFD layer\">16</A>&nbsp;\n");
	tpl_addVar(vars, 1, "SDEBUG", "<A CLASS=\"debugl\" HREF=\"status.html?debug=32\" title=\"traffic to the reader-device on I/O layer\">32</A>&nbsp;\n");
	tpl_addVar(vars, 1, "SDEBUG", "<A CLASS=\"debugl\" HREF=\"status.html?debug=64\" title=\"EMM logging\">64</A>&nbsp;\n");
	tpl_addVar(vars, 1, "SDEBUG", "<A CLASS=\"debugl\" HREF=\"status.html?debug=255\" title=\"debug all\">255</A>\n");

	fputs(tpl_getTpl(vars, "STATUS"), f);
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
	fputs(tpl_getTpl(vars, "SERVICEEDIT"), f);
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
				tpl_printf(vars, 1, "SID", "%04X : %s<BR>", sidtab->srvid[i], get_servicename(sidtab->srvid[i], sidtab->caid[0]));
			}
		} else {
			tpl_printf(vars, 0, "SIDCLASS","");
			tpl_printf(vars, 0, "SID","<A HREF=\"services.html?service=%s&action=list\">Show Services</A>",tpl_addTmp(vars, urlencode(sidtab->label)));
		}
		tpl_addVar(vars, 0, "LABELENC", tpl_addTmp(vars, urlencode(sidtab->label)));
		tpl_addVar(vars, 0, "LABEL", sidtab->label);
		tpl_addVar(vars, 0, "SIDLIST", tpl_getTpl(vars, "SERVICECONFIGSIDBIT"));
		tpl_addVar(vars, 0, "EDIICO", ICEDI);
		tpl_addVar(vars, 0, "DELICO", ICDEL);
		tpl_addVar(vars, 1, "SERVICETABS", tpl_getTpl(vars, "SERVICECONFIGLISTBIT"));
		sidtab=sidtab->next;
	}
	fputs(tpl_getTpl(vars, "SERVICECONFIGLIST"), f);
}

void send_oscam_savetpls(struct templatevars *vars, FILE *f) {
	if(strlen(cfg->http_tpl) > 0) {
		tpl_printf(vars, 0, "CNT", "%d", tpl_saveIncludedTpls(cfg->http_tpl));
		tpl_addVar(vars, 0, "PATH", cfg->http_tpl);
	} else tpl_addVar(vars, 0, "CNT", "0");
	fputs(tpl_getTpl(vars, "SAVETEMPLATES"), f);
}

void send_oscam_shutdown(struct templatevars *vars, FILE *f, struct uriparams *params) {
	if (strcmp(getParam(params, "action"), "Shutdown") == 0) {
		tpl_addVar(vars, 0, "STYLESHEET", CSS);
		tpl_printf(vars, 0, "REFRESHTIME", "%d", SHUTDOWNREFRESH);
		tpl_addVar(vars, 0, "REFRESHURL", "status.html");
		tpl_addVar(vars, 0, "REFRESH", tpl_getTpl(vars, "REFRESH"));
		tpl_printf(vars, 0, "SECONDS", "%d", SHUTDOWNREFRESH);
		fputs(tpl_getTpl(vars, "SHUTDOWN"), f);
		running = 0;
	} else {
		fputs(tpl_getTpl(vars, "PRESHUTDOWN"), f);
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
	fputs(tpl_getTpl(vars, "SCRIPT"), f);

}

void send_oscam_scanusb(struct templatevars *vars, FILE *f) {
	FILE *fp;
	int err=0;
	char path[1035];

	fp = popen("lsusb", "r");
	if (fp == NULL) {
		tpl_addVar(vars, 0, "USBENTRY", "Failed to run lusb");
		tpl_printf(vars, 0, "USBENTRY", "%s", path);
		tpl_addVar(vars, 1, "USBBIT", tpl_getTpl(vars, "SCANUSBBIT"));
		err = 1;
	}

	if(!err) {
		while (fgets(path, sizeof(path)-1, fp) != NULL) {
			tpl_printf(vars, 0, "USBENTRY", "%s", path);
			tpl_addVar(vars, 1, "USBBIT", tpl_getTpl(vars, "SCANUSBBIT"));
		}
	}
	pclose(fp);
	fputs(tpl_getTpl(vars, "SCANUSB"), f);
}

void send_oscam_files(struct templatevars *vars, FILE *f, struct uriparams *params) {

	char *stoplog = getParam(params, "stoplog");
	if(strlen(stoplog) > 0)
		cfg->disablelog = atoi(stoplog);

	char *stopusrlog = getParam(params, "stopusrlog");
	if(strlen(stopusrlog) > 0)
		cfg->disableuserfile = atoi(stopusrlog);

	char *debuglvl = getParam(params, "debug");
	if(strlen(debuglvl) > 0) {
		int lvl = atoi(debuglvl);
		if (cfg->debuglvl != lvl) {
			cfg->debuglvl = lvl;
			kill(client[0].pid, SIGUSR1);
		}
	}
	char targetfile[256];

	if (strcmp(getParam(params, "part"), "conf") == 0)
	snprintf(targetfile, 255,"%s%s", cs_confdir, "oscam.conf");
	else if (strcmp(getParam(params, "part"), "user") == 0)
	snprintf(targetfile, 255,"%s%s", cs_confdir, "oscam.user");
	else if (strcmp(getParam(params, "part"), "server") == 0)
	snprintf(targetfile, 255,"%s%s", cs_confdir, "oscam.server");
	else if (strcmp(getParam(params, "part"), "services") == 0)
	snprintf(targetfile, 255,"%s%s", cs_confdir, "oscam.services");
	else if (strcmp(getParam(params, "part"), "srvid") == 0)
	snprintf(targetfile, 255,"%s%s", cs_confdir, "oscam.srvid");
	else if (strcmp(getParam(params, "part"), "provid") == 0)
	snprintf(targetfile, 255,"%s%s", cs_confdir, "oscam.provid");
	else if (strcmp(getParam(params, "part"), "logfile") == 0) {
		snprintf(targetfile, 255,"%s", cfg->logfile);

		if (strcmp(getParam(params, "clear"), "logfile") == 0) {
			if(strlen(targetfile) > 0) {
				FILE *file = fopen(targetfile,"w");
				fclose(file);
			}
		}

		tpl_printf(vars, 0, "SDEBUG", "<SPAN CLASS=\"debugt\"> %s&nbsp;%d to&nbsp;</SPAN>\n", "Switch Debug from", cfg->debuglvl);
		tpl_addVar(vars, 1, "SDEBUG", "<A CLASS=\"debugl\" HREF=\"files.html?part=logfile&debug=0\" title=\"no debugging (default)\">0</A>&nbsp;\n");
		tpl_addVar(vars, 1, "SDEBUG", "<A CLASS=\"debugl\" HREF=\"files.html?part=logfile&debug=1\" title=\"detailed error messages\">1</A>&nbsp;\n");
		tpl_addVar(vars, 1, "SDEBUG", "<A CLASS=\"debugl\" HREF=\"files.html?part=logfile&debug=2\" title=\"ATR parsing info, ECM dumps, CW dumps\">2</A>&nbsp;\n");
		tpl_addVar(vars, 1, "SDEBUG", "<A CLASS=\"debugl\" HREF=\"files.html?part=logfile&debug=4\" title=\"traffic from/to the reader\">4</A>&nbsp;\n");
		tpl_addVar(vars, 1, "SDEBUG", "<A CLASS=\"debugl\" HREF=\"files.html?part=logfile&debug=8\" title=\"traffic from/to the clients\">8</A>&nbsp;\n");
		tpl_addVar(vars, 1, "SDEBUG", "<A CLASS=\"debugl\" HREF=\"files.html?part=logfile&debug=16\" title=\"traffic to the reader-device on IFD layer\">16</A>&nbsp;\n");
		tpl_addVar(vars, 1, "SDEBUG", "<A CLASS=\"debugl\" HREF=\"files.html?part=logfile&debug=32\" title=\"traffic to the reader-device on I/O layer\">32</A>&nbsp;\n");
		tpl_addVar(vars, 1, "SDEBUG", "<A CLASS=\"debugl\" HREF=\"files.html?part=logfile&debug=64\" title=\"EMM logging\">64</A>&nbsp;\n");
		tpl_addVar(vars, 1, "SDEBUG", "<A CLASS=\"debugl\" HREF=\"files.html?part=logfile&debug=255\" title=\"debug all\">255</A><SPAN CLASS=\"debugt\">&nbsp;&nbsp;|</SPAN>\n");

		if(!cfg->disablelog)
			tpl_printf(vars, 0, "SLOG", "<A CLASS=\"debugl\" HREF=\"files.html?part=logfile&stoplog=%d\">%s</A><SPAN CLASS=\"debugt\">&nbsp;&nbsp;|&nbsp;&nbsp;</SPAN>\n", 1, "Stop Log");
		else
			tpl_printf(vars, 0, "SLOG", "<A CLASS=\"debugl\" HREF=\"files.html?part=logfile&stoplog=%d\">%s</A><SPAN CLASS=\"debugt\">&nbsp;&nbsp;|&nbsp;&nbsp;</SPAN>\n", 0, "Start Log");

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

	}
#ifdef CS_ANTICASC
	else if (strcmp(getParam(params, "part"), "anticasc") == 0)
	snprintf(targetfile, 255,"%s", cfg->ac_logfile);
#endif

	if (!strstr(targetfile, "/dev/")) {
		if((strlen(targetfile) > 0) && (file_exists(targetfile) == 1)) {
			FILE *fp;
			char buffer[256];

			if((fp = fopen(targetfile,"r")) == NULL) return;
			while (fgets(buffer, sizeof(buffer), fp) != NULL)
				tpl_printf(vars, 1, "FILECONTENT", "%s", buffer);
			fclose (fp);
		} else {
			tpl_addVar(vars, 1, "FILECONTENT", "File not exist");
		}
	} else {
		tpl_addVar(vars, 1, "FILECONTENT", "File not valid");
	}

	fputs(tpl_getTpl(vars, "FILE"), f);
}

int process_request(FILE *f, struct in_addr in) {

	client[cs_idx].last = time((time_t)0); //reset last busy time

	int ok=0;
	struct s_ip *p_ip;
	in_addr_t addr = cs_inet_order(in.s_addr);

	for (p_ip = cfg->http_allowed; (p_ip) && (!ok); p_ip = p_ip->next)
		ok =((addr >= p_ip->ip[0]) && (addr <= p_ip->ip[1]));

	if (!ok && cfg->http_dyndns[0]) {
		if(cfg->http_dynip == addr) {
			ok = 1;
		} else {
			pthread_mutex_lock(&gethostbyname_lock); //gethostbyname ist NOT threadsafe! So we need a mutex-lock!
			struct hostent *rht;
			struct sockaddr_in udp_sa;
			rht = gethostbyname((const char *) cfg->http_dyndns);
			if (rht) {
				memcpy(&udp_sa.sin_addr, rht->h_addr, sizeof(udp_sa.sin_addr));
				cfg->http_dynip = cs_inet_order(udp_sa.sin_addr.s_addr);
				if (cfg->http_dynip == addr)
					ok = 1;
			}
			pthread_mutex_unlock(&gethostbyname_lock); //gethostbyname ist NOT threadsafe! So we need a mutex-lock!
		}
	}

	if (!ok) {
		send_error(f, 403, "Forbidden", NULL, "Access denied.");
		cs_log("unauthorized access from %s", inet_ntoa(*(struct in_addr *)&in));
		return 0;
	}

	char buf[4096];
	char tmp[4096];

	int authok = 0;
	char expectednonce[64];

	char *method;
	char *path;
	char *protocol;
	char *pch;
	char *pch2;
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
		"/files.html"};

	int pagescnt = sizeof(pages)/sizeof(char *); // Calculate the amount of items in array

	int pgidx = -1;
	int i;
	int parsemode = 1;
	struct uriparams params;
	params.paramcount = 0;

	/* First line always includes the GET/POST request */
	if (!fgets(buf, sizeof(buf), f)) return -1;
	method = strtok(buf, " ");
	path = strtok(NULL, " ");
	protocol = strtok(NULL, "\r");
	if(method == NULL || path == NULL || protocol == NULL) return -1;

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

	/* Parse url parameters; parsemode = 1 means parsing next param, parsemode = -1 parsing next
	 value; pch2 points to the beginning of the currently parsed string, pch is the current position */
	pch2=pch;
	while(pch[0] != '\0') {
		if((parsemode == 1 && pch[0] == '=') || (parsemode == -1 && pch[0] == '&')) {
			pch[0] = '\0';
			urldecode(pch2);
			if(parsemode == 1) {
				if(params.paramcount >= MAXGETPARAMS) break;
				++params.paramcount;
				params.params[params.paramcount-1] = pch2;
			} else {
				params.values[params.paramcount-1] = pch2;
			}
			parsemode = -parsemode;
			pch2 = pch + 1;
		}
		++pch;
	}
	/* last value wasn't processed in the loop yet... */
	if(parsemode == -1 && params.paramcount <= MAXGETPARAMS) {
		urldecode(pch2);
		params.values[params.paramcount-1] = pch2;
	}

	if(strlen(cfg->http_user) == 0 || strlen(cfg->http_pwd) == 0) authok = 1;
	else calculate_nonce(expectednonce, sizeof(expectednonce)/sizeof(char));

	/* Read remaining request (we're only interested in auth header) */
	while (fgets(tmp, sizeof(tmp), f)) {
		if (tmp[0] == '\r' && tmp[1] == '\n') break;
		else if(authok == 0 && strlen(tmp) > 50 && strncmp(tmp, "Authorization:", 14) == 0 && strstr(tmp, "Digest") != NULL) {
			authok = check_auth(tmp, method, path, expectednonce);
		}
	}

	//cs_debug("%s %d\n", path, pgidx);
	//for(i=0; i < params.paramcount; ++i) cs_debug("%s : %s\n", params.params[i], params.values[i]);

	fseek(f, 0, SEEK_CUR); // Force change of stream direction

	if(authok != 1) {
		strcpy(tmp, "WWW-Authenticate: Digest algorithm=\"MD5\", realm=\"");
		strcat(tmp, AUTHREALM);
		strcat(tmp, "\", qop=\"auth\", opaque=\"\", nonce=\"");
		strcat(tmp, expectednonce);
		strcat(tmp, "\"");
		if(authok == 2) strcat(tmp, ", stale=true");
		send_headers(f, 401, "Unauthorized", tmp, "text/html");
		return 0;
	}

	/*build page*/
	send_headers(f, 200, "OK", NULL, "text/html");
	if(pgidx == 8) send_css(f);
	else {
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
		tpl_printf(vars, 0, "CURDATE", "%02d.%02d.%02d", lt->tm_mday, lt->tm_mon+1, lt->tm_year%100);
		tpl_printf(vars, 0, "CURTIME", "%02d:%02d:%02d", lt->tm_hour, lt->tm_min, lt->tm_sec);
		st = localtime(&client[0].login);
		tpl_printf(vars, 0, "STARTDATE", "%02d.%02d.%02d", st->tm_mday, st->tm_mon+1, st->tm_year%100);
		tpl_printf(vars, 0, "STARTTIME", "%02d:%02d:%02d", st->tm_hour, st->tm_min, st->tm_sec);

		time_t now = time((time_t)0);
		int lsec = now - client[0].login;
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
			case 2: send_oscam_entitlement(vars, f, &params); break;
			case 3: send_oscam_status(vars, f, &params, in); break;
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
			default: send_oscam_status(vars, f, &params, in); break;
		}
		tpl_clear(vars);
	}
	return 0;
}

void http_srv() {
	int i,sock, reuse = 1;
	struct sockaddr_in sin;
	struct sockaddr_in remote;
	socklen_t len = sizeof(remote);
	char *tmp;
	fork_account = cfg->account;

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
	cs_log("HTTP Server listening on port %d", cfg->http_port);
	struct pollfd pfd[1];
	int rc;
	pfd[0].fd = sock;
	pfd[0].events = (POLLIN | POLLPRI);

	while (running) {
		int s;
		FILE *f;

		rc = poll(pfd, 1, 1000);
		if (master_pid != getppid())
		cs_exit(0);

		if (rc > 0) {
			if((s = accept(sock, (struct sockaddr *) &remote, &len)) < 0) {
				cs_log("HTTP Server: Error calling accept() (errno=%d).", errno);
				break;
			}

			f = fdopen(s, "r+");
			process_request(f, remote.sin_addr);
			fflush(f);
			fclose(f);
			shutdown(s, SHUT_WR);
			close(s);
		}
	}

	close(sock);
	kill(client[0].pid, SIGQUIT);
}
#endif
