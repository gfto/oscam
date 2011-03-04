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
#include "module-cccshare.h"
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
	LL_ITER *itr = ll_iter_create(configured_readers);
	while((rdr = ll_iter_next(itr)))
	  if (strcmp(lbl, rdr->label) == 0) break;
	ll_iter_release(itr);
	return rdr;
}

struct s_client *get_client_by_name(char *name) {
	struct s_client *cl;
	for (cl = first_client; cl ; cl = cl->next) {
		if (strcmp(name, cl->account->usr) == 0)
			return cl;
	}
	return NULL;
}

struct s_auth *get_account_by_name(char *name) {
	struct s_auth *account;
	for (account=cfg.account; (account); account=account->next) {
		if(strcmp(name, account->usr) == 0)
			return account;
	}
	return NULL;
}

void refresh_oscam(enum refreshtypes refreshtype, struct in_addr in) {

	switch (refreshtype) {
		case REFR_ACCOUNTS:
		cs_log("Refresh Accounts requested by WebIF from %s", inet_ntoa(in));

		cs_accounts_chk();
		break;

		case REFR_READERS:
		cs_card_info();
		cs_log("Refresh Reader/Tiers requested by WebIF from %s", inet_ntoa(in));
		break;

		case REFR_SERVER:
		cs_log("Refresh Server requested by WebIF from %s", inet_ntoa(in));
		//kill(first_client->pid, SIGHUP);
		//todo how I can refresh the server after global settings
		break;

		case REFR_SERVICES:
		cs_log("Refresh Services requested by WebIF from %s", inet_ntoa(in));
		//init_sidtab();
		cs_reinit_clients(cfg.account);
		break;

#ifdef CS_ANTICASC
		case REFR_ANTICASC:
		cs_log("Refresh Anticascading requested by WebIF from %s", inet_ntoa(in));
		kill_ac_client();
#endif
		default:
			break;
	}
}

char *send_oscam_config_global(struct templatevars *vars, struct uriparams *params, struct in_addr in) {
	int i;

	if (strcmp(getParam(params, "action"), "execute") == 0) {
		for(i = 0; i < (*params).paramcount; ++i) {
			if ((strcmp((*params).params[i], "part")) && (strcmp((*params).params[i], "action"))) {
				//tpl_printf(vars, TPLAPPEND, "MESSAGE", "Parameter: %s set to Value: %s<BR>\n", (*params).params[i], (*params).values[i]);
				//we use the same function as used for parsing the config tokens

				chk_t_global((*params).params[i], (*params).values[i]);
			}
		}
		tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<BR><BR><B>Configuration Global done. You should restart Oscam now.</B><BR><BR>");
		if(write_config()==0) refresh_oscam(REFR_SERVER, in);
		else tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}
	if (cfg.srvip != 0)
	tpl_addVar(vars, TPLADD, "SERVERIP", cs_inet_ntoa(cfg.srvip));
	tpl_printf(vars, TPLADD, "NICE", "%d", cfg.nice);
	tpl_printf(vars, TPLADD, "BINDWAIT", "%d", cfg.bindwait);
	tpl_printf(vars, TPLADD, "NETPRIO", "%ld", cfg.netprio);


	if (cfg.usrfile != NULL) tpl_addVar(vars, TPLADD, "USERFILE", cfg.usrfile);
	if (cfg.disableuserfile == 1) tpl_addVar(vars, TPLADD, "DISABLEUSERFILECHECKED", "selected");
	if(cfg.usrfileflag == 1) tpl_addVar(vars, TPLADD, "USERFILEFLAGCHECKED", "selected");

	char *value = mk_t_logfile();
	tpl_addVar(vars, TPLADD, "LOGFILE", value);
	free(value);
	if(cfg.disablelog == 1) 		tpl_addVar(vars, TPLADD, "DISABLELOGCHECKED", "selected");
	tpl_printf(vars, TPLADD, "MAXLOGSIZE", "%d", cfg.max_log_size);

	if (cfg.cwlogdir != NULL) 		tpl_addVar(vars, TPLADD, "CWLOGDIR", cfg.cwlogdir);
	if (cfg.saveinithistory == 1)	tpl_addVar(vars, TPLADD, "SAVEINITHISTORYCHECKED", "selected");

	tpl_printf(vars, TPLADD, "CLIENTTIMEOUT", "%ld", cfg.ctimeout);
	tpl_printf(vars, TPLADD, "FALLBACKTIMEOUT", "%ld", cfg.ftimeout);
	tpl_printf(vars, TPLADD, "CLIENTMAXIDLE", "%d", cfg.cmaxidle);
	tpl_printf(vars, TPLADD, "CACHEDELAY", "%ld", cfg.delay);

	tpl_printf(vars, TPLADD, "SLEEP", "%d", cfg.tosleep);
	if (cfg.ulparent == 1) tpl_addVar(vars, TPLADD, "UNLOCKPARENTALCHECKED", "selected");

	tpl_printf(vars, TPLADD, "SERIALTIMEOUT", "%d", cfg.srtimeout);


	if (cfg.waitforcards == 1)	tpl_addVar(vars, TPLADD, "WAITFORCARDSCHECKED", "selected");
	if (cfg.preferlocalcards == 1)	tpl_addVar(vars, TPLADD, "PREFERLOCALCARDSCHECKED", "selected");



	if (cfg.reader_restart_seconds)
		tpl_printf(vars, TPLADD, "READERRESTARTSECONDS", "%d", cfg.reader_restart_seconds);

	if (cfg.resolve_gethostbyname == 1)
		tpl_addVar(vars, TPLADD, "RESOLVER1", "selected");
	else
		tpl_addVar(vars, TPLADD, "RESOLVER0", "selected");

	tpl_printf(vars, TPLADD, "FAILBANTIME", "%d", cfg.failbantime);
	tpl_printf(vars, TPLADD, "FAILBANCOUNT", "%d", cfg.failbancount);

#ifdef CS_WITH_DOUBLECHECK
	if(cfg.double_check == 1)
		tpl_addVar(vars, TPLADD, "DCHECKCSELECTED", "selected");
#endif

	return tpl_getTpl(vars, "CONFIGGLOBAL");
}

char *send_oscam_config_loadbalancer(struct templatevars *vars, struct uriparams *params, struct in_addr in) {
	int i;

	if (strcmp(getParam(params, "button"), "Load Stats") == 0) {
		clear_all_stat();
		load_stat_from_file();
		tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<B>Stats loades from file</B><BR><BR>");
	}

	if (strcmp(getParam(params, "button"), "Save Stats") == 0) {
		save_stat_to_file();
		tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<B>Stats saved to file</B><BR><BR>");
	}

	if (strcmp(getParam(params, "button"), "Clear Stats") == 0) {
		clear_all_stat();
		tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<B>Stats cleared completly</B><BR><BR>");
	}

	if (strcmp(getParam(params, "action"),"execute") == 0) {

		memset(cfg.ser_device, 0, sizeof(cfg.ser_device));
		memset(&cfg.lb_retrylimittab, 0, sizeof(RETRYLIMITTAB));
		for(i = 0; i < (*params).paramcount; ++i) {
			if ((strcmp((*params).params[i], "part")) && (strcmp((*params).params[i], "action"))) {
				//tpl_printf(vars, TPLAPPEND, "MESSAGE", "Parameter: %s set to Value: %s<BR>\n", (*params).params[i], (*params).values[i]);
				//we use the same function as used for parsing the config tokens
				if((*params).values[i][0])
					chk_t_global((*params).params[i], (*params).values[i]);
			}
		}
		tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<BR><BR><B>Configuration Loadbalancer done.</B><BR><BR>");
		if(write_config()==0) refresh_oscam(REFR_SERVER, in);
		else tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}

	tpl_printf(vars, TPLADD, "TMP", "LBMODE%d", cfg.lb_mode);
	tpl_addVar(vars, TPLADD, tpl_getVar(vars, "TMP"), "selected");

	tpl_printf(vars, TPLADD, "LBSAVE", "%d",cfg.lb_save);
	tpl_printf(vars, TPLADD, "LBSAVEPATH", "%s", cfg.lb_savepath?cfg.lb_savepath:"");

	tpl_printf(vars, TPLADD, "LBNBESTREADERS", "%d",cfg.lb_nbest_readers);
	tpl_printf(vars, TPLADD, "LBNFBREADERS", "%d",cfg.lb_nfb_readers);
	tpl_printf(vars, TPLADD, "LBMINECMCOUNT", "%d",cfg.lb_min_ecmcount);
	tpl_printf(vars, TPLADD, "LBMAXECEMCOUNT", "%d",cfg.lb_max_ecmcount);
	tpl_printf(vars, TPLADD, "LBRETRYLIMIT", "%d",cfg.lb_retrylimit);
	
	char *value = mk_t_retrylimittab(&cfg.lb_retrylimittab);
	tpl_printf(vars, TPLADD, "LBRETRYLIMITS", value);
	free(value);
	
	tpl_printf(vars, TPLADD, "LBREOPENSECONDS", "%d",cfg.lb_reopen_seconds);
	tpl_printf(vars, TPLADD, "LBCLEANUP", "%d",cfg.lb_stat_cleanup);
	if (cfg.lb_use_locking) tpl_addVar(vars, TPLADD, "USELOCKINGCHECKED", "selected");

	return tpl_getTpl(vars, "CONFIGLOADBALANCER");
}

char *send_oscam_config_camd33(struct templatevars *vars, struct uriparams *params, struct in_addr in) {
	int i;

	if (strcmp(getParam(params, "action"), "execute") == 0) {
		for(i = 0; i < (*params).paramcount; ++i) {
			if ((strcmp((*params).params[i], "part")) && (strcmp((*params).params[i], "action"))) {
				tpl_printf(vars, TPLAPPEND, "MESSAGE", "Parameter: %s set to Value: %s<BR>\n", (*params).params[i], (*params).values[i]);
				if (strcmp((*params).params[i], "nocrypt") == 0) {
					clear_sip(&cfg.c33_plain);
				}
				//we use the same function as used for parsing the config tokens
				chk_t_camd33((*params).params[i], (*params).values[i]);
			}
		}
		tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<BR><BR><B>Configuration camd33 done. You should restart Oscam now.</B><BR><BR>");
		if(write_config()==0) refresh_oscam(REFR_SERVER, in);
		else tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}

	if (cfg.c33_port) {
		tpl_printf(vars, TPLADD, "PORT", "%d", cfg.c33_port);
		if (cfg.c33_srvip != 0)		tpl_addVar(vars, TPLADD, "SERVERIP", cs_inet_ntoa(cfg.c33_srvip));
		if (cfg.c33_passive == 1)		tpl_addVar(vars, TPLADD, "PASSIVECHECKED", "selected");

		for (i = 0; i < (int) sizeof(cfg.c33_key); ++i) tpl_printf(vars, TPLAPPEND, "KEY", "%02X",cfg.c33_key[i]);
		struct s_ip *cip;
		char *dot="";
		for (cip = cfg.c33_plain; cip; cip = cip->next) {
			tpl_printf(vars, TPLAPPEND, "NOCRYPT", "%s%s", dot, cs_inet_ntoa(cip->ip[0]));
			if (cip->ip[0] != cip->ip[1]) tpl_printf(vars, TPLAPPEND, "NOCRYPT", "-%s", cs_inet_ntoa(cip->ip[1]));
			dot=",";
		}
	}

	return tpl_getTpl(vars, "CONFIGCAMD33");
}

char *send_oscam_config_camd35(struct templatevars *vars, struct uriparams *params, struct in_addr in) {
	int i;
	if ((strcmp(getParam(params, "action"),"execute") == 0) && (getParam(params, "port"))[0]) {
		for(i = 0; i < (*params).paramcount; ++i) {
			if ((strcmp((*params).params[i], "part")) && (strcmp((*params).params[i], "action"))) {
				tpl_printf(vars, TPLAPPEND, "MESSAGE", "Parameter: %s set to Value: %s<BR>\n", (*params).params[i], (*params).values[i]);
				//we use the same function as used for parsing the config tokens
				chk_t_camd35((*params).params[i], (*params).values[i]);
			}
		}
		tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<BR><BR><B>Configuration camd35 done. You should restart Oscam now.</B><BR><BR>");
		if(write_config()==0) refresh_oscam(REFR_SERVER, in);
		else tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}

	if (cfg.c35_port) {
		tpl_printf(vars, TPLADD, "PORT", "%d", cfg.c35_port);
		if (cfg.c35_srvip != 0)
			tpl_addVar(vars, TPLAPPEND, "SERVERIP", cs_inet_ntoa(cfg.c35_srvip));

		if (cfg.c35_suppresscmd08)
			tpl_addVar(vars, TPLADD, "SUPPRESSCMD08", "checked");
	}
	return tpl_getTpl(vars, "CONFIGCAMD35");
}

char *send_oscam_config_camd35tcp(struct templatevars *vars, struct uriparams *params, struct in_addr in) {
	int i;
	if ((strcmp(getParam(params, "action"),"execute") == 0) && (getParam(params, "port"))[0]) {
		clear_ptab(&cfg.c35_tcp_ptab); /*clear Porttab*/
		for(i = 0; i < (*params).paramcount; ++i) {
			if ((strcmp((*params).params[i], "part")) && (strcmp((*params).params[i], "action"))) {
				tpl_printf(vars, TPLAPPEND, "MESSAGE", "Parameter: %s set to Value: %s<BR>\n", (*params).params[i], (*params).values[i]);
				//we use the same function as used for parsing the config tokens
				chk_t_camd35_tcp((*params).params[i], (*params).values[i]);
			}
		}
		tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<BR><BR><B>Configuration camd35 TCP done. You should restart Oscam now.</B><BR><BR>");
		if(write_config()==0) refresh_oscam(REFR_SERVER, in);
		else tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}

	if ((cfg.c35_tcp_ptab.nports > 0) && (cfg.c35_tcp_ptab.ports[0].s_port > 0)) {

		char *value = mk_t_camd35tcp_port();
		tpl_addVar(vars, TPLADD, "PORT", value);
		free(value);

		if (cfg.c35_tcp_srvip != 0)
			tpl_addVar(vars, TPLAPPEND, "SERVERIP", cs_inet_ntoa(cfg.c35_tcp_srvip));

	}
	return tpl_getTpl(vars, "CONFIGCAMD35TCP");
}

char *send_oscam_config_newcamd(struct templatevars *vars, struct uriparams *params, struct in_addr in) {
	int i;
	if (strcmp(getParam(params, "action"),"execute") == 0) {
		clear_ptab(&cfg.ncd_ptab); /*clear Porttab*/
		for(i = 0; i < (*params).paramcount; ++i) {
			if ((strcmp((*params).params[i], "part")) && (strcmp((*params).params[i], "action"))) {
				tpl_printf(vars, TPLAPPEND, "MESSAGE", "Parameter: %s set to Value: %s<BR>\n", (*params).params[i], (*params).values[i]);
				//we use the same function as used for parsing the config tokens
				if (strcmp((*params).params[i], "allowed") == 0) {
					clear_sip(&cfg.ncd_allowed);
				}
				chk_t_newcamd((*params).params[i], (*params).values[i]);
			}
		}
		tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<BR><BR><B>Configuration Newcamd done. You should restart Oscam now.</B><BR><BR>");
		if(write_config()==0) refresh_oscam(REFR_SERVER, in);
		else tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}

	if ((cfg.ncd_ptab.nports > 0) && (cfg.ncd_ptab.ports[0].s_port > 0)) {

		char *value = mk_t_newcamd_port();
		tpl_addVar(vars, TPLADD, "PORT", value);
		free(value);

		if (cfg.ncd_srvip != 0)
			tpl_addVar(vars, TPLADD, "SERVERIP", cs_inet_ntoa(cfg.ncd_srvip));

		for (i = 0; i < 14; i++) tpl_printf(vars, TPLAPPEND, "KEY", "%02X", cfg.ncd_key[i]);

		struct s_ip *cip;
		char *dot = "";
		for (cip = cfg.ncd_allowed; cip; cip = cip->next) {
			tpl_printf(vars, TPLAPPEND, "ALLOWED", "%s%s", dot, cs_inet_ntoa(cip->ip[0]));
			if (cip->ip[0] != cip->ip[1]) tpl_printf(vars, TPLAPPEND, "ALLOWED", "-%s", cs_inet_ntoa(cip->ip[1]));
			dot=",";
		}

		if (cfg.ncd_keepalive)
			tpl_addVar(vars, TPLADD, "KEEPALIVE", "checked");
		if (cfg.ncd_mgclient)
			tpl_addVar(vars, TPLADD, "MGCLIENTCHK", "checked");
	}
	return tpl_getTpl(vars, "CONFIGNEWCAMD");
}

char *send_oscam_config_radegast(struct templatevars *vars, struct uriparams *params, struct in_addr in) {
	int i;
	if (strcmp(getParam(params, "action"),"execute") == 0) {
		for(i = 0; i < (*params).paramcount; ++i) {
			if ((strcmp((*params).params[i], "part")) && (strcmp((*params).params[i], "action"))) {
				tpl_printf(vars, TPLAPPEND, "MESSAGE", "Parameter: %s set to Value: %s<BR>\n", (*params).params[i], (*params).values[i]);
				if (strcmp((*params).params[i], "allowed") == 0) {
					clear_sip(&cfg.rad_allowed);
				}
				//we use the same function as used for parsing the config tokens
				chk_t_radegast((*params).params[i], (*params).values[i]);
			}
		}
		tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<BR><BR><B>Configuration Radegast done. You should restart Oscam now.</B><BR><BR>");
		if(write_config()==0) refresh_oscam(REFR_SERVER, in);
		else tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}
	tpl_printf(vars, TPLADD, "PORT", "%d", cfg.rad_port);
	if (cfg.rad_srvip != 0)
	tpl_addVar(vars, TPLADD, "SERVERIP", cs_inet_ntoa(cfg.rad_srvip));
	tpl_addVar(vars, TPLADD, "USER", cfg.rad_usr);

	struct s_ip *cip;
	char *dot="";
	for (cip=cfg.rad_allowed; cip; cip=cip->next) {
		tpl_printf(vars, TPLAPPEND, "ALLOWED", "%s%s", dot, cs_inet_ntoa(cip->ip[0]));
		if (cip->ip[0] != cip->ip[1])
			tpl_printf(vars, TPLAPPEND, "ALLOWED", "-%s", cs_inet_ntoa(cip->ip[1]));
		dot=",";
	}

	return tpl_getTpl(vars, "CONFIGRADEGAST");
}

char *send_oscam_config_cccam(struct templatevars *vars, struct uriparams *params, struct in_addr in) {


	if (strcmp(getParam(params, "button"), "Refresh global list") == 0) {
		cs_debug_mask(D_TRACE, "Entitlements: Refresh Shares start");
		refresh_shares();
		cs_debug_mask(D_TRACE, "Entitlements: Refresh Shares finished");
		tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<B>Refresh Shares started</B><BR><BR>");
	}

	int i;
	if (strcmp(getParam(params, "action"),"execute") == 0) {
		for(i = 0; i < (*params).paramcount; ++i) {
			if ((strcmp((*params).params[i], "part")) && (strcmp((*params).params[i], "action"))) {
				tpl_printf(vars, TPLAPPEND, "MESSAGE", "Parameter: %s set to Value: %s<BR>\n", (*params).params[i], (*params).values[i]);
				//we use the same function as used for parsing the config tokens
				chk_t_cccam((*params).params[i], (*params).values[i]);
			}
		}
		if(write_config()==0) refresh_oscam(REFR_SERVER, in);
		else tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}

	tpl_printf(vars, TPLAPPEND, "PORT", "%d", cfg.cc_port);
	tpl_printf(vars, TPLADD, "RESHARE", "%d", cfg.cc_reshare);

	if (!strcmp((char*)cfg.cc_version,"2.0.11")) {
		tpl_addVar(vars, TPLADD, "VERSIONSELECTED0", "selected");
	} else if (!strcmp((char*)cfg.cc_version,"2.1.1")) {
		tpl_addVar(vars, TPLADD, "VERSIONSELECTED1", "selected");
	} else if (!strcmp((char*)cfg.cc_version,"2.1.2")) {
		tpl_addVar(vars, TPLADD, "VERSIONSELECTED2", "selected");
	} else if (!strcmp((char*)cfg.cc_version,"2.1.3")) {
		tpl_addVar(vars, TPLADD, "VERSIONSELECTED3", "selected");
	} else if (!strcmp((char*)cfg.cc_version,"2.1.4")) {
		tpl_addVar(vars, TPLADD, "VERSIONSELECTED4", "selected");
	} else if (!strcmp((char*)cfg.cc_version,"2.2.0")) {
		tpl_addVar(vars, TPLADD, "VERSIONSELECTED5", "selected");
	} else if (!strcmp((char*)cfg.cc_version,"2.2.1")) {
		tpl_addVar(vars, TPLADD, "VERSIONSELECTED6", "selected");
	}

	tpl_printf(vars, TPLADD, "UPDATEINTERVAL", "%d", cfg.cc_update_interval);
	if (cfg.cc_stealth)
		tpl_printf(vars, TPLADD, "STEALTH", "selected");

	tpl_printf(vars, TPLADD, "TMP", "MINIMIZECARDSELECTED%d", cfg.cc_minimize_cards);
	tpl_addVar(vars, TPLADD, tpl_getVar(vars, "TMP"), "selected");

	tpl_printf(vars, TPLADD, "TMP", "RESHAREMODE%d", cfg.cc_reshare_services);
	tpl_addVar(vars, TPLADD, tpl_getVar(vars, "TMP"), "selected");

	if (cfg.cc_ignore_reshare)
		tpl_printf(vars, TPLADD, "IGNORERESHARE", "selected");
	
	if (cfg.cc_forward_origin_card)
		tpl_printf(vars, TPLADD, "FORWARDORIGINCARD", "selected");
	
	if (cfg.cc_keep_connected)
		tpl_printf(vars, TPLADD, "KEEPCONNECTED", "selected");


	return tpl_getTpl(vars, "CONFIGCCCAM");
}

char *send_oscam_config_monitor(struct templatevars *vars, struct uriparams *params, struct in_addr in) {
	int i;
	if (strcmp(getParam(params, "action"),"execute") == 0) {

		//cleanup
		clear_sip(&cfg.mon_allowed);
		clear_sip(&cfg.http_allowed);

		for(i = 0; i < (*params).paramcount; ++i) {
			if ((strcmp((*params).params[i], "part")) && (strcmp((*params).params[i], "action"))) {
				tpl_printf(vars, TPLAPPEND, "MESSAGE", "Parameter: %s set to Value: %s<BR>\n", (*params).params[i], (*params).values[i]);

				//we use the same function as used for parsing the config tokens
				if (strstr((*params).params[i], "http")) {
					chk_t_webif((*params).params[i], (*params).values[i]);
				} else {
					chk_t_monitor((*params).params[i], (*params).values[i]);
				}
			}
		}
		tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<BR><BR><B>Configuration Monitor done. You should restart Oscam now.</B><BR><BR>");
		if(write_config()==0) refresh_oscam(REFR_SERVER, in);
		else tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}
	tpl_printf(vars, TPLADD, "MONPORT", "%d", cfg.mon_port);
	if (cfg.mon_srvip != 0)
	tpl_addVar(vars, TPLADD, "SERVERIP", cs_inet_ntoa(cfg.mon_srvip));
	tpl_printf(vars, TPLADD, "AULOW", "%d", cfg.mon_aulow);
	tpl_printf(vars, TPLADD, "HIDECLIENTTO", "%d", cfg.mon_hideclient_to);
	if(cfg.mon_appendchaninfo)
		tpl_addVar(vars, TPLADD, "APPENDCHANINFO", "checked");

#ifdef WITH_SSL
	if(cfg.http_use_ssl)
		tpl_printf(vars, TPLADD, "HTTPPORT", "+%d", cfg.http_port);
	else
		tpl_printf(vars, TPLADD, "HTTPPORT", "%d", cfg.http_port);
#else
	tpl_printf(vars, TPLADD, "HTTPPORT", "%d", cfg.http_port);
#endif

	tpl_addVar(vars, TPLADD, "HTTPUSER", cfg.http_user);
	tpl_addVar(vars, TPLADD, "HTTPPASSWORD", cfg.http_pwd);

	// css style selector
	if(strlen(cfg.http_css) == 0) {
		tpl_addVar(vars, TPLADD, "CSSOPTIONS", "\t\t\t\t\t\t<option value=\"\" selected>embedded</option>\n");
	} else {
		tpl_addVar(vars, TPLADD, "CSSOPTIONS", "\t\t\t\t\t\t<option value=\"\">embedded</option>\n");
	}

	DIR *hdir;
	struct dirent *entry;
	hdir = opendir(cs_confdir);
	do {
		entry = readdir(hdir);
		if ((entry) && (strstr(entry->d_name, ".css"))) {
			if (strstr(cfg.http_css, entry->d_name)) {
				tpl_printf(vars, TPLAPPEND, "CSSOPTIONS", "\t\t\t\t\t\t<option value=\"%s%s\" selected>%s%s</option>\n",cs_confdir,entry->d_name,cs_confdir,entry->d_name);
			} else {
				tpl_printf(vars, TPLAPPEND, "CSSOPTIONS", "\t\t\t\t\t\t<option value=\"%s%s\">%s%s</option>\n",cs_confdir,entry->d_name,cs_confdir,entry->d_name);
			}
		}
	} while (entry);
	closedir(hdir);

	if (cfg.http_help_lang[0])
		tpl_addVar(vars, TPLADD, "HTTPHELPLANG", cfg.http_help_lang);
	else
		tpl_addVar(vars, TPLADD, "HTTPHELPLANG", "en");

	tpl_printf(vars, TPLADD, "HTTPREFRESH", "%d", cfg.http_refresh);
	tpl_addVar(vars, TPLADD, "HTTPTPL", cfg.http_tpl);
	tpl_addVar(vars, TPLADD, "HTTPSCRIPT", cfg.http_script);
	tpl_addVar(vars, TPLADD, "HTTPJSCRIPT", cfg.http_jscript);

	if (cfg.http_hide_idle_clients > 0) tpl_addVar(vars, TPLADD, "CHECKED", "checked");

	struct s_ip *cip;
	char *dot="";
	for (cip = cfg.mon_allowed; cip; cip = cip->next) {
		tpl_printf(vars, TPLAPPEND, "NOCRYPT", "%s%s", dot, cs_inet_ntoa(cip->ip[0]));
		if (cip->ip[0] != cip->ip[1]) tpl_printf(vars, TPLAPPEND, "NOCRYPT", "-%s", cs_inet_ntoa(cip->ip[1]));
		dot=",";
	}

	dot="";
	for (cip = cfg.http_allowed; cip; cip = cip->next) {
		tpl_printf(vars, TPLAPPEND, "HTTPALLOW", "%s%s", dot, cs_inet_ntoa(cip->ip[0]));
		if (cip->ip[0] != cip->ip[1]) tpl_printf(vars, TPLAPPEND, "HTTPALLOW", "-%s", cs_inet_ntoa(cip->ip[1]));
		dot=",";
	}

	tpl_printf(vars, TPLADD, "HTTPDYNDNS", "%s", cfg.http_dyndns);

	//Monlevel selector
	tpl_printf(vars, TPLADD, "TMP", "MONSELECTED%d", cfg.mon_level);
	tpl_addVar(vars, TPLADD, tpl_getVar(vars, "TMP"), "selected");

	if (cfg.http_full_cfg)
		tpl_addVar(vars, TPLADD, "HTTPSAVEFULLSELECT", "selected");

	return tpl_getTpl(vars, "CONFIGMONITOR");
}

char *send_oscam_config_serial(struct templatevars *vars, struct uriparams *params, struct in_addr in) {
	int i;
	if (strcmp(getParam(params, "action"),"execute") == 0) {
		//cfg.ser_device[0]='\0';
		memset(cfg.ser_device, 0, sizeof(cfg.ser_device));
		for(i = 0; i < (*params).paramcount; ++i) {
			if ((strcmp((*params).params[i], "part")) && (strcmp((*params).params[i], "action"))) {
				tpl_printf(vars, TPLAPPEND, "MESSAGE", "Parameter: %s set to Value: %s<BR>\n", (*params).params[i], (*params).values[i]);
				//we use the same function as used for parsing the config tokens
				if((*params).values[i][0])
					chk_t_serial((*params).params[i], (*params).values[i]);
			}
		}
		tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<BR><BR><B>Configuration Serial done. You should restart Oscam now.</B><BR><BR>");
		if(write_config()==0) refresh_oscam(REFR_SERVER, in);
		else tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}

	if (cfg.ser_device[0]){
		char sdevice[512];
		cs_strncpy(sdevice, cfg.ser_device, sizeof(sdevice));
		char *ptr;
		char delimiter[2]; delimiter[0] = 1; delimiter[1] = '\0';
		ptr = strtok(sdevice, delimiter);
		while(ptr != NULL) {
			tpl_printf(vars, TPLADD, "SERIALDEVICE", "%s", ptr);
			tpl_addVar(vars, TPLAPPEND, "DEVICES", tpl_getTpl(vars, "CONFIGSERIALDEVICEBIT"));
			ptr = strtok(NULL, delimiter);
		}
	}

	tpl_printf(vars, TPLADD, "SERIALDEVICE", "%s", "");
	tpl_addVar(vars, TPLAPPEND, "DEVICES", tpl_getTpl(vars, "CONFIGSERIALDEVICEBIT"));

	return tpl_getTpl(vars, "CONFIGSERIAL");
}

#ifdef HAVE_DVBAPI
char *send_oscam_config_dvbapi(struct templatevars *vars, struct uriparams *params, struct in_addr in) {
	int i;
	if (strcmp(getParam(params, "action"),"execute") == 0) {
		for(i = 0; i < (*params).paramcount; ++i) {
			if ((strcmp((*params).params[i], "part")) && (strcmp((*params).params[i], "action"))) {
				tpl_printf(vars, TPLAPPEND, "MESSAGE", "Parameter: %s set to Value: %s<BR>\n", (*params).params[i], (*params).values[i]);
				//we use the same function as used for parsing the config tokens
				chk_t_dvbapi((*params).params[i], (*params).values[i]);
			}
		}
		tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<BR><BR><B>Configuration DVB Api done. You should restart Oscam now.</B><BR><BR>");
		if(write_config()==0) refresh_oscam(REFR_SERVER, in);
		else tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}

	if (cfg.dvbapi_enabled > 0)
		tpl_addVar(vars, TPLADD, "ENABLEDCHECKED", "checked");

	if (cfg.dvbapi_au > 0)
		tpl_addVar(vars, TPLADD, "AUCHECKED", "checked");

	tpl_printf(vars, TPLADD, "BOXTYPE", "<option value=\"\"%s>None</option>\n", cfg.dvbapi_boxtype == 0 ? " selected" : "");
	for (i=1; i<=BOXTYPES; i++) {
		tpl_printf(vars, TPLAPPEND, "BOXTYPE", "<option%s>%s</option>\n", cfg.dvbapi_boxtype == i ? " selected" : "", boxdesc[i]);
	}

	if(cfg.dvbapi_usr[0])
		tpl_addVar(vars, TPLADD, "USER", cfg.dvbapi_usr);

	//PMT Mode
	tpl_printf(vars, TPLADD, "TMP", "PMTMODESELECTED%d", cfg.dvbapi_pmtmode);
	tpl_addVar(vars, TPLADD, tpl_getVar(vars, "TMP"), "selected");

	return tpl_getTpl(vars, "CONFIGDVBAPI");
}
#endif

#ifdef CS_ANTICASC
char *send_oscam_config_anticasc(struct templatevars *vars, struct uriparams *params, struct in_addr in) {
	int i;
	if (strcmp(getParam(params, "action"),"execute") == 0) {
		for(i = 0; i < (*params).paramcount; ++i) {
			if ((strcmp((*params).params[i], "part")) && (strcmp((*params).params[i], "action"))) {
				tpl_printf(vars, TPLAPPEND, "MESSAGE", "Parameter: %s set to Value: %s<BR>\n", (*params).params[i], (*params).values[i]);
				//we use the same function as used for parsing the config tokens
				chk_t_ac((*params).params[i], (*params).values[i]);
			}
		}
		tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<BR><BR><B>Configuration Anticascading done. You should restart Oscam now.</B><BR><BR>");
		refresh_oscam(REFR_ANTICASC, in);
		if(write_config()==0) refresh_oscam(REFR_SERVER, in);
		else tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}
	if (cfg.ac_enabled > 0) tpl_addVar(vars, TPLADD, "CHECKED", "checked");
	tpl_printf(vars, TPLADD, "NUMUSERS", "%d", cfg.ac_users);
	tpl_printf(vars, TPLADD, "SAMPLETIME", "%d", cfg.ac_stime);
	tpl_printf(vars, TPLADD, "SAMPLES", "%d", cfg.ac_samples);
	tpl_printf(vars, TPLADD, "PENALTY", "%d", cfg.ac_penalty);
	tpl_addVar(vars, TPLADD, "ACLOGFILE", cfg.ac_logfile);
	tpl_printf(vars, TPLADD, "FAKEDELAY", "%d", cfg.ac_fakedelay);
	tpl_printf(vars, TPLADD, "DENYSAMPLES", "%d", cfg.ac_denysamples);
	return tpl_getTpl(vars, "CONFIGANTICASC");
}
#endif

char *send_oscam_config(struct templatevars *vars, struct uriparams *params, struct in_addr in) {
	char *part = getParam(params, "part");
	if (!strcmp(part,"camd33")) return send_oscam_config_camd33(vars, params, in);
	else if (!strcmp(part,"camd35")) return send_oscam_config_camd35(vars, params, in);
	else if (!strcmp(part,"camd35tcp")) return send_oscam_config_camd35tcp(vars, params, in);
	else if (!strcmp(part,"newcamd")) return send_oscam_config_newcamd(vars, params, in);
	else if (!strcmp(part,"radegast")) return send_oscam_config_radegast(vars, params, in);
	else if (!strcmp(part,"cccam")) return send_oscam_config_cccam(vars, params, in);
#ifdef HAVE_DVBAPI
	else if (!strcmp(part,"dvbapi")) return send_oscam_config_dvbapi(vars, params, in);
#endif
#ifdef CS_ANTICASC
	else if (!strcmp(part,"anticasc")) return send_oscam_config_anticasc(vars, params, in);
#endif
	else if (!strcmp(part,"monitor")) return send_oscam_config_monitor(vars, params, in);
	else if (!strcmp(part,"serial")) return send_oscam_config_serial(vars, params, in);
	else if (!strcmp(part,"loadbalancer")) return send_oscam_config_loadbalancer(vars, params, in);
	else return send_oscam_config_global(vars, params, in);
}

void inactivate_reader(struct s_reader *rdr)
{
	if (rdr == first_active_reader)
		first_active_reader = first_active_reader->next;
	else {
		struct s_reader *rdr2, *prev;
		for (prev=first_active_reader, rdr2=first_active_reader->next; prev->next && rdr != rdr2 ; prev=prev->next, rdr2=rdr2->next); //find reader in active reader list, will not be found if first in list
		if (rdr2 == rdr) //found
			prev->next = rdr2->next; //remove from active reader list
	}
	if (rdr->client)
		kill_thread(rdr->client);
}

char *send_oscam_reader(struct templatevars *vars, struct uriparams *params, struct in_addr in) {
	struct s_reader *rdr;
	int i;

	if ((strcmp(getParam(params, "action"), "disable") == 0) || (strcmp(getParam(params, "action"), "enable") == 0)) {
		if(cfg.http_readonly) {
			tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<b>Webif is in readonly mode. Enabling or disabling readers is not possible!</b><BR>");
		} else {
			rdr = get_reader_by_label(getParam(params, "label"));
			if (rdr) {
				struct s_reader *rdr2;
				if (strcmp(getParam(params, "action"), "enable") == 0) {
					if (!rdr->enable) {
						rdr->next = NULL; //terminate active reader list
						if (!first_active_reader) {
							first_active_reader = rdr;
						} else {
							for (rdr2 = first_active_reader; rdr2->next ; rdr2 = rdr2->next); //find last reader in active reader list
							rdr2->next = rdr; //add 
						}
						rdr->enable = 1;
						restart_cardreader(rdr, 1);
					}
				} else {
					if (rdr->enable) {
						rdr->enable = 0;
						inactivate_reader(rdr);
					}
				}
				if(write_server() != 0)
					tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
			}
		}
	}

	if (strcmp(getParam(params, "action"), "delete") == 0) {
		if(cfg.http_readonly) {
			tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<b>Webif is in readonly mode. No deletion will be made!</b><BR>");
		} else {
			rdr = get_reader_by_label(getParam(params, "label"));
			if (rdr) {
				inactivate_reader(rdr);
				ll_remove(configured_readers, rdr);

				if(write_server()==0) refresh_oscam(REFR_READERS, in);
				else tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
			}
		}
	}

	if (strcmp(getParam(params, "action"), "reread") == 0) {
		rdr = get_reader_by_label(getParam(params, "label"));
		if (rdr) {
			//reset the counters
			for (i = 0; i < 4; i++) {
				rdr->emmerror[i] = 0;
				rdr->emmwritten[i] = 0;
				rdr->emmskipped[i] = 0;
				rdr->emmblocked[i] = 0;
			}
			/*
			if( rdr->enable == 1 && rdr->client->typ == 'r' && rdr->client->fd_m2c ) {
				uchar dummy[1]={0x00};
				write_to_pipe(rdr->client->fd_m2c, PIP_ID_CIN, dummy, 1);
			}*/

			refresh_oscam(REFR_READERS, in); // refresh all reader because  write pipe seams not work from here
		}
	}

	LL_ITER *itr = ll_iter_create(configured_readers);
	for (i = 0, rdr = ll_iter_next(itr); rdr && rdr->label[0]; rdr = ll_iter_next(itr), i++);
	tpl_printf(vars, TPLADD, "NEXTREADER", "Reader-%d", i); //Next Readername

	ll_iter_reset(itr); //going to iterate all configured readers
	while ((rdr = ll_iter_next(itr))) {

		if(rdr->label[0] && rdr->typ) {

			if (rdr->enable)
				tpl_addVar(vars, TPLADD, "READERCLASS", "enabledreader");
			else
				tpl_addVar(vars, TPLADD, "READERCLASS", "disabledreader");

			tpl_addVar(vars, TPLADD, "READERNAME", xml_encode(vars, rdr->label));
			tpl_addVar(vars, TPLADD, "READERNAMEENC", urlencode(vars, rdr->label));
			tpl_printf(vars, TPLADD, "EMMERRORUK", "%d", rdr->emmerror[UNKNOWN]);
			tpl_printf(vars, TPLADD, "EMMERRORG", "%d", rdr->emmerror[GLOBAL]);
			tpl_printf(vars, TPLADD, "EMMERRORS", "%d", rdr->emmerror[SHARED]);
			tpl_printf(vars, TPLADD, "EMMERRORUQ", "%d", rdr->emmerror[UNIQUE]);

			tpl_printf(vars, TPLADD, "EMMWRITTENUK", "%d", rdr->emmwritten[UNKNOWN]);
			tpl_printf(vars, TPLADD, "EMMWRITTENG", "%d", rdr->emmwritten[GLOBAL]);
			tpl_printf(vars, TPLADD, "EMMWRITTENS", "%d", rdr->emmwritten[SHARED]);
			tpl_printf(vars, TPLADD, "EMMWRITTENUQ", "%d", rdr->emmwritten[UNIQUE]);

			tpl_printf(vars, TPLADD, "EMMSKIPPEDUK", "%d", rdr->emmskipped[UNKNOWN]);
			tpl_printf(vars, TPLADD, "EMMSKIPPEDG", "%d", rdr->emmskipped[GLOBAL]);
			tpl_printf(vars, TPLADD, "EMMSKIPPEDS", "%d", rdr->emmskipped[SHARED]);
			tpl_printf(vars, TPLADD, "EMMSKIPPEDUQ", "%d", rdr->emmskipped[UNIQUE]);

			tpl_printf(vars, TPLADD, "EMMBLOCKEDUK", "%d", rdr->emmblocked[UNKNOWN]);
			tpl_printf(vars, TPLADD, "EMMBLOCKEDG", "%d", rdr->emmblocked[GLOBAL]);
			tpl_printf(vars, TPLADD, "EMMBLOCKEDS", "%d", rdr->emmblocked[SHARED]);
			tpl_printf(vars, TPLADD, "EMMBLOCKEDUQ", "%d", rdr->emmblocked[UNIQUE]);

			if (!(rdr->typ & R_IS_NETWORK)) { //reader is physical
				tpl_addVar(vars, TPLADD, "REFRICO", "image?i=ICREF");
				tpl_addVar(vars, TPLADD, "READERREFRESH", tpl_getTpl(vars, "READERREFRESHBIT"));
				tpl_addVar(vars, TPLADD, "ENTICO", "image?i=ICENT");
				tpl_addVar(vars, TPLADD, "ENTITLEMENT", tpl_getTpl(vars, "READERENTITLEBIT"));
			} else {
				tpl_addVar(vars, TPLADD, "READERREFRESH","");
				if (rdr->typ == R_CCCAM) {
					tpl_addVar(vars, TPLADD, "ENTICO", "image?i=ICENT");
					tpl_addVar(vars, TPLADD, "ENTITLEMENT", tpl_getTpl(vars, "READERENTITLEBIT"));
				} else {
					tpl_addVar(vars, TPLADD, "ENTITLEMENT","");
				}
			}

			if(rdr->enable == 0) {
				tpl_addVar(vars, TPLADD, "SWITCHICO", "image?i=ICENA");
				tpl_addVar(vars, TPLADD, "SWITCHTITLE", "enable this reader");
				tpl_addVar(vars, TPLADD, "SWITCH", "enable");
			} else {
				tpl_addVar(vars, TPLADD, "SWITCHICO", "image?i=ICDIS");
				tpl_addVar(vars, TPLADD, "SWITCHTITLE", "disable this reader");
				tpl_addVar(vars, TPLADD, "SWITCH", "disable");
			}

			tpl_addVar(vars, TPLADD, "CTYP", reader_get_type_desc(rdr, 0));

			tpl_addVar(vars, TPLAPPEND, "READERLIST", tpl_getTpl(vars, "READERSBIT"));
		}
	}
	ll_iter_release(itr);

#ifdef HAVE_PCSC
	tpl_addVar(vars, TPLAPPEND, "ADDPROTOCOL", "<option>pcsc</option>\n");
#endif

	for (i=0; i<CS_MAX_MOD; i++) {
		if (cardreader[i].desc[0]!=0)
			tpl_printf(vars, TPLAPPEND, "ADDPROTOCOL", "<option>%s</option>\n", cardreader[i].desc);
	}

	return tpl_getTpl(vars, "READERS");
}

char *send_oscam_reader_config(struct templatevars *vars, struct uriparams *params, struct in_addr in) {
	int i;
	char *reader_ = getParam(params, "label");
	char *value;

	struct s_reader *rdr;

	if(strcmp(getParam(params, "action"), "Add") == 0) {
		// Add new reader
		struct s_reader *newrdr;
		if(!cs_malloc(&newrdr,sizeof(struct s_reader), -1)) return "0";
		memset(newrdr, 0, sizeof(struct s_reader));
		ll_append(configured_readers, newrdr);
		newrdr->next = NULL; // terminate list
		newrdr->enable = 0; // do not start the reader because must configured before
		strcpy(newrdr->pincode, "none");
		for (i = 1; i < CS_MAXCAIDTAB; newrdr->ctab.mask[i++] = 0xffff);
		for (i = 0; i < (*params).paramcount; ++i) {
			if (strcmp((*params).params[i], "action"))
				chk_reader((*params).params[i], (*params).values[i], newrdr);
		}
		reader_ = newrdr->label;

	} else if(strcmp(getParam(params, "action"), "Save") == 0) {

		rdr = get_reader_by_label(getParam(params, "label"));
		char servicelabels[255]="";

		clear_caidtab(&rdr->ctab);
		clear_ftab(&rdr->ftab);
		clear_ftab(&rdr->fchid);
		if(rdr->aes_list) {
			aes_clear_entries(rdr);
		}

		rdr->grp = 0;
		rdr->auprovid = 0;
		for(i = 0; i < (*params).paramcount; ++i) {
			if ((strcmp((*params).params[i], "reader")) && (strcmp((*params).params[i], "action"))) {
				if (!strcmp((*params).params[i], "services"))
					snprintf(servicelabels + strlen(servicelabels), sizeof(servicelabels), "%s,", (*params).values[i]);
				else
					/*if(strlen((*params).values[i]) > 0)*/
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
			tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
	}

	rdr = get_reader_by_label(reader_);

	tpl_addVar(vars, TPLADD, "READERNAME", rdr->label);

	if(rdr->enable)
		tpl_addVar(vars, TPLADD, "ENABLED", "checked");

	tpl_printf(vars, TPLADD, "ACCOUNT",  "%s", rdr->r_usr);
	tpl_printf(vars, TPLADD, "PASSWORD",  "%s", rdr->r_pwd); 

	for (i=0; i<14; i++)
		tpl_printf(vars, TPLAPPEND, "NCD_KEY", "%02X", rdr->ncd_key[i]);

	tpl_addVar(vars, TPLADD, "PINCODE", rdr->pincode);
	if (rdr->emmfile) tpl_addVar(vars, TPLADD, "EMMFILE", (char *)rdr->emmfile);
	tpl_printf(vars, TPLADD, "INACTIVITYTIMEOUT", "%d", rdr->tcp_ito);
	tpl_printf(vars, TPLADD, "RECEIVETIMEOUT", "%d", rdr->tcp_rto);
	if(rdr->ncd_disable_server_filt)
		tpl_addVar(vars, TPLADD, "DISABLESERVERFILTERCHECKED", "checked");

	if(rdr->fallback)
		tpl_addVar(vars, TPLADD, "FALLBACKCHECKED", "checked");

	tpl_printf(vars, TPLADD, "LOGPORT", "%d", rdr->log_port);

	if(rdr->boxid)
		tpl_printf(vars, TPLADD, "BOXID", "%08X", rdr->boxid);

	tpl_addVar(vars, TPLADD, "USER", rdr->r_usr);
	tpl_addVar(vars, TPLADD, "PASS", rdr->r_pwd);

	if(rdr->audisabled)
		tpl_addVar(vars, TPLADD, "AUDISABLED", "checked");

	if(rdr->auprovid)
		tpl_printf(vars, TPLADD, "AUPROVID", "%06lX", rdr->auprovid);

	if(rdr->force_irdeto)
		tpl_addVar(vars, TPLADD, "FORCEIRDETOCHECKED", "checked");

	int len = check_filled(rdr->rsa_mod, 120);
	if(len > 0) {
		if(len > 64) len = 120;
		else len = 64;
		for (i = 0; i < len; i++) tpl_printf(vars, TPLAPPEND, "RSAKEY", "%02X", rdr->rsa_mod[i]);
	}
	
	len = check_filled(rdr->nagra_boxkey, 8);
	if(len > 0) {
		for (i = 0; i < 8 ; i++) tpl_printf(vars, TPLAPPEND, "BOXKEY", "%02X", rdr->nagra_boxkey[i]);
	}

	if ( rdr->atr[0])
		for (i = 0; i < rdr->atrlen/2; i++)
			tpl_printf(vars, TPLAPPEND, "ATR", "%02X", rdr->atr[i]);

	if(rdr->smargopatch)
		tpl_addVar(vars, TPLADD, "SMARGOPATCHCHECKED", "checked");

	if (rdr->detect&0x80)
		tpl_printf(vars, TPLADD, "DETECT", "!%s", RDR_CD_TXT[rdr->detect&0x7f]);
	else
		tpl_printf(vars, TPLADD, "DETECT", "%s", RDR_CD_TXT[rdr->detect&0x7f]);

	tpl_printf(vars, TPLADD, "MHZ", "%d", rdr->mhz);
	tpl_printf(vars, TPLADD, "CARDMHZ", "%d", rdr->cardmhz);

	tpl_printf(vars, TPLADD, "DEVICE", "%s", rdr->device);
	if(rdr->r_port)
		tpl_printf(vars, TPLAPPEND, "DEVICE", ",%d", rdr->r_port);
	if(rdr->l_port) {
		if(rdr->r_port)
			tpl_printf(vars, TPLAPPEND, "DEVICE", ",%d", rdr->l_port);
		else
			tpl_printf(vars, TPLAPPEND, "DEVICE", ",,%d", rdr->l_port);
	}

	//group
	value = mk_t_group(rdr->grp);
	tpl_printf(vars, TPLADD, "GRP", "%s", value);
	free(value);

	if(rdr->lb_weight)
		tpl_printf(vars, TPLADD, "LBWEIGHT", "%d", rdr->lb_weight);

	//services
	char sidok[MAX_SIDBITS+1];
	uint64ToBitchar((uint64)rdr->sidtabok, MAX_SIDBITS, sidok);
	char sidno[MAX_SIDBITS+1];
	uint64ToBitchar((uint64)rdr->sidtabno,MAX_SIDBITS, sidno);
	struct s_sidtab *sidtab = cfg.sidtab;
	//build matrix
	i = 0;
	while(sidtab != NULL) {
		tpl_addVar(vars, TPLADD, "SIDLABEL", sidtab->label);
		if(sidok[i]=='1') tpl_addVar(vars, TPLADD, "CHECKED", "checked");
		else tpl_addVar(vars, TPLADD, "CHECKED", "");
		tpl_addVar(vars, TPLAPPEND, "SIDS", tpl_getTpl(vars, "READERCONFIGSIDOKBIT"));
		if(sidno[i]=='1') tpl_addVar(vars, TPLADD, "CHECKED", "checked");
		else tpl_addVar(vars, TPLADD, "CHECKED", "");
		tpl_addVar(vars, TPLAPPEND, "SIDS", tpl_getTpl(vars, "READERCONFIGSIDNOBIT"));
		sidtab=sidtab->next;
		i++;
	}

	// CAID
	value = mk_t_caidtab(&rdr->ctab);
	tpl_addVar(vars, TPLADD, "CAIDS", value);
	free(value);

	// AESkeys
	value = mk_t_aeskeys(rdr);
	tpl_addVar(vars, TPLADD, "AESKEYS", value);
	free(value);

	//ident
	value = mk_t_ftab(&rdr->ftab);
	tpl_printf(vars, TPLADD, "IDENTS", "%s", value);
	free(value);

	//CHID
	value = mk_t_ftab(&rdr->fchid);
	tpl_printf(vars, TPLADD, "CHIDS", "%s", value);
	free(value);

	//class
	CLASSTAB *clstab = &rdr->cltab;
	char *dot="";
	for(i = 0; i < clstab->an; ++i) {
		tpl_printf(vars, TPLAPPEND, "CLASS", "%s%02x", dot, (int)clstab->aclass[i]);
		dot=",";
	}

	for(i = 0; i < clstab->bn; ++i) {
		tpl_printf(vars, TPLADD, "CLASS", "%s!%02x", dot, (int)clstab->bclass[i]);
		dot=",";
	}

	if (rdr->show_cls)
		tpl_printf(vars, TPLADD, "SHOWCLS", "%d", rdr->show_cls);

	if(rdr->cachemm)
		tpl_printf(vars, TPLADD, "EMMCACHE", "%d,%d,%d", rdr->cachemm, rdr->rewritemm, rdr->logemm);

	//savenano
	value = mk_t_nano(rdr, 0x02);
	tpl_addVar(vars, TPLADD, "SAVENANO", value);
	free(value);

	//blocknano
	value = mk_t_nano(rdr, 0x01);
	tpl_addVar(vars, TPLADD, "BLOCKNANO", value);
	free(value);

	if (rdr->blockemm_unknown)
		tpl_addVar(vars, TPLADD, "BLOCKEMMUNKNOWNCHK", "checked");
	if (rdr->blockemm_u)
		tpl_addVar(vars, TPLADD, "BLOCKEMMUNIQCHK", "checked");
	if (rdr->blockemm_s)
		tpl_addVar(vars, TPLADD, "BLOCKEMMSHAREDCHK", "checked");
	if (rdr->blockemm_g)
		tpl_addVar(vars, TPLADD, "BLOCKEMMGLOBALCHK", "checked");

	if (rdr->deprecated)
		tpl_addVar(vars, TPLADD, "DEPRECATEDCHCHECKED", "checked");

	if (!strcmp(rdr->cc_version, "2.0.11")) {
		tpl_addVar(vars, TPLADD, "CCCVERSIONSELECTED0", "selected");
	} else if (!strcmp(rdr->cc_version, "2.1.1")) {
		tpl_addVar(vars, TPLADD, "CCCVERSIONSELECTED1", "selected");
	} else if (!strcmp(rdr->cc_version, "2.1.2")) {
		tpl_addVar(vars, TPLADD, "CCCVERSIONSELECTED2", "selected");
	} else if (!strcmp(rdr->cc_version, "2.1.3")) {
		tpl_addVar(vars, TPLADD, "CCCVERSIONSELECTED3", "selected");
	} else if (!strcmp(rdr->cc_version, "2.1.4")) {
		tpl_addVar(vars, TPLADD, "CCCVERSIONSELECTED4", "selected");
	} else if (!strcmp(rdr->cc_version, "2.2.0")) {
		tpl_addVar(vars, TPLADD, "CCCVERSIONSELECTED5", "selected");
	} else if (!strcmp(rdr->cc_version, "2.2.1")) {
		tpl_addVar(vars, TPLADD, "CCCVERSIONSELECTED6", "selected");
	}

#ifdef LIBUSB
	tpl_addVar(vars, TPLADD, "DEVICEEP", tpl_getTpl(vars, "READERCONFIGDEVICEEPBIT"));

	if(!rdr->device_endpoint) {
		tpl_addVar(vars, TPLADD, "DEVICEOUTEP0", "selected");
	} else if (rdr->device_endpoint == 0x82) {
		tpl_addVar(vars, TPLADD, "DEVICEOUTEP1", "selected");
	} else if (rdr->device_endpoint == 0x81) {
		tpl_addVar(vars, TPLADD, "DEVICEOUTEP2", "selected");
	}
#else
	tpl_addVar(vars, TPLADD, "DEVICEEP", "not avail LIBUSB");
#endif

	tpl_printf(vars, TPLADD, "TMP", "NDSVERSION%d", rdr->ndsversion);
	tpl_addVar(vars, TPLADD, tpl_getVar(vars, "TMP"), "selected");

	tpl_printf(vars, TPLADD, "TMP", "NAGRAREAD%d", rdr->nagra_read);
	tpl_addVar(vars, TPLADD, tpl_getVar(vars, "TMP"), "selected");

	tpl_printf(vars, TPLADD, "CCCMAXHOP", "%d", rdr->cc_maxhop);
	if(rdr->cc_want_emu)
		tpl_addVar(vars, TPLADD, "CCCWANTEMUCHECKED", "checked");

	if(rdr->cc_keepalive)
		tpl_addVar(vars, TPLADD, "KEEPALIVECHECKED", "selected");

	if(rdr->cc_reshare)
		tpl_printf(vars, TPLADD, "RESHARE", "%d", rdr->cc_reshare);

	// Show only parameters which needed for the reader
	switch (rdr->typ) {
		case R_CONSTCW:
			tpl_addVar(vars, TPLADD, "PROTOCOL", "constcw");
			tpl_addVar(vars, TPLAPPEND, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGSTDHWREADERBIT"));
			break;
		case R_DB2COM1:
		case R_DB2COM2:
		case R_MOUSE :
			tpl_addVar(vars, TPLADD, "PROTOCOL", "mouse");
			tpl_addVar(vars, TPLAPPEND, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGSTDHWREADERBIT"));
			break;
		case R_MP35:
			tpl_addVar(vars, TPLADD, "PROTOCOL", "mp35");
			tpl_addVar(vars, TPLAPPEND, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGSTDHWREADERBIT"));
			break;
		case R_SC8in1 :
			tpl_addVar(vars, TPLADD, "PROTOCOL", "sc8in1");
			tpl_addVar(vars, TPLAPPEND, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGSTDHWREADERBIT"));
			break;
		case R_SMART :
			tpl_addVar(vars, TPLADD, "PROTOCOL", "smartreader");
			tpl_addVar(vars, TPLAPPEND, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGSTDHWREADERBIT"));
			break;
		case R_INTERNAL:
			tpl_addVar(vars, TPLADD, "PROTOCOL", "internal");
			tpl_addVar(vars, TPLAPPEND, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGSTDHWREADERBIT"));
			break;
		case R_SERIAL :
			tpl_addVar(vars, TPLADD, "PROTOCOL", "serial");
			tpl_addVar(vars, TPLAPPEND, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGSTDHWREADERBIT"));
			break;
		case R_CAMD35 :
			tpl_addVar(vars, TPLADD, "PROTOCOL", "camd35");
			tpl_addVar(vars, TPLAPPEND, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGCAMD35BIT"));
			break;
		case R_CS378X :
			tpl_addVar(vars, TPLADD, "PROTOCOL", "cs378x");
			tpl_addVar(vars, TPLAPPEND, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGCS378XBIT"));
			break;
		case R_RADEGAST:
			tpl_addVar(vars, TPLADD, "PROTOCOL", "radegast");
			tpl_addVar(vars, TPLAPPEND, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGRADEGASTBIT"));
			break;
		case R_NEWCAMD :
			if ( rdr->ncd_proto == NCD_525 ){
				tpl_addVar(vars, TPLADD, "PROTOCOL", "newcamd525");
				tpl_addVar(vars, TPLAPPEND, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGNCD525BIT"));
			} else if ( rdr->ncd_proto == NCD_524 ) {
				tpl_addVar(vars, TPLADD, "PROTOCOL", "newcamd524");
				tpl_addVar(vars, TPLAPPEND, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGNCD524BIT"));
			}
			break;
		case R_CCCAM :
			tpl_addVar(vars, TPLADD, "PROTOCOL", "cccam");
			tpl_addVar(vars, TPLAPPEND, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGCCCAMBIT"));
			break;
#ifdef HAVE_PCSC
		case R_PCSC :
			tpl_addVar(vars, TPLADD, "PROTOCOL", "pcsc");
			tpl_addVar(vars, TPLAPPEND, "READERDEPENDINGCONFIG", tpl_getTpl(vars, "READERCONFIGSTDHWREADERBIT"));
			break;
#endif
		default :
			tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<b>Error: protocol not resolvable</b><BR>");
			tpl_printf(vars, TPLAPPEND, "MESSAGE", "<b>Error: protocol number: %d readername: %s</b><BR>", rdr->typ, rdr->label);
			break;

	}
	return tpl_getTpl(vars, "READERCONFIG");
}

char *send_oscam_reader_stats(struct templatevars *vars, struct uriparams *params, struct in_addr in, int apicall) {

	tpl_printf(vars, TPLADD, "CALLINGIP", "%s", inet_ntoa(in));

	struct s_reader *rdr = get_reader_by_label(getParam(params, "label"));
	if(!rdr) return "0";

	if (!apicall)
		tpl_printf(vars, TPLADD, "LABEL", "%s", rdr->label);
	else
		tpl_printf(vars, TPLADD, "READERNAME", "%s", rdr->label);

	char *stxt[]={"found", "cache1", "cache2", "emu",
			"not found", "timeout", "sleeping",
			"fake", "invalid", "corrupt", "no card", "expdate",
			"disabled", "stopped"};

	if (apicall) {
		int i, emmcount = 0;
		char *ttxt[]={"unknown", "unique", "shared", "global"};

		for (i=0; i<4; i++) {
			tpl_addVar(vars, TPLADD, "EMMRESULT", "error");
			tpl_printf(vars, TPLADD, "EMMTYPE", "%s", ttxt[i]);
			tpl_printf(vars, TPLADD, "EMMCOUNT", "%d", rdr->emmerror[i]);
			tpl_addVar(vars, TPLAPPEND, "EMMSTATS", tpl_getTpl(vars, "APIREADERSTATSEMMBIT"));
			emmcount += rdr->emmerror[i];
			tpl_printf(vars, TPLADD, "TOTALERROR", "%d", emmcount);
		}
		emmcount = 0;
		for (i=0; i<4; i++) {
			tpl_addVar(vars, TPLADD, "EMMRESULT", "written");
			tpl_printf(vars, TPLADD, "EMMTYPE", "%s", ttxt[i]);
			tpl_printf(vars, TPLADD, "EMMCOUNT", "%d", rdr->emmwritten[i]);
			tpl_addVar(vars, TPLAPPEND, "EMMSTATS", tpl_getTpl(vars, "APIREADERSTATSEMMBIT"));
			emmcount += rdr->emmwritten[i];
			tpl_printf(vars, TPLADD, "TOTALWRITTEN", "%d", emmcount);
		}
		emmcount = 0;
		for (i=0; i<4; i++) {
			tpl_addVar(vars, TPLADD, "EMMRESULT", "skipped");
			tpl_printf(vars, TPLADD, "EMMTYPE", "%s", ttxt[i]);
			tpl_printf(vars, TPLADD, "EMMCOUNT", "%d", rdr->emmskipped[i]);
			tpl_addVar(vars, TPLAPPEND, "EMMSTATS", tpl_getTpl(vars, "APIREADERSTATSEMMBIT"));
			emmcount += rdr->emmskipped[i];
			tpl_printf(vars, TPLADD, "TOTALSKIPPED", "%d", emmcount);
		}
		emmcount = 0;
		for (i=0; i<4; i++) {
			tpl_addVar(vars, TPLADD, "EMMRESULT", "blocked");
			tpl_printf(vars, TPLADD, "EMMTYPE", "%s", ttxt[i]);
			tpl_printf(vars, TPLADD, "EMMCOUNT", "%d", rdr->emmblocked[i]);
			tpl_addVar(vars, TPLAPPEND, "EMMSTATS", tpl_getTpl(vars, "APIREADERSTATSEMMBIT"));
			emmcount += rdr->emmblocked[i];
			tpl_printf(vars, TPLADD, "TOTALBLOCKED", "%d", emmcount);
		}
	}

	int rc2hide = (-1);
	if (strlen(getParam(params, "hide")) > 0)
			rc2hide = atoi(getParam(params, "hide"));

	int rowcount = 0;
	uint64 ecmcount = 0;
	time_t lastaccess=0;

	if (rdr->lb_stat) {

		LL_ITER *it = ll_iter_create(rdr->lb_stat);
		READER_STAT *stat = ll_iter_next(it);
		while (stat) {

			if (!(stat->rc == rc2hide)) {
				struct tm lt;
				localtime_r(&stat->last_received, &lt);
				ecmcount += stat->ecm_count;
				if (!apicall) {
					tpl_printf(vars, TPLADD, "CHANNEL", "%04X:%06lX:%04X", stat->caid, stat->prid, stat->srvid);
					tpl_printf(vars, TPLADD, "CHANNELNAME","%s", xml_encode(vars, get_servicename(stat->srvid, stat->caid)));
					tpl_printf(vars, TPLADD, "RC", "%s", stxt[stat->rc]);
					tpl_printf(vars, TPLADD, "TIME", "%dms", stat->time_avg);
					if (stat->time_stat[stat->time_idx])
						tpl_printf(vars, TPLADD, "TIMELAST", "%dms", stat->time_stat[stat->time_idx]);
					else
						tpl_printf(vars, TPLADD, "TIMELAST", "");
					tpl_printf(vars, TPLADD, "COUNT", "%d", stat->ecm_count);

					if(stat->last_received) {
						tpl_printf(vars, TPLADD, "LAST", "%02d.%02d.%02d %02d:%02d:%02d", lt.tm_mday, lt.tm_mon+1, lt.tm_year%100, lt.tm_hour, lt.tm_min, lt.tm_sec);

					} else {
						tpl_addVar(vars, TPLADD, "LAST","never");
					}
				} else {
					tpl_printf(vars, TPLADD, "ECMCAID", "%04X", stat->caid);
					tpl_printf(vars, TPLADD, "ECMPROVID", "%06lX", stat->prid);
					tpl_printf(vars, TPLADD, "ECMSRVID", "%04X", stat->srvid);
					tpl_addVar(vars, TPLADD, "ECMCHANNELNAME", xml_encode(vars, get_servicename(stat->srvid, stat->caid)));
					tpl_printf(vars, TPLADD, "ECMTIME", "%d", stat->time_avg);
					tpl_printf(vars, TPLADD, "ECMTIMELAST", "%d", stat->time_stat[stat->time_idx]);
					tpl_printf(vars, TPLADD, "ECMRC", "%d", stat->rc);
					tpl_printf(vars, TPLADD, "ECMRCS", "%s", stxt[stat->rc]);
					if(stat->last_received) {
						char tbuffer [30];
						strftime(tbuffer, 30, "%Y-%m-%dT%H:%M:%S%z", &lt);
						tpl_addVar(vars, TPLADD, "ECMLAST", tbuffer);
					} else {
						tpl_addVar(vars, TPLADD, "ECMLAST", "");
					}
					tpl_printf(vars, TPLADD, "ECMCOUNT", "%d", stat->ecm_count);

					if (stat->last_received > lastaccess)
						lastaccess = stat->last_received;
				}

				if (!apicall) {
					if (stat->rc == 4) {
						tpl_addVar(vars, TPLAPPEND, "READERSTATSROWNOTFOUND", tpl_getTpl(vars, "READERSTATSBIT"));
						tpl_addVar(vars, TPLADD, "READERSTATSNFHEADLINE", "\t\t<TR><TD CLASS=\"subheadline\" colspan=\"7\">Not found</TD></TR>\n");
					}
					else
						tpl_addVar(vars, TPLAPPEND, "READERSTATSROWFOUND", tpl_getTpl(vars, "READERSTATSBIT"));
				} else {

					tpl_addVar(vars, TPLAPPEND, "ECMSTATS", tpl_getTpl(vars, "APIREADERSTATSECMBIT"));
				}
			}

		stat = ll_iter_next(it);
		rowcount++;
		}

		ll_iter_release(it);

	} else {
		tpl_addVar(vars, TPLAPPEND, "READERSTATSROW","<TR><TD colspan=\"6\"> No statistics found </TD></TR>");
	}

	tpl_printf(vars, TPLADD, "ROWCOUNT", "%d", rowcount);

	if (lastaccess > 0){
		char tbuffer [30];
		struct tm lt;
		localtime_r(&lastaccess, &lt);
		strftime(tbuffer, 30, "%Y-%m-%dT%H:%M:%S%z", &lt);
		tpl_addVar(vars, TPLADD, "LASTACCESS", tbuffer);
	} else {
		tpl_addVar(vars, TPLADD, "LASTACCESS", "");
	}

	tpl_printf(vars, TPLADD, "TOTALECM", "%llu", ecmcount);

	if(!apicall)
		return tpl_getTpl(vars, "READERSTATS");
	else
		return tpl_getTpl(vars, "APIREADERSTATS");
}

char *send_oscam_user_config_edit(struct templatevars *vars, struct uriparams *params, struct in_addr in) {
	struct s_auth *account, *ptr;
	char user[sizeof(first_client->account->usr)];

	if (strcmp(getParam(params, "action"), "Save As") == 0) cs_strncpy(user, getParam(params, "newuser"), sizeof(user)/sizeof(char));
	else cs_strncpy(user, getParam(params, "user"), sizeof(user)/sizeof(char));

	int i;

	for (account = cfg.account; account != NULL && strcmp(user, account->usr) != 0; account = account->next);

	// Create a new user if it doesn't yet
	if (account == NULL) {
		i = 1;
		while(strlen(user) < 1) {
			snprintf(user, sizeof(user)/sizeof(char) - 1, "NEWUSER%d", i);
			for (account = cfg.account; account != NULL && strcmp(user, account->usr) != 0; account = account->next);
			if(account != NULL) user[0] = '\0';
			++i;
		}
		if (!cs_malloc(&account, sizeof(struct s_auth), -1)) return "0";
		if(cfg.account == NULL) cfg.account = account;
		else {
			for (ptr = cfg.account; ptr != NULL && ptr->next != NULL; ptr = ptr->next);
			ptr->next = account;
		}
		memset(account, 0, sizeof(struct s_auth));
		cs_strncpy((char *)account->usr, user, sizeof(account->usr));
		account->monlvl=cfg.mon_level;
		account->tosleep=cfg.tosleep;
		for (i=1; i<CS_MAXCAIDTAB; account->ctab.mask[i++]=0xffff);
		for (i=1; i<CS_MAXTUNTAB; account->ttab.bt_srvid[i++]=0x0000);
		account->expirationdate=(time_t)NULL;
#ifdef CS_ANTICASC
		account->ac_users=cfg.ac_users;
		account->ac_penalty=cfg.ac_penalty;
		account->ac_idx = account->ac_idx + 1;
#endif
		tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<b>New user has been added with default settings</b><BR>");

		if (write_userdb(cfg.account)==0)
			refresh_oscam(REFR_ACCOUNTS, in);
		else
			tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<B>Write Config failed</B><BR><BR>");
		// need to reget account as writing to disk changes account!
		for (account = cfg.account; account != NULL && strcmp(user, account->usr) != 0; account = account->next);
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
		tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<B>Settings updated</B><BR><BR>");

		if (write_userdb(cfg.account)==0)
			refresh_oscam(REFR_ACCOUNTS, in);
		else
			tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<B>Write Config failed</B><BR><BR>");

		// need to reget account as writing to disk changes account!
		for (account = cfg.account; account != NULL && strcmp(user, account->usr) != 0; account = account->next);
	}

	tpl_addVar(vars, TPLADD, "USERNAME", account->usr);
	tpl_addVar(vars, TPLADD, "PASSWORD", account->pwd);
	tpl_addVar(vars, TPLADD, "DESCRIPTION", account->description);

	//Disabled
	if(account->disabled)
		tpl_addVar(vars, TPLADD, "DISABLEDCHECKED", "selected");

	//Expirationdate
	struct tm timeinfo;
	localtime_r (&account->expirationdate, &timeinfo);
	char buf [80];
	strftime (buf,80,"%Y-%m-%d",&timeinfo);
	if(strcmp(buf,"1970-01-01")) tpl_addVar(vars, TPLADD, "EXPDATE", buf);

	if(account->allowedtimeframe[0] && account->allowedtimeframe[1]) {
		tpl_printf(vars, TPLADD, "ALLOWEDTIMEFRAME", "%02d:%02d-%02d:%02d",
				account->allowedtimeframe[0]/60,
				account->allowedtimeframe[0]%60,
				account->allowedtimeframe[1]/60,
				account->allowedtimeframe[1]%60 );
	}

	//Group
	char *value = mk_t_group(account->grp);
	tpl_addVar(vars, TPLADD, "GROUPS", value);
	free(value);

	//Hostname
	tpl_addVar(vars, TPLADD, "DYNDNS", (char *)account->dyndns);

	//Uniq
	tpl_printf(vars, TPLADD, "TMP", "UNIQSELECTED%d", account->uniq);
	tpl_addVar(vars, TPLADD, tpl_getVar(vars, "TMP"), "selected");

	//Sleep
	if(!account->tosleep) tpl_addVar(vars, TPLADD, "SLEEP", "0");
	else tpl_printf(vars, TPLADD, "SLEEP", "%d", account->tosleep);
	//Monlevel selector
	tpl_printf(vars, TPLADD, "TMP", "MONSELECTED%d", account->monlvl);
	tpl_addVar(vars, TPLADD, tpl_getVar(vars, "TMP"), "selected");

	//Au
	if (account->autoau == 1)
		tpl_addVar(vars, TPLADD, "AUREADER", "1");
	else if (account->aureader_list) {
		struct s_reader *rdr;
		LL_ITER *itr = ll_iter_create(account->aureader_list);
		char *dot = "";
		while ((rdr = ll_iter_next(itr))) {
			tpl_printf(vars, TPLAPPEND, "AUREADER", "%s%s", dot, rdr->label);
			dot = ",";
		}
		ll_iter_release(itr);
	}

	/* SERVICES */
	//services - first we have to move the long sidtabok/sidtabno to a binary array
	char sidok[MAX_SIDBITS+1];
	uint64ToBitchar((uint64)account->sidtabok, MAX_SIDBITS, sidok);
	char sidno[MAX_SIDBITS+1];
	uint64ToBitchar((uint64)account->sidtabno, MAX_SIDBITS, sidno);
	struct s_sidtab *sidtab = cfg.sidtab;
	//build matrix
	i=0;
	while(sidtab != NULL) {
		tpl_addVar(vars, TPLADD, "SIDLABEL", sidtab->label);
		if(sidok[i]=='1') tpl_addVar(vars, TPLADD, "CHECKED", "checked");
		else tpl_addVar(vars, TPLADD, "CHECKED", "");
		tpl_addVar(vars, TPLAPPEND, "SIDS", tpl_getTpl(vars, "USEREDITSIDOKBIT"));
		if(sidno[i]=='1') tpl_addVar(vars, TPLADD, "CHECKED", "checked");
		else tpl_addVar(vars, TPLADD, "CHECKED", "");
		tpl_addVar(vars, TPLAPPEND, "SIDS", tpl_getTpl(vars, "USEREDITSIDNOBIT"));
		sidtab=sidtab->next;
		i++;
	}

	// CAID
	value = mk_t_caidtab(&account->ctab);
	tpl_addVar(vars, TPLADD, "CAIDS", value);
	free(value);

	//ident
	value = mk_t_ftab(&account->ftab);
	tpl_printf(vars, TPLADD, "IDENTS", "%s", value);
	free(value);

	//CHID
	value = mk_t_ftab(&account->fchid);
	tpl_printf(vars, TPLADD, "CHIDS", "%s", value);
	free(value);

	//Betatunnel
	value = mk_t_tuntab(&account->ttab);
	tpl_addVar(vars, TPLADD, "BETATUNNELS", value);
	free(value);

	//SUPPRESSCMD08
	if (account->c35_suppresscmd08)
		tpl_addVar(vars, TPLADD, "SUPPRESSCMD08", "selected");

	//Sleepsend
	tpl_printf(vars, TPLADD, "SLEEPSEND", "%d", account->c35_sleepsend);

	//Keepalive
	if (account->ncd_keepalive)
		tpl_addVar(vars, TPLADD, "KEEPALIVE", "selected");

#ifdef CS_ANTICASC
	tpl_printf(vars, TPLADD, "AC_USERS", "%d", account->ac_users);
	tpl_printf(vars, TPLADD, "AC_PENALTY", "%d", account->ac_penalty);
#endif

	tpl_printf(vars, TPLADD, "CCCMAXHOPS", "%d", account->cccmaxhops);
	tpl_printf(vars, TPLADD, "CCCRESHARE", "%d", account->cccreshare);
	if (account->cccignorereshare)
		tpl_printf(vars, TPLADD, "CCCIGNORERESHARE", "selected");

	//Failban
	tpl_printf(vars, TPLADD, "FAILBAN", "%d", account->failban);

	return tpl_getTpl(vars, "USEREDIT");
}

char *send_oscam_user_config(struct templatevars *vars, struct uriparams *params, struct in_addr in) {
	struct s_auth *account, *account2;
	char *user = getParam(params, "user");
	int found = 0, hideclient = 10;

	if (cfg.mon_hideclient_to > 10)
	hideclient = cfg.mon_hideclient_to;

	if (strcmp(getParam(params, "action"), "reinit") == 0) {
		if(!cfg.http_readonly)
			refresh_oscam(REFR_ACCOUNTS, in);
	}

	if (strcmp(getParam(params, "action"), "delete") == 0) {
		if(cfg.http_readonly) {
			tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<b>Webif is in readonly mode. No deletion will be made!</b><BR>");
		} else {
			account = cfg.account;
			if(strcmp(account->usr, user) == 0) {
				cfg.account = account->next;
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
				} while ((account = account->next) && (account->next != NULL));
			}

			if (found > 0) {
				if (write_userdb(cfg.account)==0)
					refresh_oscam(REFR_ACCOUNTS, in);
				else
					tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<B>Write Config failed</B><BR><BR>");

			} else tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<b>Sorry but the specified user doesn't exist. No deletion will be made!</b><BR>");
		}
	}

	if ((strcmp(getParam(params, "action"), "disable") == 0) || (strcmp(getParam(params, "action"), "enable") == 0)) {
		account = get_account_by_name(getParam(params, "user"));
		if (account) {
			if(strcmp(getParam(params, "action"), "disable") == 0)
				account->disabled = 1;
			else
				account->disabled = 0;
			if (write_userdb(cfg.account) == 0)
				refresh_oscam(REFR_ACCOUNTS, in);
		} else {
			tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<b>Sorry but the specified user doesn't exist. No deletion will be made!</b><BR>");
		}
	}

	if (strcmp(getParam(params, "action"), "resetstats") == 0) {
		account = get_account_by_name(getParam(params, "user"));
		if (account) clear_account_stats(account);
	}

	if (strcmp(getParam(params, "action"), "resetserverstats") == 0) {
		clear_system_stats();
	}

	if (strcmp(getParam(params, "action"), "resetalluserstats") == 0) {
		clear_all_account_stats();
	}

	if ((strcmp(getParam(params, "part"), "adduser") == 0) && (!cfg.http_readonly)) {
		tpl_addVar(vars, TPLAPPEND, "NEWUSERFORM", tpl_getTpl(vars, "ADDNEWUSER"));
	} else {
		if(cfg.http_refresh > 0) {
			tpl_printf(vars, TPLADD, "REFRESHTIME", "%d", cfg.http_refresh);
			tpl_addVar(vars, TPLADD, "REFRESHURL", "userconfig.html");
			tpl_addVar(vars, TPLADD, "REFRESH", tpl_getTpl(vars, "REFRESH"));
		}
	}

	/* List accounts*/
	char *status, *expired, *classname, *lastchan;
	time_t now = time((time_t)0);
	int isec = 0, isconnected = 0;

	for (account=cfg.account; (account); account=account->next) {
		//clear for next client
		status = "offline"; lastchan = "&nbsp;", expired = ""; classname = "offline";
		isconnected = 0; isec = 0;

		if(account->expirationdate && account->expirationdate < time(NULL)) {
			expired = " (expired)";
			classname = "expired";
		} else {
			expired = "";
		}

		if(account->disabled != 0) {
			expired = " (disabled)"; classname = "disabled";
			tpl_addVar(vars, TPLADDONCE, "SWITCHICO", "image?i=ICENA");
			tpl_addVar(vars, TPLADDONCE, "SWITCHTITLE", "enable this account");
			tpl_addVar(vars, TPLADDONCE, "SWITCH", "enable");
		} else {
			tpl_addVar(vars, TPLADDONCE, "SWITCHICO", "image?i=ICDIS");
			tpl_addVar(vars, TPLADDONCE, "SWITCHTITLE", "disable this account");
			tpl_addVar(vars, TPLADDONCE, "SWITCH", "disable");
		}

		int lastresponsetm = 0;
		char *proto = "";

		//search account in active clients
		int isactive = 0;
		struct s_client *cl;
		for (cl=first_client; cl ; cl=cl->next) {
			if (cl->account && !strcmp(cl->account->usr, account->usr)) {
				isconnected = 1;

				if (!isactive)
					status = "<b>connected</b>"; classname = "connected";

				isec = now - cl->last;
				if(isec < cfg.mon_hideclient_to) {
					proto = monitor_get_proto(cl);
					status = "<b>online</b>";
					classname = "online";
					lastchan = xml_encode(vars, get_servicename(cl->last_srvid, cl->last_caid));
					lastresponsetm = cl->cwlastresptime;
					isactive++;
				}
			}
		}

		tpl_printf(vars, TPLADDONCE, "CWOK", "%d", account->cwfound);
		tpl_printf(vars, TPLADDONCE, "CWNOK", "%d", account->cwnot);
		tpl_printf(vars, TPLADDONCE, "CWIGN", "%d", account->cwignored);
		tpl_printf(vars, TPLADDONCE, "CWTOUT", "%d", account->cwtout);
		tpl_printf(vars, TPLADDONCE, "CWCACHE", "%d", account->cwcache);
		tpl_printf(vars, TPLADDONCE, "CWTUN", "%d", account->cwtun);
		tpl_printf(vars, TPLADDONCE, "EMMOK", "%d", account->emmok);
		tpl_printf(vars, TPLADDONCE, "EMMNOK", "%d", account->emmnok);

		if ( isactive > 0 || !cfg.http_hide_idle_clients) {
			tpl_addVar(vars, TPLADDONCE, "LASTCHANNEL", lastchan);
			tpl_printf(vars, TPLADDONCE, "CWLASTRESPONSET", "%d", lastresponsetm);
			tpl_addVar(vars, TPLADDONCE, "CLIENTPROTO", proto);
			tpl_addVar(vars, TPLADDONCE, "IDLESECS", sec2timeformat(vars, isec));
		}

		tpl_addVar(vars, TPLADDONCE, "CLASSNAME", classname);
		tpl_addVar(vars, TPLADDONCE, "USER", xml_encode(vars, account->usr));
		tpl_addVar(vars, TPLADD, "USERENC", urlencode(vars, account->usr));
		tpl_addVar(vars, TPLADDONCE, "DESCRIPTION", xml_encode(vars, account->description));
		tpl_addVar(vars, TPLADD, "STATUS", status);
		tpl_addVar(vars, TPLAPPENDONCE, "STATUS", expired);
		// append row to table template
		tpl_addVar(vars, TPLAPPEND, "USERCONFIGS", tpl_getTpl(vars, "USERCONFIGLISTBIT"));

	}

	tpl_printf(vars, TPLADD, "TOTAL_CWOK", "%ld", first_client->cwfound);
	tpl_printf(vars, TPLADD, "TOTAL_CWNOK", "%ld", first_client->cwnot);
	tpl_printf(vars, TPLADD, "TOTAL_CWIGN", "%ld", first_client->cwignored);
	tpl_printf(vars, TPLADD, "TOTAL_CWTOUT", "%ld", first_client->cwtout);
	tpl_printf(vars, TPLADD, "TOTAL_CWCACHE", "%ld", first_client->cwcache);
	tpl_printf(vars, TPLADD, "TOTAL_CWTUN", "%ld", first_client->cwtun);
	
	return tpl_getTpl(vars, "USERCONFIGLIST");
}

char *send_oscam_entitlement(struct templatevars *vars, struct uriparams *params, struct in_addr in, int apicall) {

	//just to stop the guys open tedious tickets for warnings related to unused variables xD
	tpl_printf(vars, TPLADD, "CALLINGIP", "%s", inet_ntoa(in));
	tpl_printf(vars, TPLADD, "ISAPICALL", "%d", apicall);
	//**************

	/* build entitlements from reader init history */
	char *reader_ = getParam(params, "label");
	char *sharelist_ = getParam(params, "globallist");
	int show_global_list = sharelist_ && sharelist_[0]=='1';

	struct s_reader *rdr = get_reader_by_label(getParam(params, "label"));
	if (show_global_list || (cfg.saveinithistory && strlen(reader_) > 0) || rdr->typ == R_CCCAM) {

		if (show_global_list || (rdr->typ == R_CCCAM && rdr->enable == 1)) {

			if (show_global_list) {
					tpl_addVar(vars, TPLADD, "READERNAME", "GLOBAL");
					tpl_addVar(vars, TPLADD, "APIHOST", "GLOBAL");
					tpl_printf(vars, TPLADD, "APIHOSTPORT", "GLOBAL");
			} else {	
					tpl_addVar(vars, TPLADD, "READERNAME", rdr->label);
					tpl_addVar(vars, TPLADD, "APIHOST", rdr->device);
					tpl_printf(vars, TPLADD, "APIHOSTPORT", "%d", rdr->r_port);
			}	

			int cardcount = 0;
			int providercount = 0;
			int nodecount = 0;

			char *provider = "";

			struct cc_card *card;
			
			LLIST *cards = NULL;
			pthread_mutex_t *lock = NULL;
			
			if (show_global_list) {
					cards = get_and_lock_sharelist();
			} else {		
					struct s_client *rc = rdr->client;
					struct cc_data *rcc = (rc)?rc->cc:NULL;

					if (rcc && rcc->cards) {
							cards = rcc->cards;
							lock = &rcc->cards_busy;
							pthread_mutex_lock(lock);
					}
			}
			
			if (cards) {	
							
				uint8 serbuf[8];

                // sort cards by hop
                LL_ITER *it; 
                int i;
                for (i = 0; i < ll_count(cards); i++) {
                    it  = ll_iter_create(cards);
                    while ((card = ll_iter_next(it))) {
                        if (it->cur->nxt && card->hop > ((struct cc_card *)ll_iter_peek(it, 1))->hop) {
                            it->cur->obj = it->cur->nxt->obj;
                            it->cur->nxt->obj = card;
                        }
                    }
                    ll_iter_release(it);
                }
				
                it = ll_iter_create(cards);
                while ((card = ll_iter_next(it))) {

					if (!apicall) {
						if (show_global_list)
							rdr = card->origin_reader;
						if (rdr)
							tpl_printf(vars, TPLADD, "HOST", "%s:%d", rdr->device, rdr->r_port);
						tpl_printf(vars, TPLADD, "CAID", "%04X", card->caid);
					} else {
						tpl_printf(vars, TPLADD, "APICARDNUMBER", "%d", cardcount);
						tpl_printf(vars, TPLADD, "APICAID", "%04X", card->caid);
					}

					if (cc_UA_valid(card->hexserial)) { //Add UA:
						cc_UA_cccam2oscam(card->hexserial, serbuf, card->caid);
						tpl_printf(vars, TPLAPPEND, "HOST", "<BR>\nUA_Oscam:%s", cs_hexdump(0, serbuf, 8));
						tpl_printf(vars, TPLAPPEND, "HOST", "<BR>\nUA_CCcam:%s", cs_hexdump(0, card->hexserial, 8));
					}
#ifdef WITH_DEBUG
   					if (!apicall) {
								int n;
								LL_ITER *its = ll_iter_create(card->goodsids);
								struct cc_srvid *srv;
								n=0;
								tpl_printf(vars, TPLADD, "SERVICESGOOD", "");
								while ((srv=ll_iter_next(its))) {
										tpl_printf(vars, TPLAPPEND, "SERVICESGOOD", "%04X%s", srv->sid, ++n%10==0?"<BR>\n":" ");
								}
								ll_iter_release(its);
								
								its = ll_iter_create(card->badsids);
								n=0;
								tpl_printf(vars, TPLADD, "SERVICESBAD", "");
								while ((srv=ll_iter_next(its))) {
										tpl_printf(vars, TPLAPPEND, "SERVICESBAD", "%04X%s", srv->sid, ++n%10==0?"<BR>\n":" ");
								}
								ll_iter_release(its);
					}
#endif

					struct s_cardsystem *cs = get_cardsystem_by_caid(card->caid);
					
					if (cs)
						tpl_addVar(vars, TPLADD, "SYSTEM", cs->desc ? cs->desc : "");
					else
						tpl_addVar(vars, TPLADD, "SYSTEM", "???");

                    tpl_printf(vars, TPLADD, "SHAREID", "%08X", card->id);
                    tpl_printf(vars, TPLADD, "REMOTEID", "%08X", card->remote_id);
					tpl_printf(vars, TPLADD, "UPHOPS", "%d", card->hop);
					tpl_printf(vars, TPLADD, "MAXDOWN", "%d", card->maxdown);

					LL_ITER *pit = ll_iter_create(card->providers);
					struct cc_provider *prov;

					providercount = 0;

					if (!apicall)
						tpl_addVar(vars, TPLADD, "PROVIDERS", "");
					else
						tpl_addVar(vars, TPLADD, "PROVIDERLIST", "");

					while ((prov = ll_iter_next(pit))) {
						provider = xml_encode(vars, get_provider(card->caid, prov->prov));

						if (!apicall) {
							if (prov->sa[0] || prov->sa[1] || prov->sa[2] || prov->sa[3]) {
								tpl_printf(vars, TPLAPPEND, "PROVIDERS", "%s SA:%02X%02X%02X%02X<BR>\n", provider, prov->sa[0], prov->sa[1], prov->sa[2], prov->sa[3]);
							} else {
								tpl_printf(vars, TPLAPPEND, "PROVIDERS", "%s<BR>\n", provider);
							}
						} else {
							if (prov->sa[0] || prov->sa[1] || prov->sa[2] || prov->sa[3])
								tpl_printf(vars, TPLADD, "APIPROVIDERSA", "%02X%02X%02X%02X", prov->sa[0], prov->sa[1], prov->sa[2], prov->sa[3]);
							else
								tpl_addVar(vars, TPLADD, "APIPROVIDERSA","");
							tpl_printf(vars, TPLADD, "APIPROVIDERCAID", "%04X", card->caid);
							tpl_printf(vars, TPLADD, "APIPROVIDERPROVID", "%06X", prov->prov);
							tpl_printf(vars, TPLADD, "APIPROVIDERNUMBER", "%d", providercount);
							tpl_addVar(vars, TPLADD, "APIPROVIDERNAME", xml_encode(vars, provider));
							tpl_addVar(vars, TPLAPPEND, "PROVIDERLIST", tpl_getTpl(vars, "APICCCAMCARDPROVIDERBIT"));
						}
						providercount++;
						tpl_printf(vars, TPLADD, "APITOTALPROVIDERS", "%d", providercount);
					}

					ll_iter_release(pit);
					LL_ITER *nit = ll_iter_create(card->remote_nodes);
					uint8 *node;

					nodecount = 0;
					if (!apicall) tpl_addVar(vars, TPLADD, "NODES", "");
					else tpl_addVar(vars, TPLADD, "NODELIST", "");

					while ((node = ll_iter_next(nit))) {

						if (!apicall) {
							tpl_printf(vars, TPLAPPEND, "NODES", "%02X%02X%02X%02X%02X%02X%02X%02X<BR>\n",
									node[0], node[1], node[2], node[3], node[4], node[5], node[6], node[7]);
						} else {
							tpl_printf(vars, TPLADD, "APINODE", "%02X%02X%02X%02X%02X%02X%02X%02X", node[0], node[1], node[2], node[3], node[4], node[5], node[6], node[7]);
							tpl_printf(vars, TPLADD, "APINODENUMBER", "%d", nodecount);
							tpl_addVar(vars, TPLAPPEND, "NODELIST", tpl_getTpl(vars, "APICCCAMCARDNODEBIT"));
						}
						nodecount++;
						tpl_printf(vars, TPLADD, "APITOTALNODES", "%d", nodecount);
					}

					ll_iter_release(nit);

					if (!apicall)
						tpl_addVar(vars, TPLAPPEND, "CCCAMSTATSENTRY", tpl_getTpl(vars, "ENTITLEMENTCCCAMENTRYBIT"));
					else
						tpl_addVar(vars, TPLAPPEND, "CARDLIST", tpl_getTpl(vars, "APICCCAMCARDBIT"));

					cardcount++;
				}

				ll_iter_release(it);
				
				if (!apicall) {
					tpl_printf(vars, TPLADD, "TOTALS", "card count=%d", cardcount);
					tpl_addVar(vars, TPLADD, "ENTITLEMENTCONTENT", tpl_getTpl(vars, "ENTITLEMENTCCCAMBIT"));
				} else {
					tpl_printf(vars, TPLADD, "APITOTALCARDS", "%d", cardcount);
				}

			} else {
				if (!apicall) {
					tpl_addVar(vars, TPLADD, "ENTITLEMENTCONTENT", tpl_getTpl(vars, "ENTITLEMENTGENERICBIT"));
					tpl_addVar(vars, TPLADD, "LOGHISTORY", "no cards found<BR>\n");
				} else {
					tpl_printf(vars, TPLADD, "APITOTALCARDS", "%d", cardcount);
				}
			}

			if (show_global_list)
					unlock_sharelist();
			else if (lock)
					pthread_mutex_unlock(lock);

		} else {
			tpl_addVar(vars, TPLADD, "LOGHISTORY", "->");
			// normal non-cccam reader

			rdr = get_reader_by_label(reader_);

			if (rdr->init_history) {
				char *ptr, *ptr1 = NULL;
				for (ptr=strtok_r(rdr->init_history, "\n", &ptr1); ptr; ptr=strtok_r(NULL, "\n", &ptr1)) {
					tpl_printf(vars, TPLAPPEND, "LOGHISTORY", "%s<BR />", ptr);
					ptr1[-1]='\n';	
				}
			}

			tpl_addVar(vars, TPLADD, "READERNAME", rdr->label);
			tpl_addVar(vars, TPLADD, "ENTITLEMENTCONTENT", tpl_getTpl(vars, "ENTITLEMENTGENERICBIT"));
		}

	} else {
		tpl_addVar(vars, TPLADD, "LOGHISTORY",
				"You have to set saveinithistory=1 in your config to see Entitlements!<BR>\n");
		tpl_addVar(vars, TPLADD, "ENTITLEMENTCONTENT", tpl_getTpl(vars, "ENTITLEMENTGENERICBIT"));
	}

	if (!apicall)
		return tpl_getTpl(vars, "ENTITLEMENTS");
	else
		return tpl_getTpl(vars, "APICCCAMCARDLIST");
}

char *send_oscam_status(struct templatevars *vars, struct uriparams *params, struct in_addr in, int apicall) {
	int i;
	char *usr;
	int lsec, isec, con, cau = 0;
	time_t now = time((time_t)0);
	struct tm lt;

	if (strcmp(getParam(params, "action"), "kill") == 0) {
		struct s_client *cl = get_client_by_tid(atol(getParam(params, "threadid")));
		if (cl) {
			kill_thread(cl);
			cs_log("Client %s killed by WebIF from %s", cl->account->usr, inet_ntoa(in));
		}
	}

	if (strcmp(getParam(params, "action"), "restart") == 0) {
		struct s_reader *rdr = get_reader_by_label(getParam(params, "label"));
		if(rdr)	{
			restart_cardreader(rdr, 1);
			cs_log("Reader %s restarted by WebIF from %s", rdr->label, inet_ntoa(in));
		}
	}

	if (strcmp(getParam(params, "action"), "resetstat") == 0) {
		struct s_reader *rdr = get_reader_by_label(getParam(params, "label"));
		if(rdr) {
			clear_reader_stat(rdr);
			cs_log("Reader %s stats resetted by WebIF from %s", rdr->label, inet_ntoa(in));
		}
	}

	char *debuglvl = getParam(params, "debug");
	if(strlen(debuglvl) > 0) {
#ifndef WITH_DEBUG
		cs_log("*** Warning: Debug Support not compiled in ***");
#else
		int dblvl = atoi(debuglvl);
		if(dblvl >= 0 && dblvl <= 255) cs_dblevel = dblvl;
		cs_log("%s debug_level=%d", "all", cs_dblevel);
#endif
	}

	char *hide = getParam(params, "hide");
	if(strlen(hide) > 0) {
		ulong clidx;
		clidx = atol(hide);
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
			int oldval = cfg.http_hide_idle_clients;
			chk_t_webif("httphideidleclients", hideidle);
			if(oldval != cfg.http_hide_idle_clients) {
				refresh_oscam(REFR_SERVER, in);
			}
		}
	}

	if(cfg.http_hide_idle_clients > 0) tpl_addVar(vars, TPLADD, "HIDEIDLECLIENTSSELECTED1", "selected");
	else tpl_addVar(vars, TPLADD, "HIDEIDLECLIENTSSELECTED0", "selected");

	int user_count_all = 0, user_count_shown = 0, user_count_active = 0;
	int reader_count_all = 0, reader_count_conn = 0;
	int proxy_count_all = 0, proxy_count_conn = 0;
	int shown;
	
	struct s_client *cl;
	for (i=0, cl=first_client; cl ; cl=cl->next, i++) {

		// Reset template variables
		tpl_addVar(vars, TPLADD, "CLIENTLBVALUE","");
		tpl_addVar(vars, TPLADD, "LASTREADER", "");
		tpl_addVar(vars, TPLADD, "CLIENTPROTO", "");
		tpl_addVar(vars, TPLADD, "CLIENTDESCRIPTION", "");
		tpl_addVar(vars, TPLADD, "CLIENTLASTRESPONSETIME", "");

		if (cl->typ=='c')
			user_count_all++;
		else if (cl->typ=='p')
			proxy_count_all++;
		else if (cl->typ=='r')
			reader_count_all++;

		shown = 0;
		if (cl->wihidden != 1) {

			if((cfg.http_hide_idle_clients != 1) || (cl->typ != 'c') || ((now - cl->lastecm) <= cfg.mon_hideclient_to)) {

				if (cl->typ=='c'){
					user_count_shown++;
					if (cfg.http_hide_idle_clients != 1 && cfg.mon_hideclient_to > 0 && (now - cl->lastecm) <= cfg.mon_hideclient_to){						
						user_count_active++;
						tpl_addVar(vars, TPLADD, "CLIENTTYPE", "a");
					} else tpl_addVar(vars, TPLADD, "CLIENTTYPE", "c");
				} else {
					if (cl->typ=='r' && cl->reader->card_status==CARD_INSERTED)
						reader_count_conn++;
					else if (cl->typ=='p' && (cl->reader->card_status==CARD_INSERTED ||cl->reader->tcp_connected))
						proxy_count_conn++;
					tpl_printf(vars, TPLADD, "CLIENTTYPE", "%c", cl->typ);
				}
			
				shown = 1;
				lsec=now-cl->login;
				isec=now-cl->last;
				usr=username(cl);

				if ((cl->typ=='r') || (cl->typ=='p')) usr=cl->reader->label;

				if (cl->dup) con=2;
				else if ((cl->tosleep) && (now-cl->lastswitch>cl->tosleep)) con=1;
				else con=0;

				//if( (cau=get_ridx(cl->aureader)+1) && (now-cl->lastemm)/60 > cfg.mon_aulow) cau=-cau;
				// workaround: no AU reader == 0 / AU ok == 1 / Last EMM > aulow == -1
				if (!cl->aureader_list) {
					cau = 0;
				} else {
					if ((now-cl->lastemm)/60 > cfg.mon_aulow)
						cau = -1;
					else
						cau = 1;
				}

				localtime_r(&cl->login, &lt);

				tpl_printf(vars, TPLADD, "HIDEIDX", "%ld", cl->thread);

				if(cl->typ == 'c' && !cfg.http_readonly) {
					tpl_printf(vars, TPLADD, "CSIDX", "<A HREF=\"status.html?action=kill&threadid=%ld\" TITLE=\"Kill this client\"><IMG HEIGHT=\"16\" WIDTH=\"16\" SRC=\"image?i=ICKIL\" ALT=\"Kill\"></A>", cl->thread);
				}
				else if((cl->typ == 'p') && !cfg.http_readonly) {
					tpl_printf(vars, TPLADD, "CSIDX", "<A HREF=\"status.html?action=restart&label=%s\" TITLE=\"Restart this reader/ proxy\"><IMG HEIGHT=\"16\" WIDTH=\"16\" SRC=\"image?i=ICKIL\" ALT=\"Restart\"></A>", urlencode(vars, cl->reader->label));
				}
				else {
					tpl_printf(vars, TPLADD, "CSIDX", "%8X&nbsp;", cl->thread);
				}

				tpl_printf(vars, TPLADD, "CLIENTTYPE", "%c", cl->typ);
				tpl_printf(vars, TPLADD, "CLIENTCNR", "%d", get_threadnum(cl));
				tpl_addVar(vars, TPLADD, "CLIENTUSER", xml_encode(vars, usr));
				if (cl->typ == 'c')
					tpl_addVar(vars, TPLADD, "CLIENTDESCRIPTION", xml_encode(vars, cl->account?cl->account->description:""));
				tpl_printf(vars, TPLADD, "CLIENTCAU", "%d", cau);
				tpl_printf(vars, TPLADD, "CLIENTCRYPTED", "%d", cl->crypted);
				tpl_addVar(vars, TPLADD, "CLIENTIP", cs_inet_ntoa(cl->ip));
				tpl_printf(vars, TPLADD, "CLIENTPORT", "%d", cl->port);
				char *proto = monitor_get_proto(cl);

				if ((strcmp(proto,"newcamd") == 0) && (cl->typ == 'c'))
					tpl_printf(vars, TPLADD, "CLIENTPROTO","%s (%s)", proto, get_ncd_client_name(cl->ncd_client_id));
				else if (((strcmp(proto,"cccam") == 0) || (strcmp(proto,"cccam ext") == 0))) {
					struct cc_data *cc = cl->cc;
					if(cc && cc->remote_version && cc->remote_build) {
						tpl_printf(vars, TPLADD, "CLIENTPROTO", "%s (%s-%s)", proto, cc->remote_version, cc->remote_build);
						if(cc->extended_mode)
							tpl_addVar(vars, TPLADD, "CLIENTPROTOTITLE", cc->remote_oscam);
						else
							tpl_addVar(vars, TPLADD, "CLIENTPROTOTITLE", ""); //unset tpl var
					}
					else
					{
						tpl_addVar(vars, TPLADD, "CLIENTPROTO", proto);
						tpl_addVar(vars, TPLADD, "CLIENTPROTOTITLE", "");
					}
				}
				else {
					tpl_addVar(vars, TPLADD, "CLIENTPROTO", proto);
					tpl_addVar(vars, TPLADD, "CLIENTPROTOTITLE", "");
				}
				
				if (!apicall) {
					tpl_printf(vars, TPLADD, "CLIENTLOGINDATE", "%02d.%02d.%02d", lt.tm_mday, lt.tm_mon+1, lt.tm_year%100);
					tpl_printf(vars, TPLAPPEND, "CLIENTLOGINDATE", " %02d:%02d:%02d", lt.tm_hour, lt.tm_min, lt.tm_sec);
					tpl_addVar(vars, TPLADD, "CLIENTLOGINSECS", sec2timeformat(vars, lsec));
				} else {	
					char tbuffer [30];
					strftime(tbuffer, 30, "%Y-%m-%dT%H:%M:%S%z", &lt);
					tpl_printf(vars, TPLADD, "CLIENTLOGINDATE", "%s", tbuffer);
					tpl_printf(vars, TPLADD, "CLIENTLOGINSECS", "%d", lsec);
				}
				
				if (isec < cfg.mon_hideclient_to || cfg.mon_hideclient_to == 0) {

					if (((cl->typ!='r') || (cl->typ!='p')) && (cl->lastreader[0])) {
						tpl_printf(vars, TPLADD, "CLIENTLBVALUE", "by %s", cl->lastreader);
						tpl_printf(vars, TPLAPPEND, "CLIENTLBVALUE", "&nbsp;(%dms)", cl->cwlastresptime);
						if (apicall)
							tpl_addVar(vars, TPLADD, "LASTREADER", cl->lastreader);
					}

					tpl_printf(vars, TPLADD, "CLIENTCAID", "%04X", cl->last_caid);
					tpl_printf(vars, TPLADD, "CLIENTSRVID", "%04X", cl->last_srvid);
					tpl_printf(vars, TPLADD, "CLIENTLASTRESPONSETIME", "%d", cl->cwlastresptime?cl->cwlastresptime:1);

					int j, found = 0;
					struct s_srvid *srvid = cfg.srvid;

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
						tpl_printf(vars, TPLADD, "CLIENTSRVPROVIDER","%s: ", xml_encode(vars, srvid->prov));
						tpl_addVar(vars, TPLADD, "CLIENTSRVNAME", xml_encode(vars, srvid->name));
						tpl_addVar(vars, TPLADD, "CLIENTSRVTYPE", xml_encode(vars, srvid->type));
						tpl_addVar(vars, TPLADD, "CLIENTSRVDESCRIPTION", xml_encode(vars, srvid->desc));
					} else {
						tpl_addVar(vars, TPLADD, "CLIENTSRVPROVIDER","");
						tpl_addVar(vars, TPLADD, "CLIENTSRVNAME","");
						tpl_addVar(vars, TPLADD, "CLIENTSRVTYPE","");
						tpl_addVar(vars, TPLADD, "CLIENTSRVDESCRIPTION","");
					}
					
				} else {
					tpl_addVar(vars, TPLADD, "CLIENTCAID", "0000");
					tpl_addVar(vars, TPLADD, "CLIENTSRVID", "0000");
					tpl_addVar(vars, TPLADD, "CLIENTSRVPROVIDER","");
					tpl_addVar(vars, TPLADD, "CLIENTSRVNAME","");
					tpl_addVar(vars, TPLADD, "CLIENTSRVTYPE","");
					tpl_addVar(vars, TPLADD, "CLIENTSRVDESCRIPTION","");
					tpl_addVar(vars, TPLADD, "CLIENTLBVALUE","");

				}

				if (!apicall) {
					tpl_addVar(vars, TPLADD, "CLIENTIDLESECS", sec2timeformat(vars, isec));
				} else {
					tpl_printf(vars, TPLADD, "CLIENTIDLESECS", "%d", isec);
				}


				if(con == 2) tpl_addVar(vars, TPLADD, "CLIENTCON", "Duplicate");
				else if (con == 1) tpl_addVar(vars, TPLADD, "CLIENTCON", "Sleep");
				else
				{
					char *txt = "OK";
					if (cl->typ == 'r' || cl->typ == 'p') //reader or proxy
					{
						struct s_reader *rdr = cl->reader;
								if (rdr->lbvalue)
									tpl_printf(vars, TPLADD, "CLIENTLBVALUE", "<A HREF=\"status.html?action=resetstat&label=%s\" TITLE=\"Reset statistics for this reader/ proxy\">%d</A>", urlencode(vars, rdr->label), rdr->lbvalue);
								else
									tpl_printf(vars, TPLADD, "CLIENTLBVALUE", "<A HREF=\"status.html?action=resetstat&label=%s\" TITLE=\"Reset statistics for this reader/ proxy\">%s</A>", urlencode(vars, rdr->label), "no data");
									
								switch(rdr->card_status)
								{
								case NO_CARD: txt = "OFF"; break;
								case UNKNOWN: txt = "UNKNOWN"; break;
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
					tpl_addVar(vars, TPLADD, "CLIENTCON", txt);
				}
			}
		}
		
		if (!apicall) {
			// select right suborder
			if (cl->typ == 'c') {
				if (shown) tpl_addVar(vars, TPLAPPEND, "CLIENTSTATUS", tpl_getTpl(vars, "CLIENTSTATUSBIT"));
				if(cfg.http_hide_idle_clients == 1 || cfg.mon_hideclient_to < 1) tpl_printf(vars, TPLADD, "CLIENTHEADLINE", "\t\t<TR><TD CLASS=\"subheadline\" colspan=\"17\">Clients %d/%d</TD></TR>\n",
						user_count_shown, user_count_all);
				else tpl_printf(vars, TPLADD, "CLIENTHEADLINE", "\t\t<TR><TD CLASS=\"subheadline\" colspan=\"17\">Clients %d/%d (%d with ECM within last %d seconds)</TD></TR>\n",
						user_count_shown, user_count_all, user_count_active, cfg.mon_hideclient_to);
			}
			else if (cl->typ == 'r') {
				if (shown) tpl_addVar(vars, TPLAPPEND, "READERSTATUS", tpl_getTpl(vars, "CLIENTSTATUSBIT"));
				tpl_printf(vars, TPLADD, "READERHEADLINE", "\t\t<TR><TD CLASS=\"subheadline\" colspan=\"17\">Readers %d/%d</TD></TR>\n",
						reader_count_conn, reader_count_all);
			}
			else if (cl->typ == 'p') {
				if (shown) tpl_addVar(vars, TPLAPPEND, "PROXYSTATUS", tpl_getTpl(vars, "CLIENTSTATUSBIT"));
				tpl_printf(vars, TPLADD, "PROXYHEADLINE", "\t\t<TR><TD CLASS=\"subheadline\" colspan=\"17\">Proxies %d/%d</TD></TR>\n",
						proxy_count_conn, proxy_count_all);
			}
			else
				if (shown) tpl_addVar(vars, TPLAPPEND, "SERVERSTATUS", tpl_getTpl(vars, "CLIENTSTATUSBIT"));

		} else {
			if (shown) tpl_addVar(vars, TPLAPPEND, "APISTATUSBITS", tpl_getTpl(vars, "APISTATUSBIT"));
		}
	}

#ifdef CS_LOGHISTORY
	for (i=(loghistidx+3) % CS_MAXLOGHIST; i!=loghistidx; i=(i+1) % CS_MAXLOGHIST) {
		char *p_usr, *p_txt;
		p_usr=(char *)(loghist+(i*CS_LOGHISTSIZE));
		p_txt=p_usr+32;

		if (!apicall) {
			if (p_txt[0]) tpl_printf(vars, TPLAPPEND, "LOGHISTORY", "\t\t<span class=\"%s\">%s\t\t</span><br>\n", p_usr, p_txt+8);
		} else {
			if (strcmp(getParam(params, "appendlog"), "1") == 0)
				tpl_printf(vars, TPLAPPEND, "LOGHISTORY", "%s", p_txt+8);
		}
	}
#else
	tpl_addVar(vars, TPLADD, "LOGHISTORY", "the flag CS_LOGHISTORY is not set in your binary<BR>\n");
#endif

#ifdef WITH_DEBUG
	// Debuglevel Selector
	int lvl;
	for (i = 0; i < 8; i++) {
		lvl = 1 << i;
		tpl_printf(vars, TPLADD, "TMPC", "DCLASS%d", lvl);
		tpl_printf(vars, TPLADD, "TMPV", "DEBUGVAL%d", lvl);
		if (cs_dblevel & lvl) {
			tpl_addVar(vars, TPLADD, tpl_getVar(vars, "TMPC"), "debugls");
			tpl_printf(vars, TPLADD, tpl_getVar(vars, "TMPV"), "%d", cs_dblevel - lvl);
		} else {
			tpl_addVar(vars, TPLADD, tpl_getVar(vars, "TMPC"), "debugl");
			tpl_printf(vars, TPLADD, tpl_getVar(vars, "TMPV"), "%d", cs_dblevel + lvl);
		}
	}

	if (cs_dblevel == 255)
		tpl_addVar(vars, TPLADD, "DCLASS255", "debugls");
	else
		tpl_addVar(vars, TPLADD, "DCLASS255", "debugl");

	tpl_addVar(vars, TPLADD, "NEXTPAGE", "status.html");
	tpl_addVar(vars, TPLADD, "DCLASS", "debugl"); //default
	tpl_printf(vars, TPLADD, "ACTDEBUG", "%d", cs_dblevel);
	tpl_addVar(vars, TPLADD, "SDEBUG", tpl_getTpl(vars, "DEBUGSELECT"));
#endif

	if(!apicall)
		return tpl_getTpl(vars, "STATUS");
	else
		return tpl_getTpl(vars, "APISTATUS");

}

char *send_oscam_services_edit(struct templatevars *vars, struct uriparams *params, struct in_addr in) {
	struct s_sidtab *sidtab,*ptr;
	char label[sizeof(cfg.sidtab->label)];
	int i;

	cs_strncpy(label, strtolower(getParam(params, "service")), sizeof(label));

	for (sidtab = cfg.sidtab; sidtab != NULL && strcmp(label, sidtab->label) != 0; sidtab=sidtab->next);

	if (sidtab == NULL) {
		i = 1;
		while(strlen(label) < 1) {
			snprintf(label, sizeof(label)/sizeof(char) - 1, "newservice%d", i);
			for (sidtab = cfg.sidtab; sidtab != NULL && strcmp(label, sidtab->label) != 0; sidtab = sidtab->next);
			if(sidtab != NULL) label[0] = '\0';
			++i;
		}
		if (!cs_malloc(&sidtab, sizeof(struct s_sidtab), -1)) return "0";

		if(cfg.sidtab == NULL) cfg.sidtab = sidtab;
		else {
			for (ptr = cfg.sidtab; ptr != NULL && ptr->next != NULL; ptr = ptr->next);
			ptr->next = sidtab;
		}
		memset(sidtab, 0, sizeof(struct s_sidtab));
		cs_strncpy((char *)sidtab->label, label, sizeof(sidtab->label));

		tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<b>New service has been added</b><BR>");
		if (write_services()==0) refresh_oscam(REFR_SERVICES, in);
		else tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<b>Writing services to disk failed!</b><BR>");

		for (sidtab = cfg.sidtab; sidtab != NULL && strcmp(label, sidtab->label) != 0; sidtab=sidtab->next);
	}

	if (strcmp(getParam(params, "action"), "Save") == 0) {
		for(i=0;i<(*params).paramcount;i++) {
			if ((strcmp((*params).params[i], "action")) && (strcmp((*params).params[i], "service"))) {
				chk_sidtab((*params).params[i], (*params).values[i], sidtab);
			}
		}
		tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<B>Services updated</B><BR><BR>");
		if (write_services()==0) refresh_oscam(REFR_SERVICES, in);
		else tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<B>Write Config failed</B><BR><BR>");

		for (sidtab = cfg.sidtab; sidtab != NULL && strcmp(label, sidtab->label) != 0; sidtab=sidtab->next);
	}

	tpl_addVar(vars, TPLADD, "LABEL", sidtab->label);
	tpl_addVar(vars, TPLADD, "LABELENC", urlencode(vars, sidtab->label));


	for (i=0; i<sidtab->num_caid; i++) {
		if (i==0) tpl_printf(vars, TPLADD, "CAIDS", "%04X", sidtab->caid[i]);
		else tpl_printf(vars, TPLAPPEND, "CAIDS", ",%04X", sidtab->caid[i]);
	}
	for (i=0; i<sidtab->num_provid; i++) {
		if (i==0) tpl_printf(vars, TPLADD, "PROVIDS", "%06lX", sidtab->provid[i]);
		else tpl_printf(vars, TPLAPPEND, "PROVIDS", ",%06lX", sidtab->provid[i]);
	}
	for (i=0; i<sidtab->num_srvid; i++) {
		if (i==0) tpl_printf(vars, TPLADD, "SRVIDS", "%04X", sidtab->srvid[i]);
		else tpl_printf(vars, TPLAPPEND, "SRVIDS", ",%04X", sidtab->srvid[i]);
	}
	return tpl_getTpl(vars, "SERVICEEDIT");
}

char *send_oscam_services(struct templatevars *vars, struct uriparams *params, struct in_addr in) {
	struct s_sidtab *sidtab, *sidtab2;
	char *service = getParam(params, "service");
	int i, found = 0;

	if (strcmp(getParam(params, "action"), "delete") == 0) {
		if(cfg.http_readonly) {
			tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<b>Sorry, Webif is in readonly mode. No deletion will be made!</b><BR>");
		} else {
			sidtab=cfg.sidtab;
			if(strcmp(sidtab->label, service) == 0) {
				cfg.sidtab = sidtab->next;
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
				tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<b>Service has been deleted!</b><BR>");
				if (write_services() == 0) refresh_oscam(REFR_SERVICES, in);
				else tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<b>Writing services to disk failed!</b><BR>");
			} else tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<b>Sorry but the specified service doesn't exist. No deletion will be made!</b><BR>");
		}
	}

	sidtab = cfg.sidtab;
	// Show List
	while(sidtab != NULL) {
		tpl_printf(vars, TPLADD, "SID","");
		if ((strcmp(getParam(params, "service"), sidtab->label) == 0) && (strcmp(getParam(params, "action"), "list") == 0) ) {
			tpl_printf(vars, TPLADD, "SIDCLASS","sidlist");
			tpl_printf(vars, TPLAPPEND, "SID", "<div style=\"float:right;background-color:red;color:white\"><A HREF=\"services.html\" style=\"color:white;text-decoration:none\">X</A></div>");
			for (i=0; i<sidtab->num_srvid; i++) {
				tpl_printf(vars, TPLAPPEND, "SID", "%04X : %s<BR>", sidtab->srvid[i], xml_encode(vars, get_servicename(sidtab->srvid[i], sidtab->caid[0])));
			}
		} else {
			tpl_printf(vars, TPLADD, "SIDCLASS","");
			tpl_printf(vars, TPLADD, "SID","<A HREF=\"services.html?service=%s&action=list\">Show Services</A>", urlencode(vars, sidtab->label));
		}
		tpl_addVar(vars, TPLADD, "LABELENC", urlencode(vars, sidtab->label));
		tpl_addVar(vars, TPLADD, "LABEL", xml_encode(vars, sidtab->label));
		tpl_addVar(vars, TPLADD, "SIDLIST", tpl_getTpl(vars, "SERVICECONFIGSIDBIT"));

		tpl_addVar(vars, TPLAPPEND, "SERVICETABS", tpl_getTpl(vars, "SERVICECONFIGLISTBIT"));
		sidtab=sidtab->next;
	}
	return tpl_getTpl(vars, "SERVICECONFIGLIST");
}

char *send_oscam_savetpls(struct templatevars *vars) {
	if(strlen(cfg.http_tpl) > 0) {
		tpl_printf(vars, TPLADD, "CNT", "%d", tpl_saveIncludedTpls(cfg.http_tpl));
		tpl_addVar(vars, TPLADD, "PATH", cfg.http_tpl);
	} else tpl_addVar(vars, TPLADD, "CNT", "0");
	return tpl_getTpl(vars, "SAVETEMPLATES");
}

char *send_oscam_shutdown(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in, int apicall) {
	if (strcmp(strtolower(getParam(params, "action")), "shutdown") == 0) {
		if(!apicall){
			tpl_addVar(vars, TPLADD, "STYLESHEET", CSS);
			tpl_printf(vars, TPLADD, "REFRESHTIME", "%d", SHUTDOWNREFRESH);
			tpl_addVar(vars, TPLADD, "REFRESHURL", "status.html");
			tpl_addVar(vars, TPLADD, "REFRESH", tpl_getTpl(vars, "REFRESH"));
			tpl_printf(vars, TPLADD, "SECONDS", "%d", SHUTDOWNREFRESH);
			send_headers(f, 200, "OK", NULL, "text/html", 0);
			webif_write(tpl_getTpl(vars, "SHUTDOWN"), f);
			cs_log("Shutdown requested by WebIF from %s", inet_ntoa(in));
		} else {
			tpl_addVar(vars, TPLADD, "APICONFIRMMESSAGE", "shutdown");
			cs_log("Shutdown requested by XMLApi from %s", inet_ntoa(in));
		}
		running = 0;
		cs_exit_oscam();

		if(!apicall)
			return "1";
		else
			return tpl_getTpl(vars, "APICONFIRMATION");

	}
	else if (strcmp(strtolower(getParam(params, "action")), "restart") == 0) {
		if(!apicall){
			tpl_addVar(vars, TPLADD, "STYLESHEET", CSS);
			tpl_printf(vars, TPLADD, "REFRESHTIME", "%d", 2);
			tpl_addVar(vars, TPLADD, "REFRESHURL", "status.html");
			tpl_addVar(vars, TPLADD, "REFRESH", tpl_getTpl(vars, "REFRESH"));
			tpl_printf(vars, TPLADD, "SECONDS", "%d", 2);
			send_headers(f, 200, "OK", NULL, "text/html", 0);
			webif_write(tpl_getTpl(vars, "SHUTDOWN"), f);
			cs_log("Restart requested by WebIF from %s", inet_ntoa(in));
		} else {
			tpl_addVar(vars, TPLADD, "APICONFIRMMESSAGE", "restart");
			cs_log("Restart requested by XMLApi from %s", inet_ntoa(in));
		}
		running = 0;
		cs_restart_oscam();

		if(!apicall)
			return "1";
		else
			return tpl_getTpl(vars, "APICONFIRMATION");
		
	} else {
		return tpl_getTpl(vars, "PRESHUTDOWN");
	}
}

char *send_oscam_script(struct templatevars *vars) {

	char *result = "not found";
	int rc = 0;
	if(!cfg.http_readonly) {
		if(cfg.http_script[0]) {
			tpl_addVar(vars, TPLADD, "SCRIPTNAME",cfg.http_script);
			rc = system(cfg.http_script);
			if(rc == -1) {
				result = "done";
			} else {
				result = "failed";
			}
		} else {
			tpl_addVar(vars, TPLADD, "SCRIPTNAME", "no script defined");
		}
		tpl_addVar(vars, TPLADD, "SCRIPTRESULT", result);
		tpl_printf(vars, TPLADD, "CODE", "%d", rc);
	} else {
		tpl_addVar(vars, TPLAPPEND, "MESSAGE", "<b>Sorry, Webif is in readonly mode. No script execution possible!</b><BR>");
	}
	return tpl_getTpl(vars, "SCRIPT");

}

char *send_oscam_scanusb(struct templatevars *vars) {

#ifndef OS_CYGWIN32
	FILE *fp;
	int err=0;
	char path[1035];

	fp = popen("lsusb -v | egrep '^Bus|^ *iSerial|^ *iProduct'", "r");
	if (fp == NULL) {
		tpl_addVar(vars, TPLADD, "USBENTRY", "Failed to run lusb");
		tpl_printf(vars, TPLADD, "USBENTRY", "%s", path);
		tpl_addVar(vars, TPLAPPEND, "USBBIT", tpl_getTpl(vars, "SCANUSBBIT"));
		err = 1;
	}

	if(!err) {
		while (fgets(path, sizeof(path)-1, fp) != NULL) {
			tpl_addVar(vars, TPLADD, "USBENTRYCLASS", "");
			if (strstr(path,"Bus ")) {
				tpl_printf(vars, TPLADD, "USBENTRY", "%s", path);
				tpl_addVar(vars, TPLADD, "USBENTRYCLASS", "CLASS=\"scanusbsubhead\"");
			} else {
				tpl_printf(vars, TPLADD, "USBENTRY", "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;%s", path);
			}
			tpl_addVar(vars, TPLAPPEND, "USBBIT", tpl_getTpl(vars, "SCANUSBBIT"));
		}
	}
	pclose(fp);
#else
	tpl_addVar(vars, TPLADD, "MESSAGE", "Function not supported in CYGWIN environment");
#endif
	return tpl_getTpl(vars, "SCANUSB");
}

char *send_oscam_files(struct templatevars *vars, struct uriparams *params) {

	int writable=0;

	char *stoplog = getParam(params, "stoplog");
	if(strlen(stoplog) > 0)
		cfg.disablelog = atoi(stoplog);

	char *stopusrlog = getParam(params, "stopusrlog");
	if(strlen(stopusrlog) > 0)
		cfg.disableuserfile = atoi(stopusrlog);

	char *debuglvl = getParam(params, "debug");
	if(strlen(debuglvl) > 0) {
#ifndef WITH_DEBUG
		cs_log("*** Warning: Debug Support not compiled in ***");
#else
		int dblvl = atoi(debuglvl);
		if(dblvl >= 0 && dblvl <= 255) cs_dblevel = dblvl;
		cs_log("%s debug_level=%d", "all", cs_dblevel);
#endif
	}

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
		snprintf(targetfile, 255,"%s", cfg.logfile);

		if (strcmp(getParam(params, "clear"), "logfile") == 0) {
			if(strlen(targetfile) > 0) {
				FILE *file = fopen(targetfile,"w");
				fclose(file);
			}
		}

#ifdef WITH_DEBUG
		// Debuglevel Selector
		int i, lvl;
		for (i = 0; i < 8; i++) {
			lvl = 1 << i;
			tpl_printf(vars, TPLADD, "TMPC", "DCLASS%d", lvl);
			tpl_printf(vars, TPLADD, "TMPV", "DEBUGVAL%d", lvl);
			if (cs_dblevel & lvl) {
				tpl_addVar(vars, TPLADD, tpl_getVar(vars, "TMPC"), "debugls");
				tpl_printf(vars, TPLADD, tpl_getVar(vars, "TMPV"), "%d", cs_dblevel - lvl);
			} else {
				tpl_addVar(vars, TPLADD, tpl_getVar(vars, "TMPC"), "debugl");
				tpl_printf(vars, TPLADD, tpl_getVar(vars, "TMPV"), "%d", cs_dblevel + lvl);
			}
		}

		if (cs_dblevel == 255)
			tpl_addVar(vars, TPLADD, "DCLASS255", "debugls");
		else
			tpl_addVar(vars, TPLADD, "DCLASS255", "debugl");

		tpl_addVar(vars, TPLADD, "CUSTOMPARAM", "&part=logfile");
		tpl_printf(vars, TPLADD, "ACTDEBUG", "%d", cs_dblevel);
		tpl_addVar(vars, TPLADD, "SDEBUG", tpl_getTpl(vars, "DEBUGSELECT"));
		tpl_addVar(vars, TPLADD, "NEXTPAGE", "files.html");
#endif

		if(!cfg.disablelog)
			tpl_printf(vars, TPLADD, "SLOG", "<BR><A CLASS=\"debugl\" HREF=\"files.html?part=logfile&stoplog=%d\">%s</A><SPAN CLASS=\"debugt\">&nbsp;&nbsp;|&nbsp;&nbsp;</SPAN>\n", 1, "Stop Log");
		else
			tpl_printf(vars, TPLADD, "SLOG", "<BR><A CLASS=\"debugl\" HREF=\"files.html?part=logfile&stoplog=%d\">%s</A><SPAN CLASS=\"debugt\">&nbsp;&nbsp;|&nbsp;&nbsp;</SPAN>\n", 0, "Start Log");

		tpl_printf(vars, TPLADD, "SCLEAR", "<A CLASS=\"debugl\" HREF=\"files.html?part=logfile&clear=logfile\">%s</A><BR><BR>\n", "Clear Log");
	}
	else if (strcmp(getParam(params, "part"), "userfile") == 0) {
		snprintf(targetfile, 255,"%s", cfg.usrfile);
		if (strcmp(getParam(params, "clear"), "usrfile") == 0) {
			if(strlen(targetfile) > 0) {
				FILE *file = fopen(targetfile,"w");
				fclose(file);
			}
		}

		if(!cfg.disableuserfile)
			tpl_printf(vars, TPLADD, "SLOG", "<A HREF=\"files.html?part=userfile&stopusrlog=%d\">%s</A>&nbsp;&nbsp;|&nbsp;&nbsp;\n", 1, "Stop Log");
		else
			tpl_printf(vars, TPLADD, "SLOG", "<A HREF=\"files.html?part=userfile&stopusrlog=%d\">%s</A>&nbsp;&nbsp;|&nbsp;&nbsp;\n", 0, "Start Log");

		tpl_printf(vars, TPLADD, "SCLEAR", "<A HREF=\"files.html?part=userfile&clear=usrfile\">%s</A><BR><BR>\n", "Clear Log");
		tpl_addVar(vars, TPLADD, "FILTER", "<FORM ACTION=\"files.html\" method=\"get\">\n");
		tpl_addVar(vars, TPLAPPEND, "FILTER", "<INPUT name=\"part\" type=\"hidden\" value=\"userfile\">\n");
		tpl_addVar(vars, TPLAPPEND, "FILTER", "<SELECT name=\"filter\">\n");
		tpl_printf(vars, TPLAPPEND, "FILTER", "<OPTION value=\"%s\">%s</OPTION>\n", "all", "all");

		struct s_auth *account;
		for (account = cfg.account; (account); account = account->next) {
			tpl_printf(vars, TPLAPPEND, "FILTER", "<OPTION value=\"%s\" %s>%s</OPTION>\n", account->usr, strcmp(getParam(params, "filter"), account->usr) ? "":"selected", account->usr);
		}
		tpl_addVar(vars, TPLAPPEND, "FILTER", "</SELECT><input type=\"submit\" name=\"action\" value=\"Filter\" title=\"Filter for a specific user\"></FORM>\n");

	}
#ifdef CS_ANTICASC
	else if (strcmp(getParam(params, "part"), "anticasc") == 0)
		snprintf(targetfile, 255,"%s", cfg.ac_logfile);
#endif

#ifdef HAVE_DVBAPI
	else if (strcmp(getParam(params, "part"), "dvbapi") == 0) {
		snprintf(targetfile, 255, "%s%s", cs_confdir, "oscam.dvbapi");
		writable = 1;
	}
#endif


	if (!strstr(targetfile, "/dev/")) {

		if (strcmp(getParam(params, "action"), "Save") == 0) {
			if((strlen(targetfile) > 0) /*&& (file_exists(targetfile) == 1)*/) {
				FILE *fpsave;
				char *fcontent = getParam(params, "filecontent");

				if((fpsave = fopen(targetfile,"w"))){
					fprintf(fpsave,"%s",fcontent);
					fclose(fpsave);

					if (strcmp(getParam(params, "part"), "srvid") == 0)
						init_srvid();

					if (strcmp(getParam(params, "part"), "user") == 0)
						cs_accounts_chk();

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

			if((fp = fopen(targetfile,"r")) == NULL) return "0";
			while (fgets(buffer, sizeof(buffer), fp) != NULL)
				if (!strcmp(getParam(params, "filter"), "all"))
					tpl_printf(vars, TPLAPPEND, "FILECONTENT", "%s", buffer);
				else
					if(strstr(buffer,getParam(params, "filter")))
						tpl_printf(vars, TPLAPPEND, "FILECONTENT", "%s", buffer);
			fclose (fp);
		} else {
			tpl_addVar(vars, TPLAPPEND, "FILECONTENT", "File does not exist or no file selected!");
		}
	} else {
		tpl_addVar(vars, TPLAPPEND, "FILECONTENT", "File not valid!");
	}

	tpl_addVar(vars, TPLADD, "PART", getParam(params, "part"));

	if (!writable) {
		tpl_addVar(vars, TPLADD, "WRITEPROTECTION", "You cannot change the content of this file!");
		tpl_addVar(vars, TPLADD, "BTNDISABLED", "DISABLED");
	}

	return tpl_getTpl(vars, "FILE");
}

char *send_oscam_failban(struct templatevars *vars, struct uriparams *params) {

	uint ip2delete = 0;
	LL_ITER *itr = ll_iter_create(cfg.v_list);
	V_BAN *v_ban_entry;

	if (strcmp(getParam(params, "action"), "delete") == 0) {
		sscanf(getParam(params, "intip"), "%u", &ip2delete);
		while ((v_ban_entry=ll_iter_next(itr))) {
			if (v_ban_entry->v_ip == ip2delete) {
				ll_iter_remove_data(itr);
				break;
			}
		}
	}
	ll_iter_reset(itr);
	
	time_t now = time((time_t)0);

	while ((v_ban_entry=ll_iter_next(itr))) {

		tpl_printf(vars, TPLADD, "IPADDRESS", "%s", cs_inet_ntoa(v_ban_entry->v_ip));

		struct tm st ;
		localtime_r(&v_ban_entry->v_time, &st);

		tpl_printf(vars, TPLADD, "VIOLATIONDATE", "%02d.%02d.%02d %02d:%02d:%02d",
				st.tm_mday, st.tm_mon+1,
				st.tm_year%100, st.tm_hour,
				st.tm_min, st.tm_sec);

		tpl_printf(vars, TPLADD, "VIOLATIONCOUNT", "%d", v_ban_entry->v_count);
		tpl_addVar(vars, TPLADD, "LEFTTIME", sec2timeformat(vars, (cfg.failbantime * 60) - (now - v_ban_entry->v_time)));
		tpl_printf(vars, TPLADD, "INTIP", "%u", v_ban_entry->v_ip);
		tpl_addVar(vars, TPLAPPEND, "FAILBANROW", tpl_getTpl(vars, "FAILBANBIT"));
	}
	ll_iter_release(itr);
	
	return tpl_getTpl(vars, "FAILBAN");
}

char *send_oscam_api(struct templatevars *vars, FILE *f, struct uriparams *params, struct in_addr in) {
	if (strcmp(getParam(params, "part"), "status") == 0) {
		return send_oscam_status(vars, params, in, 1);
	}
	else if (strcmp(getParam(params, "part"), "entitlement") == 0) {

		if (strcmp(getParam(params, "label"),"")) {
			struct s_reader *rdr = get_reader_by_label(getParam(params, "label"));
			if (rdr) {
				if (rdr->typ == R_CCCAM && rdr->enable == 1) {
					return send_oscam_entitlement(vars, params, in, 1);
				} else {
					//Send Errormessage
					tpl_addVar(vars, TPLADD, "APIERRORMESSAGE", "no cccam reader or disabled");
					return tpl_getTpl(vars, "APIERROR");
				}
			} else {
				//Send Errormessage
				tpl_addVar(vars, TPLADD, "APIERRORMESSAGE", "reader not exist");
				return tpl_getTpl(vars, "APIERROR");
			}
		} else {
			//Send Errormessage
			tpl_addVar(vars, TPLADD, "APIERRORMESSAGE", "no reader selected");
			return tpl_getTpl(vars, "APIERROR");
		}
	}
	else if (strcmp(getParam(params, "part"), "readerstats") == 0) {
		if (strcmp(getParam(params, "label"),"")) {
			struct s_reader *rdr = get_reader_by_label(getParam(params, "label"));
			if (rdr) {
				return send_oscam_reader_stats(vars, params, in, 1);
			} else {
				//Send Errormessage
				tpl_addVar(vars, TPLADD, "APIERRORMESSAGE", "reader not exist");
				return tpl_getTpl(vars, "APIERROR");
			}
		} else {
			//Send Errormessage
			tpl_addVar(vars, TPLADD, "APIERRORMESSAGE", "no reader selected");
			return tpl_getTpl(vars, "APIERROR");
		}
	} else if (strcmp(getParam(params, "part"), "shutdown") == 0) {
		if ((strcmp(strtolower(getParam(params, "action")), "restart") == 0) ||
				(strcmp(strtolower(getParam(params, "action")), "shutdown") == 0)){
			if(!cfg.http_readonly) {
				return send_oscam_shutdown(vars, f, params, in, 1);
			} else {
				tpl_addVar(vars, TPLADD, "APIERRORMESSAGE", "webif readonly mode");
				return tpl_getTpl(vars, "APIERROR");
			}
		} else {
			tpl_addVar(vars, TPLADD, "APIERRORMESSAGE", "missing parameter action");
			return tpl_getTpl(vars, "APIERROR");
		}

	}
	else {
		tpl_addVar(vars, TPLADD, "APIERRORMESSAGE", "part not found");
		return tpl_getTpl(vars, "APIERROR");
	}
}

char *send_oscam_image(struct templatevars *vars, FILE *f, struct uriparams *params, char *image) {
	char *wanted;
	if(image == NULL) wanted = getParam(params, "i");
	else wanted = image;
	if(strlen(wanted) > 3 && wanted[0] == 'I' && wanted[1] == 'C'){
		char *header = strstr(tpl_getTpl(vars, wanted), "data:");
		if(header != NULL){
			char *ptr = header + 5;
			while (ptr[0] != ';' && ptr[0] != '\0') ++ptr;
			if(ptr[0] != '\0' && ptr[1] != '\0') ptr[0] = '\0';
			else return "0";
			ptr = strstr(ptr + 1, "base64,");
			if(ptr != NULL){
				int len = b64decode((uchar *)ptr + 7);
				if(len > 0){
					send_headers(f, 200, "OK", NULL, header + 5, 1);
					webif_write_raw(ptr + 7, f, len);
					return "1";
				}
			}
		}
	}
	return "0";
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
	in_addr_t addr = in.s_addr;

	ok = check_ip(cfg.http_allowed, in.s_addr) ? v : 0;

	if (!ok && cfg.http_dyndns[0]) {
		cs_debug_mask(D_TRACE, "WebIf: IP not found in allowed range - test dyndns");

		if(cfg.http_dynip && cfg.http_dynip == addr) {
			ok = v;
			cs_debug_mask(D_TRACE, "WebIf: dyndns address previously resolved and ok");

		} else {

			if (cfg.resolve_gethostbyname) {
				cs_debug_mask(D_TRACE, "WebIf: try resolving IP with 'gethostbyname'");
				pthread_mutex_lock(&gethostbyname_lock);
				struct hostent *rht;
				struct sockaddr_in udp_sa;

				rht = gethostbyname((const char *) cfg.http_dyndns);
				if (rht) {
					memcpy(&udp_sa.sin_addr, rht->h_addr, sizeof(udp_sa.sin_addr));
					cfg.http_dynip = udp_sa.sin_addr.s_addr;
					cs_debug_mask(D_TRACE, "WebIf: dynip resolved %s access from %s",
							cs_inet_ntoa(cfg.http_dynip),
							cs_inet_ntoa(addr));
					if (cfg.http_dynip == addr)
						ok = v;
				} else {
					cs_log("can't resolve %s", cfg.http_dyndns); }
				pthread_mutex_unlock(&gethostbyname_lock);

			} else {
				cs_debug_mask(D_TRACE, "WebIf: try resolving IP with 'getaddrinfo'");
				struct addrinfo hints, *res = NULL;
				memset(&hints, 0, sizeof(hints));
				hints.ai_socktype = SOCK_STREAM;
				hints.ai_family = AF_INET;
				hints.ai_protocol = IPPROTO_TCP;

				int err = getaddrinfo((const char*)cfg.http_dyndns, NULL, &hints, &res);
				if (err != 0 || !res || !res->ai_addr) {
					cs_log("can't resolve %s, error: %s", cfg.http_dyndns, err ? gai_strerror(err) : "unknown");
				}
				else {
					cfg.http_dynip = ((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr;
					cs_debug_mask(D_TRACE, "WebIf: dynip resolved %s access from %s",
							cs_inet_ntoa(cfg.http_dynip),
							cs_inet_ntoa(addr));
					if (cfg.http_dynip == addr)
						ok = v;
				}
				if (res) freeaddrinfo(res);

			}
		}
	} else {
		if (cfg.http_dyndns[0])
			cs_debug_mask(D_TRACE, "WebIf: IP found in allowed range - bypass dyndns");
	}

	if (!ok) {
		send_error(f, 403, "Forbidden", NULL, "Access denied.");
		cs_log("unauthorized access from %s flag %d", inet_ntoa(in), v);
		return 0;
	}

	int authok = 0;
	char expectednonce[(MD5_DIGEST_LENGTH * 2) + 1];

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
		"/oscamapi.html",
		"/image",
		"/favicon.ico"};

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
			if (cfg.http_use_ssl)
				ERR_print_errors_fp(stderr);
#endif
			return -1;
		}
		if(!cs_realloc(&filebuf, bufsize+n+1, -1)){
			send_error500(f);
			return -1;
		}
		
		memcpy(filebuf+bufsize, buf2, n);
		bufsize+=n;

		//max request size 100kb
		if (bufsize>102400) {
			cs_log("error: too much data received from %s", inet_ntoa(in));
			free(filebuf);
			return -1;
		}

#ifdef WITH_SSL
		if (cfg.http_use_ssl) {
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

	if(strlen(cfg.http_user) == 0 || strlen(cfg.http_pwd) == 0) authok = 1;
	else calculate_nonce(expectednonce);

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
		char temp[sizeof(AUTHREALM) + sizeof(expectednonce) + 100];
		snprintf(temp, sizeof(temp), "WWW-Authenticate: Digest algorithm=\"MD5\", realm=\"%s\", qop=\"auth\", opaque=\"\", nonce=\"%s\"", AUTHREALM, expectednonce);
		if(authok == 2) strncat(temp, ", stale=true", sizeof(temp));
		send_headers(f, 401, "Unauthorized", temp, "text/html", 0);
		free(filebuf);
		return 0;
	}

	/*build page*/
	if(pgidx == 8) {
		send_headers(f, 200, "OK", NULL, "text/css", 1);
		send_file(f, "CSS");
	} else if (pgidx == 17) {
		send_headers(f, 200, "OK", NULL, "text/javascript", 1);
		send_file(f, "JS");
	} else {
		time_t t;
		struct templatevars *vars = tpl_create();
		if(vars == NULL){
			send_error500(f);
			free(filebuf);
			return 0;
		}
		struct tm lt, st;
		time(&t);

		localtime_r(&t, &lt);

		tpl_addVar(vars, TPLADD, "CS_VERSION", CS_VERSION);
		tpl_addVar(vars, TPLADD, "CS_SVN_VERSION", CS_SVN_VERSION);
		if(cfg.http_refresh > 0 && (pgidx == 3 || pgidx == -1)) {
			tpl_printf(vars, TPLADD, "REFRESHTIME", "%d", cfg.http_refresh);
			tpl_addVar(vars, TPLADD, "REFRESHURL", "status.html");
			tpl_addVar(vars, TPLADD, "REFRESH", tpl_getTpl(vars, "REFRESH"));
		}

		tpl_printf(vars, TPLADD, "CURDATE", "%02d.%02d.%02d", lt.tm_mday, lt.tm_mon+1, lt.tm_year%100);
		tpl_printf(vars, TPLADD, "CURTIME", "%02d:%02d:%02d", lt.tm_hour, lt.tm_min, lt.tm_sec);
		localtime_r(&first_client->login, &st);
		tpl_printf(vars, TPLADD, "STARTDATE", "%02d.%02d.%02d", st.tm_mday, st.tm_mon+1, st.tm_year%100);
		tpl_printf(vars, TPLADD, "STARTTIME", "%02d:%02d:%02d", st.tm_hour, st.tm_min, st.tm_sec);
		tpl_printf(vars, TPLADD, "PROCESSID", "%d", server_pid);

		time_t now = time((time_t)0);
		// XMLAPI
		if (pgidx == 18) {
			char tbuffer [30];
			strftime(tbuffer, 30, "%Y-%m-%dT%H:%M:%S%z", &st);
			tpl_printf(vars, TPLADD, "APISTARTTIME", "%s", tbuffer);
			tpl_printf(vars, TPLADD, "APIUPTIME", "%u", now - first_client->login);
		}

		// language code in helplink
		if (cfg.http_help_lang[0])
			tpl_addVar(vars, TPLADD, "LANGUAGE", cfg.http_help_lang);
		else
			tpl_addVar(vars, TPLADD, "LANGUAGE", "en");

		tpl_addVar(vars, TPLADD, "UPTIME", sec2timeformat(vars, (now - first_client->login)));
		tpl_printf(vars, TPLADD, "CURIP", "%s", inet_ntoa(in));
		if(cfg.http_readonly)
			tpl_addVar(vars, TPLAPPEND, "BTNDISABLED", "DISABLED");
		
		char *result = NULL;
		
		switch(pgidx) {
			case 0: result = send_oscam_config(vars, &params, in); break;
			case 1: result = send_oscam_reader(vars, &params, in); break;
			case 2: result = send_oscam_entitlement(vars, &params, in, 0); break;
			case 3: result = send_oscam_status(vars, &params, in, 0); break;
			case 4: result = send_oscam_user_config(vars, &params, in); break;
			case 5: result = send_oscam_reader_config(vars, &params, in); break;
			case 6: result = send_oscam_services(vars, &params, in); break;
			case 7: result = send_oscam_user_config_edit(vars, &params, in); break;
			//case  8: css file
			case 9: result = send_oscam_services_edit(vars, &params, in); break;
			case 10: result = send_oscam_savetpls(vars); break;
			case 11: result = send_oscam_shutdown(vars, f, &params, in, 0); break;
			case 12: result = send_oscam_script(vars); break;
			case 13: result = send_oscam_scanusb(vars); break;
			case 14: result = send_oscam_files(vars, &params); break;
			case 15: result = send_oscam_reader_stats(vars, &params, in, 0); break;
			case 16: result = send_oscam_failban(vars, &params); break;
			//case  17: js file
			case 18: result = send_oscam_api(vars, f, &params, in); break;
			case 19: result = send_oscam_image(vars, f, &params, NULL); break;
			case 20: result = send_oscam_image(vars, f, &params, "ICMAI"); break;
			default: result = send_oscam_status(vars, &params, in, 0); break;
		}
		if(result == NULL || !strcmp(result, "0") || strlen(result) == 0) send_error500(f);
		else if (strcmp(result, "1")) {
			if (pgidx == 18)
				send_headers(f, 200, "OK", NULL, "text/xml", 0);
			else
				send_headers(f, 200, "OK", NULL, "text/html", 0);
			webif_write(result, f);
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

	if (cfg.http_cert[0]==0)
		snprintf(path, sizeof(path), "%s%s", cs_confdir, cs_cert);
	else
		cs_strncpy(path, cfg.http_cert, sizeof(path));

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
	struct s_client * cl = create_client(first_client->ip);
	if (cl == NULL) return;
	cl->thread = pthread_self();
	pthread_setspecific(getclient, cl);
	cl->typ = 'h';
	int sock, reuse = 1;
	struct sockaddr_in sin;
	struct sockaddr_in remote;
	struct timeval stimeout;
	
	socklen_t len = sizeof(remote);
	/* Create random string for nonce value generation */
	create_rand_str(noncekey,32);

	/* Startup server */
	if((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		cs_log("HTTP Server: Creating socket failed! (errno=%d)", errno);
		return;
	}
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
		cs_log("HTTP Server: Setting SO_REUSEADDR via setsockopt failed! (errno=%d)", errno);
	}

    stimeout.tv_sec = 30;
    stimeout.tv_usec = 0;
     
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &stimeout, sizeof(stimeout)) < 0) {
     		cs_log("HTTP Server: Setting SO_RCVTIMEO via setsockopt failed! (errno=%d)", errno);
    }
     
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &stimeout, sizeof(stimeout)) < 0) {
     		cs_log("HTTP Server: Setting SO_SNDTIMEO via setsockopt failed! (errno=%d)", errno);
    }
    
	memset(&sin, 0, sizeof sin);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(cfg.http_port);
	if((bind(sock, (struct sockaddr *) &sin, sizeof(sin))) < 0) {
		cs_log("HTTP Server couldn't bind on port %d (errno=%d). Not starting HTTP!", cfg.http_port, errno);
		close(sock);
		return;
	}
	if (listen(sock, SOMAXCONN) < 0) {
		cs_log("HTTP Server: Call to listen() failed! (errno=%d)", errno);
		close(sock);
		return;
	}
	cs_log("HTTP Server listening on port %d%s", cfg.http_port, cfg.http_use_ssl ? " (SSL)" : "");
	struct pollfd pfd2[1];
	int rc;
	pfd2[0].fd = sock;
	pfd2[0].events = (POLLIN | POLLPRI);

#ifdef WITH_SSL
	SSL_CTX *ctx = NULL;
	if (cfg.http_use_ssl)
		ctx = webif_init_ssl();

	if (ctx==NULL)
		cfg.http_use_ssl = 0;
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
			if (cfg.http_use_ssl) {
				SSL *ssl;
				ssl = SSL_new(ctx);
				if(ssl != NULL){
					if(SSL_set_fd(ssl, s)){
						if (SSL_accept(ssl) != -1)
							process_request((FILE *)ssl, remote.sin_addr);
						else {
							FILE *f;
							f = fdopen(s, "r+");
							if(f != NULL) {
								// Note: This is quite dirty and only works because webif is not multithreaded!
								cfg.http_use_ssl=0;
								send_error(f, 200, "Bad Request", NULL, "This web server is running in SSL mode.");
								cfg.http_use_ssl=1;
								fflush(f);
								fclose(f);
							} else cs_log("WebIf: Error opening file descriptor using fdopen() (errno=%d)", errno);					
						}
					} else cs_log("WebIf: Error calling SSL_set_fd().");
					SSL_shutdown(ssl);
					close(s);
					SSL_free(ssl);
				} else {
					close(s);
					cs_log("WebIf: Error calling SSL_new().");
				}
			} else
#endif
			{
				FILE *f;
				f = fdopen(s, "r+");
				if(f != NULL) {
					process_request(f, remote.sin_addr);
					fflush(f);
					fclose(f);
				} else cs_log("WebIf: Error opening file descriptor using fdopen() (errno=%d)", errno);
				shutdown(s, SHUT_WR);
				close(s);
			}
		}
	}
#ifdef WITH_SSL
	if (cfg.http_use_ssl)
		SSL_CTX_free(ctx);
#endif
	cs_log("HTTP Server: Shutdown requested from %s", inet_ntoa(remote.sin_addr));
	close(sock);
	//exit(SIGQUIT);
}
#endif
