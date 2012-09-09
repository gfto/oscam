//FIXME Not checked on threadsafety yet; after checking please remove this line

#include "globals.h"

#if defined(__APPLE__) || defined(__FreeBSD__)
#include <net/if_dl.h>
#include <ifaddrs.h>
#elif defined(__SOLARIS__)
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/sockio.h>
#else
#include <net/if.h>
#endif

#include "oscam-conf.h"
#include "oscam-conf-chk.h"

#define MAXLINESIZE 16384

static const char *cs_conf="oscam.conf";
static const char *cs_user="oscam.user";
static const char *cs_srvr="oscam.server";
static const char *cs_srid="oscam.srvid";
static const char *cs_trid="oscam.tiers";
static const char *cs_l4ca="oscam.guess";
static const char *cs_sidt="oscam.services";
#ifdef CS_ANTICASC
static const char *cs_ac="oscam.ac";
#endif

//Todo #ifdef CCCAM
static const char *cs_provid="oscam.provid";

#ifdef IRDETO_GUESSING
static const char *cs_ird="oscam.ird";
#endif
uint32_t cfg_sidtab_generation = 1;

static void disablelog_fn(const char *token, char *value, void *UNUSED(setting), FILE *f) {
	if (value) {
		cs_disable_log(strToIntVal(value, 0));
		return;
	}
	if (cfg.disablelog || cfg.http_full_cfg)
		fprintf_conf(f, token, "%d\n", cfg.disablelog);
}

#if defined(WEBIF) || defined(MODULE_MONITOR)
static void loghistorysize_fn(const char *token, char *value, void *UNUSED(setting), FILE *f) {
	if (value) {
		uint32_t newsize = strToUIntVal(value, 4096);
		if (newsize < 1024 && newsize != 0) {
			fprintf(stderr, "WARNING: loghistorysize is too small, adjusted to 1024\n");
			newsize = 1024;
		}
		cs_reinit_loghist(newsize);
		return;
	}
	if (cfg.loghistorysize != 4096 || cfg.http_full_cfg)
		fprintf_conf(f, token, "%u\n", cfg.loghistorysize);
}
#endif

static void serverip_fn(const char *token, char *value, void *setting, FILE *f) {
	IN_ADDR_T srvip = *(IN_ADDR_T *)setting;
	if (value) {
		if (strlen(value) == 0) {
			set_null_ip((IN_ADDR_T *)setting);
		} else {
			cs_inet_addr(value, (IN_ADDR_T *)setting);
		}
		return;
	}
	if (IP_ISSET(srvip) || cfg.http_full_cfg)
		fprintf_conf(f, token, "%s\n", cs_inet_ntoa(srvip));
}

void iprange_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_ip **ip = setting;
	if (value) {
		if(strlen(value) == 0) {
			clear_sip(ip);
		} else {
			chk_iprange(value, ip);
		}
		return;
	}
	value = mk_t_iprange(*ip);
	if (strlen(value) > 0 || cfg.http_full_cfg)
		fprintf_conf(f, token, "%s\n", value);
	free_mk_t(value);
}

static void logfile_fn(const char *token, char *value, void *UNUSED(setting), FILE *f) {
	if (value) {
		char *saveptr1 = NULL;
		cfg.logtostdout = 0;
		cfg.logtosyslog = 0;
		NULLFREE(cfg.logfile);
		if (strlen(value) > 0) {
			char *pch;
			for(pch = strtok_r(value, ";", &saveptr1); pch != NULL; pch = strtok_r(NULL, ";", &saveptr1)){
				pch=trim(pch);
				if(!strcmp(pch, "stdout")) cfg.logtostdout = 1;
				else if(!strcmp(pch, "syslog")) cfg.logtosyslog = 1;
				else {
					NULLFREE(cfg.logfile);
					if(!cs_malloc(&(cfg.logfile), strlen(pch) + 1, -1)) continue;
					else memcpy(cfg.logfile, pch, strlen(pch) + 1);
				}
			}
		} else {
			if(cs_malloc(&(cfg.logfile), strlen(CS_LOGFILE) + 1, -1))
				memcpy(cfg.logfile, CS_LOGFILE, strlen(CS_LOGFILE) + 1);
			else cfg.logtostdout = 1;
		}
		return;
	}
	if (cfg.logfile || cfg.logtostdout == 1 || cfg.logtosyslog == 1 || cfg.http_full_cfg) {
		value = mk_t_logfile();
		fprintf_conf(f, token, "%s\n", value);
		free_mk_t(value);
	}
}

static void check_caid_fn(const char *token, char *value, void *setting, FILE *f) {
	CAIDTAB *caid_table = setting;
	if (value) {
		if (strlen(value) == 0)
			clear_caidtab(caid_table);
		else
			chk_caidtab(value, caid_table);
		return;
	}
	if (caid_table->caid[0] || cfg.http_full_cfg) {
		value = mk_t_caidtab(caid_table);
		fprintf_conf(f, token, "%s\n", value);
		free_mk_t(value);
	}
}

#ifdef WITH_LB
static void caidvaluetab_fn(const char *token, char *value, void *setting, FILE *f) {
	CAIDVALUETAB *caid_value_table = setting;
	int limit = streq(token, "lb_retrylimits") ? 50 : 1;
	if (value) {
		chk_caidvaluetab(value, caid_value_table, limit);
		return;
	}
	if (caid_value_table->n > 0 || cfg.http_full_cfg) {
		value = mk_t_caidvaluetab(caid_value_table);
		fprintf_conf(f, token, "%s\n", value);
		free_mk_t(value);
	}
}
#endif

#define OFS(X) \
	offsetof(struct s_config, X)

#define SIZEOF(X) \
	sizeof(((struct s_config *)0)->X)

static const struct config_list global_opts[] = {
#if defined(QBOXHD) || defined(__arm__)
	DEF_OPT_INT("enableled"					, OFS(enableled),			0 ),
#endif
	DEF_OPT_FUNC("disablelog"				, OFS(disablelog),			disablelog_fn ),
#if defined(WEBIF) || defined(MODULE_MONITOR)
	DEF_OPT_FUNC("loghistorysize"			, OFS(loghistorysize),		loghistorysize_fn ),
#endif
	DEF_OPT_FUNC("serverip"					, OFS(srvip),				serverip_fn ),
	DEF_OPT_FUNC("logfile"					, OFS(logfile),				logfile_fn ),
	DEF_OPT_INT("disableuserfile"			, OFS(disableuserfile),		1 ),
	DEF_OPT_INT("disablemail"				, OFS(disablemail),			1 ),
	DEF_OPT_INT("usrfileflag"				, OFS(usrfileflag),			0 ),
	DEF_OPT_UINT("clienttimeout"			, OFS(ctimeout),			CS_CLIENT_TIMEOUT ),
	DEF_OPT_UINT("fallbacktimeout"			, OFS(ftimeout),			CS_CLIENT_TIMEOUT / 2 ),
	DEF_OPT_UINT("clientmaxidle"			, OFS(cmaxidle),			CS_CLIENT_MAXIDLE ),
	DEF_OPT_UINT("cachedelay"				, OFS(delay),				CS_DELAY ),
	DEF_OPT_INT("bindwait"					, OFS(bindwait),			CS_BIND_TIMEOUT ),
	DEF_OPT_UINT("netprio"					, OFS(netprio),				0 ),
	DEF_OPT_INT("sleep"						, OFS(tosleep),				0 ),
	DEF_OPT_INT("unlockparental"			, OFS(ulparent),			0 ),
	DEF_OPT_INT("nice"						, OFS(nice),				99 ),
	DEF_OPT_UINT("serialreadertimeout"		, OFS(srtimeout),			1500 ),
	DEF_OPT_INT("maxlogsize"				, OFS(max_log_size),		10 ),
	DEF_OPT_INT("waitforcards"				, OFS(waitforcards),		1 ),
	DEF_OPT_INT("waitforcards_extra_delay"	, OFS(waitforcards_extra_delay), 500 ),
	DEF_OPT_INT("preferlocalcards"			, OFS(preferlocalcards),	0 ),
	DEF_OPT_INT("readerrestartseconds"		, OFS(reader_restart_seconds), 5 ),
	DEF_OPT_INT("dropdups"					, OFS(dropdups),			0 ),
#ifdef CS_CACHEEX
	DEF_OPT_UINT("cacheexwaittime"			, OFS(cacheex_wait_time),	DEFAULT_CACHEEX_WAIT_TIME ),
	DEF_OPT_INT("cacheexenablestats"		, OFS(cacheex_enable_stats), 0 ),
#endif
	DEF_OPT_INT("block_same_ip"				, OFS(block_same_ip),		1 ),
	DEF_OPT_INT("block_same_name"			, OFS(block_same_name),		1 ),
	DEF_OPT_STR("usrfile"					, OFS(usrfile),				NULL ),
	DEF_OPT_STR("mailfile"					, OFS(mailfile),			NULL ),
	DEF_OPT_STR("cwlogdir"					, OFS(cwlogdir),			NULL ),
	DEF_OPT_STR("emmlogdir"					, OFS(emmlogdir),			NULL ),
#ifdef WITH_LB
	DEF_OPT_INT("lb_mode"					, OFS(lb_mode),				DEFAULT_LB_MODE ),
	DEF_OPT_INT("lb_save"					, OFS(lb_save),				0 ),
	DEF_OPT_INT("lb_nbest_readers"			, OFS(lb_nbest_readers),	DEFAULT_NBEST ),
	DEF_OPT_INT("lb_nfb_readers"			, OFS(lb_nfb_readers),		DEFAULT_NFB ),
	DEF_OPT_INT("lb_min_ecmcount"			, OFS(lb_min_ecmcount),		DEFAULT_MIN_ECM_COUNT ),
	DEF_OPT_INT("lb_max_ecmcount"			, OFS(lb_max_ecmcount),		DEFAULT_MAX_ECM_COUNT ),
	DEF_OPT_INT("lb_reopen_seconds"			, OFS(lb_reopen_seconds),	DEFAULT_REOPEN_SECONDS ),
	DEF_OPT_INT("lb_retrylimit"				, OFS(lb_retrylimit),		DEFAULT_RETRYLIMIT ),
	DEF_OPT_INT("lb_stat_cleanup"			, OFS(lb_stat_cleanup),		DEFAULT_LB_STAT_CLEANUP ),
	DEF_OPT_INT("lb_reopen_mode"			, OFS(lb_reopen_mode),		DEFAULT_LB_REOPEN_MODE ),
	DEF_OPT_INT("lb_max_readers"			, OFS(lb_max_readers),		0 ),
	DEF_OPT_INT("lb_auto_betatunnel"		, OFS(lb_auto_betatunnel),	DEFAULT_LB_AUTO_BETATUNNEL ),
	DEF_OPT_INT("lb_auto_betatunnel_prefer_beta"	, OFS(lb_auto_betatunnel_prefer_beta), DEFAULT_LB_AUTO_BETATUNNEL_PREFER_BETA ),
	DEF_OPT_STR("lb_savepath"				, OFS(lb_savepath),			NULL ),
	DEF_OPT_FUNC("lb_retrylimits"			, OFS(lb_retrylimittab), caidvaluetab_fn ),
	DEF_OPT_FUNC("lb_nbest_percaid"			, OFS(lb_nbest_readers_tab), caidvaluetab_fn ),
	DEF_OPT_FUNC("lb_noproviderforcaid"		, OFS(lb_noproviderforcaid), check_caid_fn ),
#endif
	DEF_OPT_FUNC("double_check_caid"		, OFS(double_check_caid),	check_caid_fn ),
	DEF_OPT_STR("ecmfmt"					, OFS(ecmfmt),				NULL ),
	DEF_OPT_INT("resolvegethostbyname"		, OFS(resolve_gethostbyname), 0 ),
	DEF_OPT_INT("failbantime"				, OFS(failbantime),			0 ),
	DEF_OPT_INT("failbancount"				, OFS(failbancount),		0 ),
	DEF_OPT_INT("suppresscmd08"				, OFS(c35_suppresscmd08),	0 ),
	DEF_OPT_INT("double_check"				, OFS(double_check),		0 ),
	DEF_OPT_UINT("max_cache_time"			, OFS(max_cache_time),		DEFAULT_MAX_CACHE_TIME ),
	DEF_OPT_UINT("max_cache_count"			, OFS(max_cache_count),		DEFAULT_MAX_CACHE_COUNT ),
	DEF_LAST_OPT
};

#ifdef CS_ANTICASC
static bool anticasc_should_save_fn(void) { return cfg.ac_enabled; }

static const struct config_list anticasc_opts[] = {
	DEF_OPT_SAVE_FUNC(anticasc_should_save_fn),
	DEF_OPT_INT("enabled"					, OFS(ac_enabled),				0 ),
	DEF_OPT_INT("numusers"					, OFS(ac_users),				0 ),
	DEF_OPT_INT("sampletime"				, OFS(ac_stime),				2 ),
	DEF_OPT_INT("samples"					, OFS(ac_samples),				10 ),
	DEF_OPT_INT("penalty"					, OFS(ac_penalty),				0 ),
	DEF_OPT_STR("aclogfile"					, OFS(ac_logfile),				NULL ),
	DEF_OPT_INT("fakedelay"					, OFS(ac_fakedelay),			3000 ),
	DEF_OPT_INT("denysamples"				, OFS(ac_denysamples),			8 ),
	DEF_LAST_OPT
};
#else
static const struct config_list anticasc_opts[] = { DEF_LAST_OPT };
#endif

#ifdef MODULE_MONITOR
static bool monitor_should_save_fn(void) { return cfg.mon_port; }

static const struct config_list monitor_opts[] = {
	DEF_OPT_SAVE_FUNC(monitor_should_save_fn),
	DEF_OPT_INT("port"						, OFS(mon_port),				0 ),
	DEF_OPT_FUNC("serverip"					, OFS(mon_srvip),				serverip_fn ),
	DEF_OPT_FUNC("nocrypt"					, OFS(mon_allowed),				iprange_fn ),
	DEF_OPT_INT("aulow"						, OFS(mon_aulow),				30 ),
	DEF_OPT_INT("monlevel"					, OFS(mon_level),				2 ),
	DEF_OPT_INT("hideclient_to"				, OFS(mon_hideclient_to),		15 ),
	DEF_OPT_INT("appendchaninfo"			, OFS(mon_appendchaninfo),		0 ),
	DEF_LAST_OPT
};
#else
static const struct config_list monitor_opts[] = { DEF_LAST_OPT };
#endif

#ifdef WEBIF
static void http_port_fn(const char *token, char *value, void *UNUSED(setting), FILE *f) {
	if (value) {
		cfg.http_port = 0;
		if (value[0]) {
			if (value[0] == '+') {
				if (config_WITH_SSL()) {
					cfg.http_use_ssl = 1;
				} else {
					fprintf(stderr, "Warning: OSCam compiled without SSL support.\n");
				}
				cfg.http_port = strtoul(value + 1, NULL, 10);
			} else {
				cfg.http_port = strtoul(value, NULL, 10);
			}
		}
		return;
	}
	fprintf_conf(f, token, "%s%d\n", cfg.http_use_ssl ? "+" : "", cfg.http_port);
}

static void http_dyndns_fn(const char *token, char *value, void *UNUSED(setting), FILE *f) {
	int i;
	if (value) {
		char *ptr, *saveptr1 = NULL;
		for (i = 0, ptr = strtok_r(value, ",", &saveptr1); (i < MAX_HTTP_DYNDNS) && (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++) {
			trim(ptr);
			cs_strncpy((char *)cfg.http_dyndns[i], ptr, sizeof(cfg.http_dyndns[i]));
		}
		return;
	}
	if (strlen((const char *)(cfg.http_dyndns[0])) > 0 || cfg.http_full_cfg) {
		fprintf_conf(f, token, "%s", "");
		for (i = 0; i < MAX_HTTP_DYNDNS; i++) {
			if (cfg.http_dyndns[i][0]) {
				fprintf(f, "%s%s", i > 0 ? "," : "", cfg.http_dyndns[i]);
			}
		}
		fprintf(f, "\n");
	}
}

static bool webif_should_save_fn(void) { return cfg.http_port; }

static const struct config_list webif_opts[] = {
	DEF_OPT_SAVE_FUNC(webif_should_save_fn),
	DEF_OPT_FUNC("httpport"					, OFS(http_port),				http_port_fn ),
	DEF_OPT_STR("httpuser"					, OFS(http_user),				NULL ),
	DEF_OPT_STR("httppwd"					, OFS(http_pwd),				NULL ),
	DEF_OPT_STR("httpcss"					, OFS(http_css),				NULL ),
	DEF_OPT_STR("httpjscript"				, OFS(http_jscript),			NULL ),
	DEF_OPT_STR("httpscript"				, OFS(http_script),				NULL ),
	DEF_OPT_STR("httptpl"					, OFS(http_tpl),				NULL ),
	DEF_OPT_STR("httphelplang"				, OFS(http_help_lang),			"en" ),
	DEF_OPT_STR("httpcert"					, OFS(http_cert),				NULL ),
	DEF_OPT_INT("http_prepend_embedded_css"	, OFS(http_prepend_embedded_css), 0 ),
	DEF_OPT_INT("httprefresh"				, OFS(http_refresh),			0 ),
	DEF_OPT_INT("httphideidleclients"		, OFS(http_hide_idle_clients),	0 ),
	DEF_OPT_INT("httpshowpicons"			, OFS(http_showpicons),			0 ),
	DEF_OPT_FUNC("httpallowed"				, OFS(http_allowed),			iprange_fn ),
	DEF_OPT_INT("httpreadonly"				, OFS(http_readonly),			0 ),
	DEF_OPT_INT("httpsavefullcfg"			, OFS(http_full_cfg),			0 ),
	DEF_OPT_INT("httpforcesslv3"			, OFS(http_force_sslv3),		0 ),
	DEF_OPT_FUNC("httpdyndns"				, OFS(http_dyndns),				http_dyndns_fn ),
	DEF_LAST_OPT
};
#else
static const struct config_list webif_opts[] = { DEF_LAST_OPT };
#endif

#ifdef MODULE_CAMD33
static void camd33_key_fn(const char *token, char *value, void *UNUSED(setting), FILE *f) {
	if (value) {
		cfg.c33_crypted = 1;
		if (!strlen(value))
			cfg.c33_crypted = 0;
		else if (key_atob_l(value, cfg.c33_key, 32)) {
			cfg.c33_crypted = 0;
			memset(cfg.c33_key, 0, sizeof(cfg.c33_key));
			fprintf(stderr, "ERROR: camd3.3 config error in 'key'.\n");
		}
		return;
	}
	unsigned int i;
	fprintf_conf_n(f, token);
	for (i = 0; i < sizeof(cfg.c33_key); i++) {
		fprintf(f, "%02X", cfg.c33_key[i]);
	}
	fprintf(f, "\n");
}

static bool camd33_should_save_fn(void) { return cfg.c33_port; }

static const struct config_list camd33_opts[] = {
	DEF_OPT_SAVE_FUNC(camd33_should_save_fn),
	DEF_OPT_INT("port"						, OFS(c33_port),				0 ),
	DEF_OPT_FUNC("serverip"					, OFS(c33_srvip),				serverip_fn ),
	DEF_OPT_FUNC("nocrypt"					, OFS(c33_plain),				iprange_fn ),
	DEF_OPT_INT("passive"					, OFS(c33_passive),				0 ),
	DEF_OPT_FUNC("key"						, OFS(c33_key),					camd33_key_fn ),
	DEF_LAST_OPT
};
#else
static const struct config_list camd33_opts[] = { DEF_LAST_OPT };
#endif

#ifdef CS_CACHEEX
static bool csp_should_save_fn(void) { return cfg.csp_port; }

static const struct config_list csp_opts[] = {
	DEF_OPT_SAVE_FUNC(csp_should_save_fn),
	DEF_OPT_INT("port"						, OFS(csp_port),				0 ),
	DEF_OPT_FUNC("serverip"					, OFS(csp_srvip),				serverip_fn ),
	DEF_OPT_UINT("wait_time"				, OFS(csp_wait_time),			0 ),
	DEF_LAST_OPT
};
#else
static const struct config_list csp_opts[] = { DEF_LAST_OPT };
#endif

#ifdef MODULE_CAMD35
static bool camd35_should_save_fn(void) { return cfg.c35_port; }

static const struct config_list camd35_opts[] = {
	DEF_OPT_SAVE_FUNC(camd35_should_save_fn),
	DEF_OPT_INT("port"						, OFS(c35_port),				0 ),
	DEF_OPT_FUNC("serverip"					, OFS(c35_srvip),				serverip_fn ),
	DEF_OPT_INT("suppresscmd08"				, OFS(c35_udp_suppresscmd08),	0 ),
	DEF_LAST_OPT
};
#else
static const struct config_list camd35_opts[] = { DEF_LAST_OPT };
#endif

#ifdef MODULE_CAMD35_TCP
static void porttab_cs378x_fn(const char *token, char *value, void *setting, FILE *f) {
	PTAB *ptab = setting;
	if (value) {
		if(strlen(value) == 0) {
			clear_ptab(ptab);
		} else {
			chk_port_tab(value, ptab);
		}
		return;
	}
	value = mk_t_camd35tcp_port();
	fprintf_conf(f, token, "%s\n", value);
	free_mk_t(value);
}

static bool cs378x_should_save_fn(void) { return cfg.c35_tcp_ptab.nports && cfg.c35_tcp_ptab.ports[0].s_port; }

static const struct config_list cs378x_opts[] = {
	DEF_OPT_SAVE_FUNC(cs378x_should_save_fn),
	DEF_OPT_FUNC("port"						, OFS(c35_tcp_ptab),			porttab_cs378x_fn ),
	DEF_OPT_FUNC("serverip"					, OFS(c35_tcp_srvip),			serverip_fn ),
	DEF_OPT_INT("suppresscmd08"				, OFS(c35_tcp_suppresscmd08),	0 ),
	DEF_LAST_OPT
};
#else
static const struct config_list cs378x_opts[] = { DEF_LAST_OPT };
#endif

#ifdef MODULE_NEWCAMD
static void porttab_newcamd_fn(const char *token, char *value, void *setting, FILE *f) {
	PTAB *ptab = setting;
	if (value) {
		if(strlen(value) == 0) {
			clear_ptab(ptab);
		} else {
			chk_port_tab(value, ptab);
		}
		return;
	}
	value = mk_t_newcamd_port();
	fprintf_conf(f, token, "%s\n", value);
	free_mk_t(value);
}

static void newcamd_key_fn(const char *token, char *value, void *UNUSED(setting), FILE *f) {
	if (value) {
		if (strlen(value) == 0) {
			memset(cfg.ncd_key, 0, sizeof(cfg.ncd_key));
		} else if (key_atob_l(value, cfg.ncd_key, 28)) {
			fprintf(stderr, "Configuration newcamd: Error in Key\n");
			memset(cfg.ncd_key, 0, sizeof(cfg.ncd_key));
		}
		return;
	}
	fprintf_conf_n(f, token);
	unsigned int i;
	for (i = 0; i < 14; i++) {
		fprintf(f,"%02X", cfg.ncd_key[i]);
	}
	fprintf(f,"\n");
}

static bool newcamd_should_save_fn(void) { return cfg.ncd_ptab.nports && cfg.ncd_ptab.ports[0].s_port; }

static const struct config_list newcamd_opts[] = {
	DEF_OPT_SAVE_FUNC(newcamd_should_save_fn),
	DEF_OPT_FUNC("port"						, OFS(ncd_ptab),			porttab_newcamd_fn ),
	DEF_OPT_FUNC("serverip"					, OFS(ncd_srvip),			serverip_fn ),
	DEF_OPT_FUNC("allowed"					, OFS(ncd_allowed),			iprange_fn ),
	DEF_OPT_FUNC("key"						, OFS(ncd_key),				newcamd_key_fn ),
	DEF_OPT_INT("keepalive"					, OFS(ncd_keepalive),		DEFAULT_NCD_KEEPALIVE ),
	DEF_OPT_INT("mgclient"					, OFS(ncd_mgclient),		0 ),
	DEF_LAST_OPT
};
#else
static const struct config_list newcamd_opts[] = { DEF_LAST_OPT };
#endif

#ifdef MODULE_CCCAM
static void cccam_port_fn(const char *token, char *value, void *UNUSED(setting), FILE *f) {
	if (value) {
		int i;
		char *ptr, *saveptr1 = NULL;
		memset(cfg.cc_port, 0, sizeof(cfg.cc_port));
		for (i = 0, ptr = strtok_r(value, ",", &saveptr1); ptr && i < CS_MAXPORTS; ptr = strtok_r(NULL, ",", &saveptr1)) {
			cfg.cc_port[i] = strtoul(ptr, NULL, 10);
			if (cfg.cc_port[i])
				i++;
		}
		return;
	}
	value = mk_t_cccam_port();
	fprintf_conf(f, token, "%s\n", value);
	free_mk_t(value);
}

static void cccam_nodeid_fn(const char *token, char *value, void *UNUSED(setting), FILE *f) {
	if (value) {
		int i, valid = 0;
		memset(cfg.cc_fixed_nodeid, 0, 8);
		for (i = 0; i < 8 && value[i] != 0; i++) {
			cfg.cc_fixed_nodeid[i] = gethexval(value[i*2]) << 4 | gethexval(value[i*2+1]);
			if (cfg.cc_fixed_nodeid[i])
				valid = 1;
		}
		cfg.cc_use_fixed_nodeid = valid && i == 8;
		return;
	}
	if (cfg.cc_use_fixed_nodeid || cfg.http_full_cfg) {
		fprintf_conf(f, token, "%02X%02X%02X%02X%02X%02X%02X%02X\n",
			cfg.cc_fixed_nodeid[0], cfg.cc_fixed_nodeid[1], cfg.cc_fixed_nodeid[2], cfg.cc_fixed_nodeid[3],
			cfg.cc_fixed_nodeid[4], cfg.cc_fixed_nodeid[5], cfg.cc_fixed_nodeid[6], cfg.cc_fixed_nodeid[7]);
	}
}

static bool cccam_should_save_fn(void) { return cfg.cc_port[0]; }

static const struct config_list cccam_opts[] = {
	DEF_OPT_SAVE_FUNC(cccam_should_save_fn),
	DEF_OPT_FUNC("port"						, OFS(cc_port),				cccam_port_fn ),
	DEF_OPT_FUNC("nodeid"					, OFS(cc_fixed_nodeid),		cccam_nodeid_fn ),
	DEF_OPT_SSTR("version"					, OFS(cc_version),			"", SIZEOF(cc_version) ),
	DEF_OPT_INT("reshare"					, OFS(cc_reshare),			10 ),
	DEF_OPT_INT("reshare_mode"				, OFS(cc_reshare_services),	0 ),
	DEF_OPT_INT("ignorereshare"				, OFS(cc_ignore_reshare),	0 ),
	DEF_OPT_INT("forward_origin_card"		, OFS(cc_forward_origin_card), 0 ),
	DEF_OPT_INT("stealth"					, OFS(cc_stealth),			0 ),
	DEF_OPT_INT("updateinterval"			, OFS(cc_update_interval),	DEFAULT_UPDATEINTERVAL ),
	DEF_OPT_INT("minimizecards"				, OFS(cc_minimize_cards),	0 ),
	DEF_OPT_INT("keepconnected"				, OFS(cc_keep_connected),	1 ),
	DEF_LAST_OPT
};
#else
static const struct config_list cccam_opts[] = { DEF_LAST_OPT };
#endif

#ifdef MODULE_PANDORA
static bool pandora_should_save_fn(void) { return cfg.pand_port; }

static const struct config_list pandora_opts[] = {
	DEF_OPT_SAVE_FUNC(pandora_should_save_fn),
	DEF_OPT_INT("pand_port"					, OFS(pand_port),			0 ),
	DEF_OPT_FUNC("pand_srvid"				, OFS(pand_srvip),			serverip_fn ),
	DEF_OPT_STR("pand_usr"					, OFS(pand_usr),			NULL ),
	DEF_OPT_STR("pand_pass"					, OFS(pand_pass),			NULL ),
	DEF_OPT_INT("pand_ecm"					, OFS(pand_ecm),			0 ),
	DEF_OPT_INT("pand_skip_send_dw"			, OFS(pand_skip_send_dw),	0 ),
	DEF_OPT_FUNC("pand_allowed"				, OFS(pand_allowed),		iprange_fn ),
	DEF_LAST_OPT
};
#else
static const struct config_list pandora_opts[] = { DEF_LAST_OPT };
#endif

#ifdef MODULE_RADEGAST
static bool radegast_should_save_fn(void) { return cfg.rad_port; }

static const struct config_list radegast_opts[] = {
	DEF_OPT_SAVE_FUNC(radegast_should_save_fn),
	DEF_OPT_INT("port"						, OFS(rad_port),			0 ),
	DEF_OPT_FUNC("serverip"					, OFS(rad_srvip),			serverip_fn ),
	DEF_OPT_FUNC("allowed"					, OFS(rad_allowed),			iprange_fn ),
	DEF_OPT_STR("user"						, OFS(rad_usr),				NULL ),
	DEF_LAST_OPT
};
#else
static const struct config_list radegast_opts[] = { DEF_LAST_OPT };
#endif

#ifdef MODULE_SERIAL
static bool serial_should_save_fn(void) { return cfg.ser_device != NULL; }

static const struct config_list serial_opts[] = {
	DEF_OPT_SAVE_FUNC(serial_should_save_fn),
	DEF_OPT_STR("device"						, OFS(ser_device),		NULL ),
	DEF_LAST_OPT
};
#else
static const struct config_list serial_opts[] = { DEF_LAST_OPT };
#endif

#ifdef MODULE_GBOX
static bool gbox_should_save_fn(void) { return cfg.gbox_port; }

static const struct config_list gbox_opts[] = {
	DEF_OPT_SAVE_FUNC(gbox_should_save_fn),
	DEF_OPT_INT("port"						, OFS(gbox_port),			0 ),
	DEF_OPT_STR("gsmsfile"					, OFS(gbox_gsms_path),		NULL ),
	DEF_OPT_STR("hostname"					, OFS(gbox_hostname),		NULL ),
	DEF_OPT_STR("password"					, OFS(gbox_key),			NULL ),
	DEF_LAST_OPT
};
#else
static const struct config_list gbox_opts[] = { DEF_LAST_OPT };
#endif

#ifdef HAVE_DVBAPI
static void dvbapi_boxtype_fn(const char *token, char *value, void *UNUSED(setting), FILE *f) {
	if (value) {
		int i;
		cfg.dvbapi_boxtype = 0;
		for (i = 1; i <= BOXTYPES; i++) {
			if (streq(value, boxdesc[i])) {
				cfg.dvbapi_boxtype = i;
				break;
			}
		}
		return;
	}
	if (cfg.dvbapi_boxtype)
		fprintf_conf(f, token, "%s\n", boxdesc[cfg.dvbapi_boxtype]);
}

static void dvbapi_services_fn(const char *UNUSED(token), char *value, void *UNUSED(setting), FILE *UNUSED(f)) {
	if (value)
		chk_services(value, &cfg.dvbapi_sidtabok, &cfg.dvbapi_sidtabno);
	// THIS OPTION IS NOT SAVED
}

static void dvbapi_caidtab_fn(const char *token, char *value, void *UNUSED(setting), FILE *UNUSED(f)) {
	char cmd = ' ';
	if (streq(token, "priority")) cmd = 'p';
	if (streq(token, "ignore"))   cmd = 'i';
	if (streq(token, "cw_delay")) cmd = 'd';
	if (value && cmd != ' ')
		dvbapi_chk_caidtab(value, cmd);
	// THIS OPTION IS NOT SAVED
}

static bool dvbapi_should_save_fn(void) { return cfg.dvbapi_enabled; }

static const struct config_list dvbapi_opts[] = {
	DEF_OPT_SAVE_FUNC(dvbapi_should_save_fn),
	DEF_OPT_INT("enabled"					, OFS(dvbapi_enabled),		0 ),
	DEF_OPT_INT("au"						, OFS(dvbapi_au),			0 ),
	DEF_OPT_INT("pmt_mode"					, OFS(dvbapi_pmtmode),		0 ),
	DEF_OPT_INT("request_mode"				, OFS(dvbapi_requestmode),	0 ),
	DEF_OPT_INT("request_mode"				, OFS(dvbapi_requestmode),	0 ),
	DEF_OPT_INT("reopenonzap"				, OFS(dvbapi_reopenonzap),	0 ),
	DEF_OPT_INT("delayer"					, OFS(dvbapi_delayer),		0 ),
	DEF_OPT_STR("user"						, OFS(dvbapi_usr),			NULL ),
	DEF_OPT_FUNC("boxtype"					, OFS(dvbapi_boxtype),		dvbapi_boxtype_fn ),
	DEF_OPT_FUNC("services"					, OFS(dvbapi_sidtabok),		dvbapi_services_fn ),
	// OBSOLETE OPTIONS
	DEF_OPT_FUNC("priority"					, 0,						dvbapi_caidtab_fn ),
	DEF_OPT_FUNC("ignore"					, 0,						dvbapi_caidtab_fn ),
	DEF_OPT_FUNC("cw_delay"					, 0,						dvbapi_caidtab_fn ),
	DEF_LAST_OPT
};
#else
static const struct config_list dvbapi_opts[] = { DEF_LAST_OPT };
#endif

#ifdef LCDSUPPORT
static bool lcd_should_save_fn(void) { return cfg.enablelcd; }

static const struct config_list lcd_opts[] = {
	DEF_OPT_SAVE_FUNC(lcd_should_save_fn),
	DEF_OPT_INT("enablelcd"					, OFS(enablelcd),			0 ),
	DEF_OPT_STR("lcd_outputpath"			, OFS(lcd_output_path),		NULL ),
	DEF_OPT_INT("lcd_hideidle"				, OFS(lcd_hide_idle),		0 ),
	DEF_OPT_INT("lcd_writeintervall"		, OFS(lcd_write_intervall),	10 ),
	DEF_LAST_OPT
};
#else
static const struct config_list lcd_opts[] = { DEF_LAST_OPT };
#endif

static const struct config_sections oscam_conf[] = {
	{ "global",   global_opts }, // *** MUST BE FIRST ***
	{ "anticasc", anticasc_opts },
	{ "csp",      csp_opts },
	{ "lcd",      lcd_opts },
	{ "camd33",   camd33_opts },
	{ "cs357x",   camd35_opts },
	{ "cs378x",   cs378x_opts },
	{ "newcamd",  newcamd_opts },
	{ "radegast", radegast_opts },
	{ "serial",   serial_opts },
	{ "gbox",     gbox_opts },
	{ "cccam",    cccam_opts },
	{ "pandora",  pandora_opts },
	{ "dvbapi",   dvbapi_opts },
	{ "monitor",  monitor_opts },
	{ "webif",    webif_opts },
	{ NULL, NULL }
};

void config_set(char *section, const char *token, char *value) {
	config_set_value(oscam_conf, section, token, value, &cfg);
}

int32_t init_config(void)
{
	const struct config_sections *cur_section = oscam_conf; // Global
	FILE *fp;
	char *token;

	if(!cs_malloc(&token, MAXLINESIZE, -1)) return 1;

	config_sections_set_defaults(oscam_conf);

	snprintf(token, MAXLINESIZE, "%s%s", cs_confdir, cs_conf);
	if (!(fp = fopen(token, "r"))) {
		fprintf(stderr, "Cannot open config file '%s' (errno=%d %s)\n", token, errno, strerror(errno));
		exit(1);
	}

	int line = 0;
	int valid_section = 1;
	while (fgets(token, MAXLINESIZE, fp)) {
		++line;
		int len = strlen(trim(token));
		if (len < 3) // a=b or [a] are at least 3 chars
			continue;
		if (token[0] == '#') // Skip comments
			continue;
		if (token[0] == '[' && token[len - 1] == ']') {
			token[len - 1] = '\0';
			valid_section = 0;
			const struct config_sections *newconf = config_find_section(oscam_conf, token + 1);
			if (config_section_is_active(newconf)) {
				cur_section = newconf;
				valid_section = 1;
			}
			if (!newconf) {
				fprintf(stderr, "WARNING: %s line %d unknown section [%s].\n",
					cs_conf, line, token + 1);
				continue;
			}
			if (!config_section_is_active(newconf)) {
				fprintf(stderr, "WARNING: %s line %d section [%s] is ignorred (support not compiled in).\n",
					cs_conf, line, newconf->section);
			}
			continue;
		}
		if (!valid_section)
			continue;
		char *value = strchr(token, '=');
		if (!value) // No = found, well go on
			continue;
		*value++ ='\0';
		char *tvalue = trim(value);
		char *ttoken = trim(strtolower(token));
		if (!config_list_parse(cur_section->config, ttoken, tvalue, &cfg)) {
			fprintf(stderr, "WARNING: %s line %d section [%s] contains unknown setting '%s=%s'\n",
				cs_conf, line, cur_section->section, ttoken, tvalue);
		}
	}
	free(token);
	fclose(fp);

	// Apply configuration fixups
	if (!cfg.usrfile)
		cfg.disableuserfile = 1;

	if (!cfg.mailfile)
		cfg.disablemail = 1;

	if (cfg.ctimeout < 100)
		cfg.ctimeout *= 1000;

	if (cfg.ftimeout < 100)
		cfg.ftimeout *= 1000;

	if (cfg.nice < -20 || cfg.nice > 20)
		cfg.nice = 99;

	if (cfg.nice != 99)
		cs_setpriority(cfg.nice);

	if (cfg.srtimeout <= 0)
		cfg.srtimeout = 1500;
	if (cfg.srtimeout < 100)
		cfg.srtimeout *= 1000;

	if (cfg.max_log_size != 0 && cfg.max_log_size <= 10)
		cfg.max_log_size = 10;

#ifdef WITH_LB
	if (cfg.lb_save > 0 && cfg.lb_save < 100) {
		fprintf(stderr, "WARNING: %s (%d) was corrected to the minimum: %d\n",
			token, cfg.lb_save, 100);
		cfg.lb_save = 100;
	}

	if (cfg.lb_nbest_readers < 2)
		cfg.lb_nbest_readers = DEFAULT_NBEST;
#endif

#ifdef LCDSUPPORT
	if (cfg.lcd_write_intervall < 5)
		cfg.lcd_write_intervall = 5;
#endif

	cs_init_log();
	cs_init_statistics();
	if (cfg.ftimeout >= cfg.ctimeout) {
		cfg.ftimeout = cfg.ctimeout - 100;
		cs_log("WARNING: fallbacktimeout adjusted to %u ms (must be smaller than clienttimeout (%u ms))", cfg.ftimeout, cfg.ctimeout);
	}
	if(cfg.ftimeout < cfg.srtimeout) {
		cfg.ftimeout = cfg.srtimeout + 100;
		cs_log("WARNING: fallbacktimeout adjusted to %u ms (must be greater than serialreadertimeout (%u ms))", cfg.ftimeout, cfg.srtimeout);
	}
	if(cfg.ctimeout < cfg.srtimeout) {
		cfg.ctimeout = cfg.srtimeout + 100;
		cs_log("WARNING: clienttimeout adjusted to %u ms (must be greater than serialreadertimeout (%u ms))", cfg.ctimeout, cfg.srtimeout);
	}
	if (cfg.max_cache_time < (cfg.ctimeout/1000+1))
		cfg.max_cache_time = cfg.ctimeout/1000+2;

#ifdef CS_ANTICASC
	// Anticascating config fixups
	if (cfg.ac_users < 0)
		cfg.ac_users = 0;

	if (cfg.ac_stime < 0)
		cfg.ac_stime = 2;

	if (cfg.ac_samples < 2 || cfg.ac_samples > 10)
		cfg.ac_samples = 10;

	if (cfg.ac_penalty < 0 || cfg.ac_penalty > 3)
		cfg.ac_penalty = 0;

	if (cfg.ac_fakedelay < 100 || cfg.ac_fakedelay > 3000)
		cfg.ac_fakedelay = 1000;

	if (cfg.ac_denysamples < 2 || cfg.ac_denysamples > cfg.ac_samples - 1)
		cfg.ac_denysamples = cfg.ac_samples - 1;

	if (cfg.ac_denysamples + 1 > cfg.ac_samples) {
		cfg.ac_denysamples = cfg.ac_samples - 1;
		cs_log("WARNING: DenySamples adjusted to %d", cfg.ac_denysamples);
	}
#endif
	return 0;
}

int32_t write_config(void)
{
	FILE *f;
	char tmpfile[256];
	char destfile[256];
	char bakfile[256];

	snprintf(destfile, sizeof(destfile),"%s%s", cs_confdir, cs_conf);
	snprintf(tmpfile, sizeof(tmpfile), "%s%s.tmp", cs_confdir, cs_conf);
	snprintf(bakfile, sizeof(bakfile),"%s%s.bak", cs_confdir, cs_conf);

	if (!(f=fopen(tmpfile, "w"))){
		cs_log("Cannot open file \"%s\" (errno=%d %s)", tmpfile, errno, strerror(errno));
		return(1);
	}
	setvbuf(f, NULL, _IOFBF, 16*1024);
	fprintf(f,"# oscam.conf generated automatically by Streamboard OSCAM %s build #%s\n", CS_VERSION, CS_SVN_VERSION);
	fprintf(f,"# Read more: http://streamboard.de.vu/svn/oscam/trunk/Distribution/doc/txt/oscam.conf.txt\n\n");
	config_sections_save(oscam_conf, f);
	fclose(f);

	return(safe_overwrite_with_bak(destfile, tmpfile, bakfile, 0));
}

void chk_account(const char *token, char *value, struct s_auth *account)
{
	int32_t i;
	char *ptr1, *saveptr1 = NULL;

	if (!strcmp(token, "user")) {
		cs_strncpy(account->usr, value, sizeof(account->usr));
		return;
	}

	if (!strcmp(token, "pwd")) {
		cs_strncpy(account->pwd, value, sizeof(account->pwd));
		return;
	}

	if (!strcmp(token, "allowedprotocols")) {
		account->allowedprotocols = 0;
		if(strlen(value) > 3) {
			char *ptr;
			for (i = 0, ptr = strtok_r(value, ",", &saveptr1); (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++){
				if		(!strcmp(ptr, "camd33"))	account->allowedprotocols |= LIS_CAMD33TCP;
				else if (!strcmp(ptr, "camd35"))	account->allowedprotocols |= LIS_CAMD35UDP;
				else if (!strcmp(ptr, "cs357x"))	account->allowedprotocols |= LIS_CAMD35UDP;
				else if (!strcmp(ptr, "cs378x"))	account->allowedprotocols |= LIS_CAMD35TCP;
				else if (!strcmp(ptr, "newcamd"))	account->allowedprotocols |= LIS_NEWCAMD;
				else if (!strcmp(ptr, "cccam"))		account->allowedprotocols |= LIS_CCCAM;
				else if (!strcmp(ptr, "csp"))		account->allowedprotocols |= LIS_CSPUDP;
				else if (!strcmp(ptr, "gbox"))		account->allowedprotocols |= LIS_GBOX;
				else if (!strcmp(ptr, "radegast"))	account->allowedprotocols |= LIS_RADEGAST;
				// these have no listener ports so it doesn't make sense
				else if (!strcmp(ptr, "dvbapi"))	account->allowedprotocols |= LIS_DVBAPI;
				else if (!strcmp(ptr, "constcw"))	account->allowedprotocols |= LIS_CONSTCW;
				else if (!strcmp(ptr, "serial"))	account->allowedprotocols |= LIS_SERIAL;
			}
		}
		return;
	}

#ifdef WEBIF
	if (!strcmp(token, "description")) {
		NULLFREE(account->description);
		if(strlen(value) > 0 && cs_malloc(&account->description, strlen(value)+1, -1)){
			cs_strncpy(account->description, value, strlen(value)+1);
		}
		return;
	}
#endif

	if (!strcmp(token, "hostname")) {
		cs_strncpy((char *)account->dyndns, value, sizeof(account->dyndns));
		return;
	}

	if (!strcmp(token, "betatunnel")) {
		if(strlen(value) == 0) {
			clear_tuntab(&account->ttab);
			return;
		} else {
			chk_tuntab(value, &account->ttab);
			return;
		}
	}

	if (!strcmp(token, "uniq")) {
		account->uniq = strToIntVal(value, 0);
		return;
	}

#ifdef CS_CACHEEX
	if (!strcmp(token, "cacheex")) {
		account->cacheex = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "cacheex_maxhop")) {
		account->cacheex_maxhop = strToIntVal(value, 0);
		return;
	}
#endif

	if (!strcmp(token, "sleep")) {
		account->tosleep = strToIntVal(value, cfg.tosleep);
		return;
	}

	if (!strcmp(token, "sleepsend")) {
		uint32_t tmp = strToUIntVal(value, 0);
		if (tmp > 0xFF)
			account->c35_sleepsend = 0xFF;
		else account->c35_sleepsend = tmp;
		return;
	}

	if (!strcmp(token, "monlevel")) {
		account->monlvl = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "caid")) {
		if(strlen(value) == 0) {
			clear_caidtab(&account->ctab);
			return;
		} else {
			chk_caidtab(value, &account->ctab);
			return;
		}
	}

	if (!strcmp(token, "disabled")) {
		account->disabled = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "suppresscmd08")) {
		account->c35_suppresscmd08 = strToIntVal(value, 0);
		return;
	}

#ifdef MODULE_CCCAM
	if (!strcmp(token, "cccmaxhops")) {
		account->cccmaxhops = strToIntVal(value, DEFAULT_CC_MAXHOP);
		return;
	}

	if (!strcmp(token, "cccreshare")) {
		account->cccreshare = strToIntVal(value, DEFAULT_CC_RESHARE);
		return;
	}

	if (!strcmp(token, "cccignorereshare")) {
		account->cccignorereshare = strToIntVal(value, DEFAULT_CC_IGNRSHR);
		return;
	}

	if (!strcmp(token, "cccstealth")) {
		account->cccstealth = strToIntVal(value, DEFAULT_CC_STEALTH);
		return;
	}
#endif

	if (!strcmp(token, "keepalive")) {
		account->ncd_keepalive = strToIntVal(value, DEFAULT_NCD_KEEPALIVE);
		return;
	}
	/*
	*  case insensitive
	*/
	strtolower(value);

	if (!strcmp(token, "au")) {

		// set default values for usage during runtime from Webif
		account->autoau = 0;

		if (!account->aureader_list)
			account->aureader_list = ll_create("aureader_list");

		if(value && value[0] == '1') {
			account->autoau = 1;
		}
		ll_clear(account->aureader_list);

		// exit if invalid or no value
		if ((strlen(value) == 0) || (value[0] == '0'))
			return;

		LL_ITER itr = ll_iter_create(configured_readers);
		struct s_reader *rdr;
		char *pch;

		for (pch = strtok_r(value, ",", &saveptr1); pch != NULL; pch = strtok_r(NULL, ",", &saveptr1)) {
			ll_iter_reset(&itr);
			while ((rdr = ll_iter_next(&itr))) {
				if (((rdr->label[0]) && (!strcmp(rdr->label, pch))) || account->autoau) {
					ll_append(account->aureader_list, rdr);
				}
			}
		}
		return;
	}

	if (!strcmp(token, "group")) {
		account->grp = 0;
		for (ptr1=strtok_r(value, ",", &saveptr1); ptr1; ptr1=strtok_r(NULL, ",", &saveptr1)) {
			int32_t g;
			g = atoi(ptr1);
			if ((g>0) && (g < 65)) account->grp|=(((uint64_t)1)<<(g-1));
		}
		return;
	}

	if(!strcmp(token, "services")) {
		chk_services(value, &account->sidtabok, &account->sidtabno);
		return;
	}

	if(!strcmp(token, "ident")) { /*ToDo ftab clear*/
		chk_ftab(value, &account->ftab, "user", account->usr, "provid");
		return;
	}

	if(!strcmp(token, "class")) {
		chk_cltab(value, &account->cltab);
		return;
	}

	if(!strcmp(token, "chid")) {
		chk_ftab(value, &account->fchid, "user", account->usr, "chid");
		return;
	}

	if (!strcmp(token, "expdate")) {
		if (!value[0]) {
			account->expirationdate=(time_t)NULL;
			return;
		}
		struct tm cstime;
		memset(&cstime,0,sizeof(cstime));
		for (i=0, ptr1=strtok_r(value, "-/", &saveptr1); (i<3)&&(ptr1); ptr1=strtok_r(NULL, "-/", &saveptr1), i++) {
			switch(i) {
				case 0: cstime.tm_year=atoi(ptr1)-1900; break;
				case 1: cstime.tm_mon =atoi(ptr1)-1;    break;
				case 2: cstime.tm_mday=atoi(ptr1);      break;
			}
		}
		cstime.tm_hour=23;
		cstime.tm_min=59;
		cstime.tm_sec=59;
		cstime.tm_isdst=-1;
		account->expirationdate=mktime(&cstime);
		return;
	}

	if (!strcmp(token, "allowedtimeframe")) {
		if(strlen(value) == 0) {
			account->allowedtimeframe[0] = 0;
			account->allowedtimeframe[1] = 0;
		} else {
			int32_t allowed[4];
			if (sscanf(value, "%2d:%2d-%2d:%2d", &allowed[0], &allowed[1], &allowed[2], &allowed[3]) != 4) {
				account->allowedtimeframe[0] = 0;
				account->allowedtimeframe[1] = 0;
				fprintf(stderr, "Warning: value '%s' is not valid for allowedtimeframe (hh:mm-hh:mm)\n", value);
			} else {
				account->allowedtimeframe[0] = (allowed[0]*60) + allowed[1];
				account->allowedtimeframe[1] = (allowed[2]*60) + allowed[3];
			}
		}
		return;
	}

	if (!strcmp(token, "failban")) {
		account->failban = strToIntVal(value, 0);
		return;
	}

#ifdef CS_ANTICASC
	if( !strcmp(token, "numusers") ) {
		account->ac_users = strToIntVal(value, DEFAULT_AC_USERS);
		if ( account->ac_users < -1 )
			account->ac_users = DEFAULT_AC_USERS;
		return;
	}

	if( !strcmp(token, "penalty") ) {
		account->ac_penalty = strToIntVal(value, DEFAULT_AC_PENALTY);
		if ( account->ac_penalty < -1 )
			account->ac_penalty = DEFAULT_AC_PENALTY;
		return;
	}
#endif

	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in account section not recognized\n",token);
}

int32_t write_services(void)
{
	int32_t i;
	FILE *f;
	struct s_sidtab *sidtab = cfg.sidtab;
	char tmpfile[256];
	char destfile[256];
	char bakfile[256];
	char *ptr;

	snprintf(destfile, sizeof(destfile),"%s%s", cs_confdir, cs_sidt);
	snprintf(tmpfile, sizeof(tmpfile), "%s%s.tmp", cs_confdir, cs_sidt);
	snprintf(bakfile, sizeof(bakfile),"%s%s.bak", cs_confdir, cs_sidt);

	if (!(f=fopen(tmpfile, "w"))){
		cs_log("Cannot open file \"%s\" (errno=%d %s)", tmpfile, errno, strerror(errno));
		return(1);
	}
	setvbuf(f, NULL, _IOFBF, 16*1024);
	fprintf(f,"# oscam.services generated automatically by Streamboard OSCAM %s build #%s\n", CS_VERSION, CS_SVN_VERSION);
	fprintf(f,"# Read more: http://streamboard.de.vu/svn/oscam/trunk/Distribution/doc/txt/oscam.services.txt\n\n");

	while(sidtab != NULL){
		ptr = sidtab->label;
		while (*ptr) {
			if (*ptr == ' ') *ptr = '_';
			ptr++;
		}
		fprintf(f,"[%s]\n", sidtab->label);
		fprintf_conf_n(f, "caid");
		for (i=0; i<sidtab->num_caid; i++){
			if (i==0) fprintf(f,"%04X", sidtab->caid[i]);
			else fprintf(f,",%04X", sidtab->caid[i]);
		}
		fputc((int)'\n', f);
		fprintf_conf_n(f, "provid");
		for (i=0; i<sidtab->num_provid; i++){
			if (i==0) fprintf(f,"%06X", sidtab->provid[i]);
			else fprintf(f,",%06X", sidtab->provid[i]);
		}
		fputc((int)'\n', f);
		fprintf_conf_n(f, "srvid");
		for (i=0; i<sidtab->num_srvid; i++){
			if (i==0) fprintf(f,"%04X", sidtab->srvid[i]);
			else fprintf(f,",%04X", sidtab->srvid[i]);
		}
		fprintf(f,"\n");
		sidtab=sidtab->next;
	}

	fclose(f);
	return(safe_overwrite_with_bak(destfile, tmpfile, bakfile, 0));
}

int32_t write_userdb(void)
{
	FILE *f;
	struct s_auth *account;
	char *value;
	char tmpfile[256];
	char destfile[256];
	char bakfile[256];

	snprintf(destfile, sizeof(destfile),"%s%s", cs_confdir, cs_user);
	snprintf(tmpfile, sizeof(tmpfile), "%s%s.tmp", cs_confdir, cs_user);
	snprintf(bakfile, sizeof(bakfile),"%s%s.bak", cs_confdir, cs_user);

  if (!(f=fopen(tmpfile, "w"))){
    cs_log("Cannot open file \"%s\" (errno=%d %s)", tmpfile, errno, strerror(errno));
    return(1);
  }
  setvbuf(f, NULL, _IOFBF, 16*1024);
  fprintf(f,"# oscam.user generated automatically by Streamboard OSCAM %s build #%s\n", CS_VERSION, CS_SVN_VERSION);
  fprintf(f,"# Read more: http://streamboard.de.vu/svn/oscam/trunk/Distribution/doc/txt/oscam.user.txt\n\n");

  //each account
	for (account=cfg.account; (account) ; account=account->next){
		fprintf(f,"[account]\n");
		fprintf_conf(f, "user", "%s\n", account->usr);
		fprintf_conf(f, "pwd", "%s\n", account->pwd);
#ifdef WEBIF
		if (account->description || cfg.http_full_cfg)
			fprintf_conf(f, "description", "%s\n", account->description?account->description:"");
#endif
		if (account->disabled || cfg.http_full_cfg)
			fprintf_conf(f, "disabled", "%d\n", account->disabled);

		if (account->expirationdate || cfg.http_full_cfg) {
			struct tm timeinfo;
			localtime_r(&account->expirationdate, &timeinfo);
			char buf [80];
			strftime (buf,80,"%Y-%m-%d",&timeinfo);
			if(strcmp(buf,"1970-01-01"))
				fprintf_conf(f, "expdate", "%s\n", buf);
			else
				fprintf_conf(f, "expdate", "\n");
		}


		if(account->allowedtimeframe[0] && account->allowedtimeframe[1]) {
			fprintf_conf(f, "allowedtimeframe", "%02d:%02d-%02d:%02d\n",
					account->allowedtimeframe[0]/60,
					account->allowedtimeframe[0]%60,
					account->allowedtimeframe[1]/60,
					account->allowedtimeframe[1]%60 );
		} else {
			if (cfg.http_full_cfg)
				fprintf_conf(f, "allowedtimeframe", "\n");
		}

		//group
		if (account->grp || cfg.http_full_cfg) {
			value = mk_t_group(account->grp);
			fprintf_conf(f, "group", "%s\n", value);
			free_mk_t(value);
		}

		if (account->dyndns[0] || cfg.http_full_cfg)
			fprintf_conf(f, "hostname", "%s\n", account->dyndns);

		if (account->uniq || cfg.http_full_cfg)
			fprintf_conf(f, "uniq", "%d\n", account->uniq);

#ifdef CS_CACHEEX
		if (account->cacheex || cfg.http_full_cfg)
			fprintf_conf(f, "cacheex", "%d\n", account->cacheex);

		if (account->cacheex_maxhop || cfg.http_full_cfg)
			fprintf_conf(f, "cacheex_maxhop", "%d\n", account->cacheex_maxhop);
#endif

		if (account->tosleep != cfg.tosleep || cfg.http_full_cfg)
			fprintf_conf(f, "sleep", "%d\n", account->tosleep);

		if (account->monlvl != cfg.mon_level || cfg.http_full_cfg)
			fprintf_conf(f, "monlevel", "%d\n", account->monlvl);

		if (account->autoau == 1)
			fprintf_conf(f, "au", "1\n");
		else if (account->aureader_list) {

			value = mk_t_aureader(account);
			if (strlen(value) > 0)
				fprintf_conf(f, "au", "%s\n", value);
			free_mk_t(value);

		} else if (cfg.http_full_cfg) fprintf_conf(f, "au", "\n");

		value = mk_t_service((uint64_t)account->sidtabok, (uint64_t)account->sidtabno);
		if (strlen(value) > 0 || cfg.http_full_cfg)
			fprintf_conf(f, "services", "%s\n", value);
		free_mk_t(value);

		// allowed protocols
		if (account->allowedprotocols || cfg.http_full_cfg ){
			value = mk_t_allowedprotocols(account);
			fprintf_conf(f, "allowedprotocols", "%s\n", value);
			free_mk_t(value);
		}

		//CAID
		if (account->ctab.caid[0] || cfg.http_full_cfg) {
			value = mk_t_caidtab(&account->ctab);
			fprintf_conf(f, "caid", "%s\n", value);
			free_mk_t(value);
		}

		//betatunnel
		if (account->ttab.bt_caidfrom[0] || cfg.http_full_cfg) {
			value = mk_t_tuntab(&account->ttab);
			fprintf_conf(f, "betatunnel", "%s\n", value);
			free_mk_t(value);
		}

		//ident
		if (account->ftab.nfilts || cfg.http_full_cfg) {
			value = mk_t_ftab(&account->ftab);
			fprintf_conf(f, "ident", "%s\n", value);
			free_mk_t(value);
		}

		//CHID
		if (account->fchid.nfilts || cfg.http_full_cfg) {
			value = mk_t_ftab(&account->fchid);
			fprintf_conf(f, "chid", "%s\n", value);
			free_mk_t(value);
		}

		//class
		if ((account->cltab.bn > 0 || account->cltab.an > 0) || cfg.http_full_cfg) {
			value = mk_t_cltab(&account->cltab);
			fprintf_conf(f, "class", "%s\n", value);
			free_mk_t(value);
		}

		if ((account->c35_suppresscmd08 != cfg.c35_suppresscmd08) || cfg.http_full_cfg)
			fprintf_conf(f, "suppresscmd08", "%d\n", account->c35_suppresscmd08);

#ifdef MODULE_CCCAM
		if (account->cccmaxhops != DEFAULT_CC_MAXHOP || cfg.http_full_cfg)
			fprintf_conf(f, "cccmaxhops", "%d\n", account->cccmaxhops);

		if (account->cccreshare != DEFAULT_CC_RESHARE || cfg.http_full_cfg)
			fprintf_conf(f, "cccreshare", "%d\n", account->cccreshare);

		if (account->cccignorereshare != DEFAULT_CC_IGNRSHR || cfg.http_full_cfg)
			fprintf_conf(f, "cccignorereshare", "%d\n", account->cccignorereshare);

		if (account->cccstealth != DEFAULT_CC_STEALTH || cfg.http_full_cfg)
			fprintf_conf(f, "cccstealth", "%d\n", account->cccstealth);
#endif

		if (account->c35_sleepsend || cfg.http_full_cfg)
			fprintf_conf(f, "sleepsend", "%u\n", account->c35_sleepsend);

		if (account->failban || cfg.http_full_cfg)
			fprintf_conf(f, "failban", "%d\n", account->failban);

		if ((account->ncd_keepalive != DEFAULT_NCD_KEEPALIVE) || cfg.http_full_cfg)
			fprintf_conf(f, "keepalive", "%d\n", account->ncd_keepalive);

#ifdef CS_ANTICASC
		if (account->ac_users != DEFAULT_AC_USERS || cfg.http_full_cfg)
			fprintf_conf(f, "numusers", "%d\n", account->ac_users);
		if (account->ac_penalty != DEFAULT_AC_PENALTY || cfg.http_full_cfg)
			fprintf_conf(f, "penalty", "%d\n", account->ac_penalty);
#endif
		fputc((int)'\n', f);
	}
  fclose(f);

  return(safe_overwrite_with_bak(destfile, tmpfile, bakfile, 0));
}

int32_t write_server(void)
{
	int32_t j;
	char *value;
	FILE *f;

	char tmpfile[256];
	char destfile[256];
	char bakfile[256];

	snprintf(destfile, sizeof(destfile),"%s%s", cs_confdir, cs_srvr);
	snprintf(tmpfile, sizeof(tmpfile), "%s%s.tmp", cs_confdir, cs_srvr);
	snprintf(bakfile, sizeof(bakfile),"%s%s.bak", cs_confdir, cs_srvr);

	if (!(f=fopen(tmpfile, "w"))){
		cs_log("Cannot open file \"%s\" (errno=%d %s)", tmpfile, errno, strerror(errno));
		return(1);
	}
	setvbuf(f, NULL, _IOFBF, 16*1024);
	fprintf(f,"# oscam.server generated automatically by Streamboard OSCAM %s build #%s\n", CS_VERSION, CS_SVN_VERSION);
	fprintf(f,"# Read more: http://streamboard.de.vu/svn/oscam/trunk/Distribution/doc/txt/oscam.server.txt\n\n");

	struct s_reader *rdr;
	LL_ITER itr = ll_iter_create(configured_readers);
	while((rdr = ll_iter_next(&itr))) {
		if ( rdr->label[0]) {
			int32_t isphysical = (rdr->typ & R_IS_NETWORK)?0:1;
			char *ctyp = reader_get_type_desc(rdr, 0);

			fprintf(f,"[reader]\n");

			fprintf_conf(f, "label", "%s\n", rdr->label);

#ifdef WEBIF
			if (rdr->description || cfg.http_full_cfg)
				fprintf_conf(f, "description", "%s\n", rdr->description?rdr->description:"");
#endif

			if (rdr->enable == 0 || cfg.http_full_cfg)
				fprintf_conf(f, "enable", "%d\n", rdr->enable);

			fprintf_conf(f, "protocol", "%s\n", ctyp);
			fprintf_conf(f, "device", "%s", rdr->device);

			if ((rdr->r_port || cfg.http_full_cfg) && !isphysical)
				fprintf(f, ",%d", rdr->r_port);
			if ((rdr->l_port || cfg.http_full_cfg) && !isphysical && strncmp(ctyp, "cccam", 5))
				fprintf(f, ",%d", rdr->l_port);
			fprintf(f, "\n");

#ifdef WITH_LIBUSB
			if (!(rdr->typ & R_IS_NETWORK))
				if (rdr->device_endpoint || cfg.http_full_cfg)
					fprintf_conf(f, "device_out_endpoint", "0x%2X\n", rdr->device_endpoint);
#endif

			if (rdr->ncd_key[0] || rdr->ncd_key[13] || cfg.http_full_cfg) {
				fprintf_conf_n(f, "key");
				if(rdr->ncd_key[0] || rdr->ncd_key[13]){
					for (j = 0; j < 14; j++) {
						fprintf(f, "%02X", rdr->ncd_key[j]);
					}
				}
				fprintf(f, "\n");
			}

			if ((rdr->r_usr[0] || cfg.http_full_cfg) && !isphysical)
				fprintf_conf(f, "user", "%s\n", rdr->r_usr);

			if (strlen(rdr->r_pwd) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "password", "%s\n", rdr->r_pwd);

			if(strcmp(rdr->pincode, "none") || cfg.http_full_cfg)
				fprintf_conf(f, "pincode", "%s\n", rdr->pincode);

			if ((rdr->emmfile || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "readnano", "%s\n", rdr->emmfile?rdr->emmfile:"");

			value = mk_t_service((uint64_t)rdr->sidtabok, (uint64_t)rdr->sidtabno);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "services", "%s\n", value);
			free_mk_t(value);

			if (((rdr->typ != R_CCCAM && rdr->tcp_ito != DEFAULT_INACTIVITYTIMEOUT) || (rdr->typ == R_CCCAM && rdr->tcp_ito != 30) || cfg.http_full_cfg) && !isphysical)
				fprintf_conf(f, "inactivitytimeout", "%d\n", rdr->tcp_ito);

			if ((rdr->resetcycle != 0 || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "resetcycle", "%d\n", rdr->resetcycle);

			if ((rdr->tcp_rto != DEFAULT_TCP_RECONNECT_TIMEOUT || cfg.http_full_cfg) && !isphysical)
				fprintf_conf(f, "reconnecttimeout", "%d\n", rdr->tcp_rto);

			if ((rdr->ncd_disable_server_filt || cfg.http_full_cfg) && rdr->typ == R_NEWCAMD)
				fprintf_conf(f, "disableserverfilter", "%d\n", rdr->ncd_disable_server_filt);

			if ((rdr->smargopatch || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "smargopatch", "%d\n", rdr->smargopatch);

			if ((rdr->sc8in1_dtrrts_patch || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "sc8in1_dtrrts_patch", "%d\n", rdr->sc8in1_dtrrts_patch);

			if (rdr->fallback || cfg.http_full_cfg)
				fprintf_conf(f, "fallback", "%d\n", rdr->fallback);

#ifdef CS_CACHEEX
			if (rdr->cacheex || cfg.http_full_cfg)
				fprintf_conf(f, "cacheex", "%d\n", rdr->cacheex);

			if (rdr->cacheex_maxhop || cfg.http_full_cfg)
				fprintf_conf(f, "cacheex_maxhop", "%d\n", rdr->cacheex_maxhop);
#endif

#ifdef WITH_COOLAPI
			if (rdr->cool_timeout_init || cfg.http_full_cfg)
				fprintf_conf(f, "cool_timeout_init", "%d\n", rdr->cool_timeout_init);
			if (rdr->cool_timeout_after_init || cfg.http_full_cfg)
				fprintf_conf(f, "cool_timeout_after_init", "%d\n", rdr->cool_timeout_after_init);
#endif
			if (rdr->log_port || cfg.http_full_cfg)
				fprintf_conf(f, "logport", "%d\n", rdr->log_port);

			value = mk_t_caidtab(&rdr->ctab);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "caid", "%s\n", value);
			free_mk_t(value);

			if (rdr->boxid && isphysical)
				fprintf_conf(f, "boxid", "%08X\n", rdr->boxid);
			else if (cfg.http_full_cfg && isphysical)
				fprintf_conf(f, "boxid", "\n");

			if((rdr->fix_9993 || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "fix9993", "%d\n", rdr->fix_9993);

			// rsakey
			int32_t len = check_filled(rdr->rsa_mod, 120);
			if (len > 0 && isphysical) {
				if(len > 64) len = 120;
				else len = 64;
				char tmp[len*2+1];
				fprintf_conf(f, "rsakey", "%s\n", cs_hexdump(0, rdr->rsa_mod, len, tmp, sizeof(tmp)));
			} else if(cfg.http_full_cfg && isphysical)
				fprintf_conf(f, "rsakey", "\n");

			if (rdr->ins7E[0x1A] && isphysical) {
				char tmp[0x1A*2+1];
				fprintf_conf(f, "ins7e", "%s\n", cs_hexdump(0, rdr->ins7E, 0x1A, tmp, sizeof(tmp)));
			} else if (cfg.http_full_cfg && isphysical)
				fprintf_conf(f, "ins7e", "\n");

			if (rdr->ins7E11[0x01] && isphysical) {
				char tmp[0x01*2+1];
				fprintf_conf(f, "ins7e11", "%s\n", cs_hexdump(0, rdr->ins7E11, 0x01, tmp, sizeof(tmp)));
			} else if (cfg.http_full_cfg && isphysical)
				fprintf_conf(f, "ins7e11", "\n");

			if ((rdr->force_irdeto || cfg.http_full_cfg) && isphysical) {
				fprintf_conf(f, "force_irdeto", "%d\n", rdr->force_irdeto);
			}

			len = check_filled(rdr->nagra_boxkey, 8);
			if ((len > 0 || cfg.http_full_cfg) && isphysical){
				char tmp[17];
				fprintf_conf(f, "boxkey", "%s\n", len>0?cs_hexdump(0, rdr->nagra_boxkey, 8, tmp, sizeof(tmp)):"");
			}

			if ((rdr->atr[0] || cfg.http_full_cfg) && isphysical) {
				fprintf_conf_n(f, "atr");
				if(rdr->atr[0]){
					for (j=0; j < rdr->atrlen/2; j++) {
						fprintf(f, "%02X", rdr->atr[j]);
					}
				}
				fprintf(f, "\n");
			}

			value = mk_t_ecmwhitelist(rdr->ecmWhitelist);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "ecmwhitelist", "%s\n", value);
			free_mk_t(value);

			if (isphysical) {
				if (rdr->detect&0x80)
					fprintf_conf(f, "detect", "!%s\n", RDR_CD_TXT[rdr->detect&0x7f]);
				else
					fprintf_conf(f, "detect", "%s\n", RDR_CD_TXT[rdr->detect&0x7f]);
			}

			if ((rdr->nagra_read || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "nagra_read", "%d\n", rdr->nagra_read);

			if ((rdr->mhz || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "mhz", "%d\n", rdr->mhz);

			if ((rdr->cardmhz || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "cardmhz", "%d\n", rdr->cardmhz);

#ifdef WITH_AZBOX
			if ((rdr->mode != -1 || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "mode", "%d\n", rdr->mode);
#endif

			value = mk_t_ftab(&rdr->ftab);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "ident", "%s\n", value);
			free_mk_t(value);

			//Todo: write reader class

			value = mk_t_ftab(&rdr->fchid);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "chid", "%s\n", value);
			free_mk_t(value);

			value = mk_t_cltab(&rdr->cltab);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "class", "%s\n", value);
			free_mk_t(value);

			value = mk_t_aeskeys(rdr);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "aeskeys", "%s\n", value);
			free_mk_t(value);

			value = mk_t_group(rdr->grp);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "group", "%s\n", value);
			free_mk_t(value);

			if (rdr->cachemm || cfg.http_full_cfg)
				fprintf_conf(f, "emmcache", "%d,%d,%d\n", rdr->cachemm, rdr->rewritemm, rdr->logemm);

			if ((rdr->blockemm & EMM_UNKNOWN) || cfg.http_full_cfg)
				fprintf_conf(f, "blockemm-unknown", "%d\n", (rdr->blockemm & EMM_UNKNOWN) ? 1: 0);

			if ((rdr->blockemm & EMM_UNIQUE) || cfg.http_full_cfg)
				fprintf_conf(f, "blockemm-u", "%d\n", (rdr->blockemm & EMM_UNIQUE) ? 1: 0);

			if ((rdr->blockemm & EMM_SHARED) || cfg.http_full_cfg)
				fprintf_conf(f, "blockemm-s", "%d\n", (rdr->blockemm & EMM_SHARED) ? 1: 0);

			if ((rdr->blockemm & EMM_GLOBAL) || cfg.http_full_cfg)
				fprintf_conf(f, "blockemm-g", "%d\n", (rdr->blockemm & EMM_GLOBAL) ? 1: 0);

			if ((rdr->saveemm & EMM_UNKNOWN) || cfg.http_full_cfg)
				fprintf_conf(f, "saveemm-unknown", "%d\n", (rdr->saveemm & EMM_UNKNOWN) ? 1: 0);

			if ((rdr->saveemm & EMM_UNIQUE) || cfg.http_full_cfg)
				fprintf_conf(f, "saveemm-u", "%d\n", (rdr->saveemm & EMM_UNIQUE) ? 1: 0);

			if ((rdr->saveemm & EMM_SHARED) || cfg.http_full_cfg)
				fprintf_conf(f, "saveemm-s", "%d\n", (rdr->saveemm & EMM_SHARED) ? 1: 0);

			if ((rdr->saveemm & EMM_GLOBAL) || cfg.http_full_cfg)
				fprintf_conf(f, "saveemm-g", "%d\n", (rdr->saveemm & EMM_GLOBAL) ? 1: 0);

			value = mk_t_emmbylen(rdr);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "blockemm-bylen", "%s\n", value);
			free_mk_t(value);

#ifdef WITH_LB
			if (rdr->lb_weight != 100 || cfg.http_full_cfg)
				fprintf_conf(f, "lb_weight", "%d\n", rdr->lb_weight);
#endif

			//savenano
			value = mk_t_nano(rdr, 0x02);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "savenano", "%s\n", value);
			free_mk_t(value);

			//blocknano
			value = mk_t_nano(rdr, 0x01);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "blocknano", "%s\n", value);
			free_mk_t(value);

			if (rdr->dropbadcws)
				fprintf_conf(f, "dropbadcws", "%d\n", rdr->dropbadcws);

            if (rdr->disablecrccws)
                fprintf_conf(f, "disablecrccws", "%d\n", rdr->disablecrccws);

			if (rdr->use_gpio)
				fprintf_conf(f, "use_gpio", "%d\n", rdr->use_gpio);

#ifdef MODULE_CCCAM
			if (rdr->typ == R_CCCAM) {
				if (rdr->cc_version[0] || cfg.http_full_cfg)
					fprintf_conf(f, "cccversion", "%s\n", rdr->cc_version);

				if (rdr->cc_maxhop != DEFAULT_CC_MAXHOP || cfg.http_full_cfg)
					fprintf_conf(f, "cccmaxhops", "%d\n", rdr->cc_maxhop);

				if (rdr->cc_mindown > 0 || cfg.http_full_cfg)
					fprintf_conf(f, "cccmindown", "%d\n", rdr->cc_mindown);

				if (rdr->cc_want_emu || cfg.http_full_cfg)
					fprintf_conf(f, "cccwantemu", "%d\n", rdr->cc_want_emu);

				if (rdr->cc_keepalive != DEFAULT_CC_KEEPALIVE || cfg.http_full_cfg)
					fprintf_conf(f, "ccckeepalive", "%d\n", rdr->cc_keepalive);

				if (rdr->cc_reshare != DEFAULT_CC_RESHARE || cfg.http_full_cfg)
					fprintf_conf(f, "cccreshare", "%d\n", rdr->cc_reshare);

				if (rdr->cc_reconnect != DEFAULT_CC_RECONNECT || cfg.http_full_cfg)
					fprintf_conf(f, "cccreconnect", "%d\n", rdr->cc_reconnect);
			}
			else if (rdr->cc_hop > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "ccchop", "%d\n", rdr->cc_hop);
#endif

#ifdef MODULE_PANDORA
			if (rdr->typ == R_PANDORA)
			{
				if (rdr->pand_send_ecm || cfg.http_full_cfg)
					fprintf_conf(f, "pand_send_ecm", "%d\n", rdr->pand_send_ecm);
			}
#endif

			if ((rdr->deprecated || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "deprecated", "%d\n", rdr->deprecated);

			if (rdr->audisabled || cfg.http_full_cfg)
				fprintf_conf(f, "audisabled", "%d\n", rdr->audisabled);

			if (rdr->auprovid)
				fprintf_conf(f, "auprovid", "%06X\n", rdr->auprovid);
			else if (cfg.http_full_cfg)
				fprintf_conf(f, "auprovid", "\n");

			if ((rdr->ndsversion || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "ndsversion", "%d\n", rdr->ndsversion);

			if ((rdr->ratelimitecm || cfg.http_full_cfg) && isphysical) {
				fprintf_conf(f, "ratelimitecm", "%d\n", rdr->ratelimitecm);
				fprintf_conf(f, "ratelimitseconds", "%d\n", rdr->ratelimitseconds);
			}

			if ((rdr->cooldown[0] || cfg.http_full_cfg) && isphysical) {
				fprintf_conf(f, "cooldown", "%d,%d\n", rdr->cooldown[0], rdr->cooldown[1]);
			}

			fprintf(f, "\n");
		}
	}
	fclose(f);

	return(safe_overwrite_with_bak(destfile, tmpfile, bakfile, 0));
}



#define write_conf(CONFIG_VAR, text) \
	fprintf(fp, "%-27s %s\n", text ":", config_##CONFIG_VAR() ? "yes" : "no")

#define write_readerconf(CONFIG_VAR, text) \
	fprintf(fp, "%-27s %s\n", text ":", config_##CONFIG_VAR() ? "yes" : "no - no EMM support!")

void write_versionfile(void) {
#if defined(__CYGWIN__)
	return;
#endif
	struct tm st;
	char targetfile[256];
	snprintf(targetfile, sizeof(targetfile) - 1, "%s%s", get_tmp_dir(), "/oscam.version");
	targetfile[sizeof(targetfile) - 1] = 0;
	FILE *fp = fopen(targetfile, "w");
	if (!fp) {
		cs_log("Cannot open %s (errno=%d %s)", targetfile, errno, strerror(errno));
		return;
	}

	time_t now = time(NULL);
	localtime_r(&now, &st);

	fprintf(fp, "Unix starttime: %ld\n", (long)now);
	fprintf(fp, "Starttime:      %02d.%02d.%04d", st.tm_mday, st.tm_mon + 1, st.tm_year + 1900);
	fprintf(fp, " %02d:%02d:%02d\n", st.tm_hour, st.tm_min, st.tm_sec);
	fprintf(fp, "Version:        %s  Rev. %s\n", CS_VERSION, CS_SVN_VERSION);
	fprintf(fp, "Max PID:        unlimited\n\n\n");
	fprintf(fp, "Active modules:\n");

	write_conf(WEBIF, "Web interface support");
	write_conf(WITH_SSL, "SSL support");
	write_conf(HAVE_DVBAPI, "DVB API support");
	if (config_HAVE_DVBAPI())
		write_conf(WITH_STAPI, "DVB API with STAPI support");
	write_conf(CS_ANTICASC, "Anti-cascading support");
	write_conf(IRDETO_GUESSING, "Irdeto guessing");
	write_conf(WITH_DEBUG, "Debug mode");
	write_conf(MODULE_MONITOR, "Monitor");
	write_conf(WITH_LB, "Loadbalancing support");
	write_conf(LCDSUPPORT, "LCD support");
	write_conf(IPV6SUPPORT, "IPv6 support");
	write_conf(CS_CACHEEX, "Cache exchange support");
	write_conf(MODULE_CAMD33, "camd 3.3x");
	write_conf(MODULE_CAMD35, "camd 3.5 UDP");
	write_conf(MODULE_CAMD35_TCP, "camd 3.5 TCP");
	write_conf(MODULE_NEWCAMD, "newcamd");
	write_conf(MODULE_CCCAM, "CCcam");
	write_conf(MODULE_PANDORA, "Pandora");
	write_conf(MODULE_GBOX, "gbox");
	write_conf(MODULE_RADEGAST, "radegast");
	write_conf(MODULE_SERIAL, "serial");
	write_conf(MODULE_CONSTCW, "constant CW");
	write_conf(WITH_CARDREADER, "Cardreader");
	if (config_WITH_CARDREADER()) {
		write_readerconf(READER_NAGRA, "Nagra");
		write_readerconf(READER_IRDETO, "Irdeto");
		write_readerconf(READER_CONAX, "Conax");
		write_readerconf(READER_CRYPTOWORKS, "Cryptoworks");
		write_readerconf(READER_SECA, "Seca");
		write_readerconf(READER_VIACCESS, "Viaccess");
		write_readerconf(READER_VIDEOGUARD, "NDS Videoguard");
		write_readerconf(READER_DRE, "DRE Crypt");
		write_readerconf(READER_TONGFANG, "TONGFANG");
		write_readerconf(READER_BULCRYPT, "Bulcrypt");
	} else {
		write_readerconf(WITH_CARDREADER, "Reader Support");
	}
	fclose(fp);
}
#undef write_conf

int32_t init_free_userdb(struct s_auth *ptr) {
	int32_t nro;
	for (nro = 0; ptr; nro++) {
		struct s_auth *ptr_next;
		ptr_next = ptr->next;
		ll_destroy(ptr->aureader_list);
		ptr->next = NULL;
		add_garbage(ptr);
		ptr = ptr_next;
	}
	cs_log("userdb %d accounts freed", nro);

	return nro;
}

struct s_auth *init_userdb(void)
{
	struct s_auth *authptr = NULL;
	int32_t tag = 0, nr = 0, expired = 0, disabled = 0;
	//int32_t first=1;
	FILE *fp;
	char *value, *token;
	struct s_auth *account = NULL;
	struct s_auth *probe = NULL;
	if(!cs_malloc(&token, MAXLINESIZE, -1)) return authptr;

	snprintf(token, MAXLINESIZE, "%s%s", cs_confdir, cs_user);
	if (!(fp = fopen(token, "r"))) {
		cs_log("Cannot open file \"%s\" (errno=%d %s)", token, errno, strerror(errno));
		free(token);
		return authptr;
	}

	while (fgets(token, MAXLINESIZE, fp)) {
		int32_t i, l;
		void *ptr;

		if ((l=strlen(trim(token))) < 3)
			continue;

		if ((token[0] == '[') && (token[l-1] == ']')) {
			token[l - 1] = 0;
			tag = (!strcmp("account", strtolower(token + 1)));

			if(!cs_malloc(&ptr, sizeof(struct s_auth), -1)){
				free(token);
				return authptr;
			}
			if (account)
				account->next = ptr;
			else
				authptr = ptr;

			account = ptr;
			account->allowedtimeframe[0] = 0;
			account->allowedtimeframe[1] = 0;
			account->aureader_list = NULL;
			account->monlvl = cfg.mon_level;
			account->tosleep = cfg.tosleep;
			account->c35_suppresscmd08 = cfg.c35_suppresscmd08;
			account->ncd_keepalive = cfg.ncd_keepalive;
			account->firstlogin = 0;
#ifdef MODULE_CCCAM
			account->cccmaxhops = DEFAULT_CC_MAXHOP;
			account->cccreshare = DEFAULT_CC_RESHARE; // default: use global cfg
			account->cccignorereshare = DEFAULT_CC_IGNRSHR; // default: use global cfg
			account->cccstealth = DEFAULT_CC_STEALTH; // default: use global cfg
#endif
#ifdef CS_ANTICASC
			account->ac_users   = DEFAULT_AC_USERS;   // use ac_users global value
			account->ac_penalty = DEFAULT_AC_PENALTY; // use ac_penalty global value
#endif
			for (i = 1; i < CS_MAXCAIDTAB; account->ctab.mask[i++] = 0xffff);
			for (i = 1; i < CS_MAXTUNTAB; account->ttab.bt_srvid[i++] = 0x0000);
			nr++;

			continue;
		}

		if (!tag)
			continue;

		if (!(value=strchr(token, '=')))
			continue;

		*value++ = '\0';

		// check for duplicate useraccounts and make the name unique
		if (!strcmp(trim(strtolower(token)), "user")) {
			for(probe = authptr; probe; probe = probe->next){
				if (!strcmp(probe->usr, trim(value))){
					fprintf(stderr, "Warning: duplicate account '%s'\n", value);
					strncat(value, "_x", sizeof(probe->usr) - strlen(value) - 1);
				}
			}
		}

		chk_account(trim(strtolower(token)), trim(value), account);
	}
	free(token);
	fclose(fp);

	for(account = authptr; account; account = account->next){
		if(account->expirationdate && account->expirationdate < time(NULL))
			++expired;

		if(account->disabled)
			++disabled;
	}

	cs_log("userdb reloaded: %d accounts loaded, %d expired, %d disabled", nr, expired, disabled);
	return authptr;
}

void free_sidtab(struct s_sidtab *ptr)
{
		if (!ptr) return;
		add_garbage(ptr->caid); //no need to check on NULL first, freeing NULL doesnt do anything
		add_garbage(ptr->provid);
		add_garbage(ptr->srvid);
		add_garbage(ptr);
}

static void chk_entry4sidtab(char *value, struct s_sidtab *sidtab, int32_t what)
{
  int32_t i, b;
  char *ptr, *saveptr1 = NULL;
  uint16_t *slist=(uint16_t *) 0;
  uint32_t *llist=(uint32_t *) 0;
  uint32_t caid;
  char buf[strlen(value) + 1];
  cs_strncpy(buf, value, sizeof(buf));
  b=(what==1) ? sizeof(uint32_t) : sizeof(uint16_t);
  for (i=0, ptr=strtok_r(value, ",", &saveptr1); ptr; ptr=strtok_r(NULL, ",", &saveptr1))
  {
    caid=a2i(ptr, b);
    if (!errno) i++;
  }
  //if (!i) return(0);
  if (b==sizeof(uint16_t)){
    if(!cs_malloc(&slist, i*sizeof(uint16_t), -1)) return;
  } else {
  	if(!cs_malloc(&llist, i*sizeof(uint32_t), -1)) return;
  }
  cs_strncpy(value, buf, sizeof(buf));
  for (i=0, ptr=strtok_r(value, ",", &saveptr1); ptr; ptr=strtok_r(NULL, ",", &saveptr1))
  {
    caid=a2i(ptr, b);
    if (errno) continue;
    if (b==sizeof(uint16_t))
      slist[i++]=(uint16_t) caid;
    else
      llist[i++]=caid;
  }
  switch (what)
  {
    case 0: add_garbage(sidtab->caid);
    		sidtab->caid=slist;
            sidtab->num_caid=i;
            break;
    case 1: add_garbage(sidtab->provid);
    		sidtab->provid=llist;
            sidtab->num_provid=i;
            break;
    case 2: add_garbage(sidtab->srvid);
    		sidtab->srvid=slist;
            sidtab->num_srvid=i;
            break;
  }
}

void chk_sidtab(char *token, char *value, struct s_sidtab *sidtab)
{
  if (!strcmp(token, "caid")) { chk_entry4sidtab(value, sidtab, 0); return; }
  if (!strcmp(token, "provid")) { chk_entry4sidtab(value, sidtab, 1); return; }
  if (!strcmp(token, "ident")) { chk_entry4sidtab(value, sidtab, 1); return; }
  if (!strcmp(token, "srvid")) { chk_entry4sidtab(value, sidtab, 2); return; }
  if (token[0] != '#')
    fprintf(stderr, "Warning: keyword '%s' in sidtab section not recognized\n",token);
}

void init_free_sidtab(void) {
		struct s_sidtab *nxt, *ptr = cfg.sidtab;
		while (ptr) {
				nxt = ptr->next;
				free_sidtab(ptr);
				ptr = nxt;
		}
		cfg.sidtab = NULL;
		++cfg_sidtab_generation;
}

#ifdef DEBUG_SIDTAB
static void show_sidtab(struct s_sidtab *sidtab)
{
  for (; sidtab; sidtab=sidtab->next)
  {
    int32_t i;
    char buf[1024];
    char *saveptr = buf;
    cs_log("label=%s", sidtab->label);
    snprintf(buf, sizeof(buf), "caid(%d)=", sidtab->num_caid);
    for (i=0; i<sidtab->num_caid; i++)
      snprintf(buf+strlen(buf), 1024-(buf-saveptr), "%04X ", sidtab->caid[i]);
    cs_log("%s", buf);
    snprintf(buf, sizeof(buf), "provider(%d)=", sidtab->num_provid);
    for (i=0; i<sidtab->num_provid; i++)
      snprintf(buf+strlen(buf), 1024-(buf-saveptr), "%08X ", sidtab->provid[i]);
    cs_log("%s", buf);
    snprintf(buf, sizeof(buf), "services(%d)=", sidtab->num_srvid);
    for (i=0; i<sidtab->num_srvid; i++)
      snprintf(buf+strlen(buf), 1024-(buf-saveptr), "%04X ", sidtab->srvid[i]);
    cs_log("%s", buf);
  }
}
#endif

int32_t init_sidtab(void) {
	int32_t nr, nro, nrr;
	FILE *fp;
	char *value, *token;
	if(!cs_malloc(&token, MAXLINESIZE, -1)) return 1;
	struct s_sidtab *ptr;
	struct s_sidtab *sidtab=(struct s_sidtab *)0;

	snprintf(token, MAXLINESIZE, "%s%s", cs_confdir, cs_sidt);
	if (!(fp=fopen(token, "r")))
	{
		cs_log("Cannot open file \"%s\" (errno=%d %s)", token, errno, strerror(errno));
		free(token);
		return(1);
	}
	for (nro=0, ptr=cfg.sidtab; ptr; nro++)
	{
		struct s_sidtab *ptr_next;
		ptr_next=ptr->next;
		free_sidtab(ptr);
		ptr=ptr_next;
	}
	nr = 0; nrr = 0;
	while (fgets(token, MAXLINESIZE, fp))
	{
		int32_t l;
		void *ptr;
		if ((l=strlen(trim(token)))<3) continue;
		if ((token[0]=='[') && (token[l-1]==']'))
		{
			token[l-1]=0;
			if(nr > MAX_SIDBITS){
				fprintf(stderr, "Warning: Service No.%d - '%s' ignored. Max allowed Services %d\n", nr, strtolower(token+1), MAX_SIDBITS);
				nr++;
				nrr++;
			} else {
				if (!cs_malloc(&ptr, sizeof(struct s_sidtab), -1)) {
					free(token);
					return(1);
				}
				if (sidtab)
					sidtab->next=ptr;
				else
					cfg.sidtab=ptr;
				sidtab=ptr;
				nr++;
				cs_strncpy(sidtab->label, strtolower(token+1), sizeof(sidtab->label));
				continue;
			}
		}
		if (!sidtab) continue;
		if (!(value=strchr(token, '='))) continue;
		*value++='\0';
		chk_sidtab(trim(strtolower(token)), trim(strtolower(value)), sidtab);
	}
	free(token);
	fclose(fp);

#ifdef DEBUG_SIDTAB
	show_sidtab(cfg.sidtab);
#endif
	++cfg_sidtab_generation;
	cs_log("services reloaded: %d services freed, %d services loaded, rejected %d", nro, nr, nrr);
	return(0);
}

//Todo #ifdef CCCAM
int32_t init_provid(void) {
	int32_t nr;
	FILE *fp;
	char *payload, *saveptr1 = NULL, *token;
	if(!cs_malloc(&token, MAXLINESIZE, -1)) return 0;
	static struct s_provid *provid=(struct s_provid *)0;
	snprintf(token, MAXLINESIZE, "%s%s", cs_confdir, cs_provid);

	if (!(fp=fopen(token, "r"))) {
		cs_log("can't open file \"%s\" (err=%d %s), no provids's loaded", token, errno, strerror(errno));
		free(token);
		return(0);
	}
	nr=0;
	while (fgets(token, MAXLINESIZE, fp)) {

		int32_t l;
		void *ptr;
		char *tmp, *providasc;
		tmp = trim(token);

		if (tmp[0] == '#') continue;
		if ((l = strlen(tmp)) < 11) continue;
		if (!(payload = strchr(token, '|'))) continue;
		if (!(providasc = strchr(token, ':'))) continue;

		*payload++ = '\0';

		if (!cs_malloc(&ptr, sizeof(struct s_provid), -1)) {
			free(token);
			fclose(fp);
			return(1);
		}
		if (provid)
			provid->next = ptr;
		else
			cfg.provid = ptr;

		provid = ptr;

		int32_t i;
		char *ptr1;
		for (i = 0, ptr1 = strtok_r(payload, "|", &saveptr1); ptr1; ptr1 = strtok_r(NULL, "|", &saveptr1), i++){
			switch(i){
			case 0:
				cs_strncpy(provid->prov, trim(ptr1), sizeof(provid->prov));
				break;
			case 1:
				cs_strncpy(provid->sat, trim(ptr1), sizeof(provid->sat));
				break;
			case 2:
				cs_strncpy(provid->lang, trim(ptr1), sizeof(provid->lang));
				break;
			}
		}

		*providasc++ = '\0';
		provid->provid = a2i(providasc, 3);
		provid->caid = a2i(token, 3);
		nr++;
	}
	free(token);
	fclose(fp);
	if (nr>0)
		cs_log("%d provid's loaded", nr);
	else{
		cs_log("oscam.provid loading failed, wrong format?");
	}
	return(0);
}

int32_t init_srvid(void)
{
	int32_t nr = 0, i;
	FILE *fp;
	char *payload, *tmp, *saveptr1 = NULL, *token;
	if(!cs_malloc(&token, MAXLINESIZE, -1)) return 0;
	struct s_srvid *srvid=NULL, *new_cfg_srvid[16], *last_srvid[16];
	snprintf(token, MAXLINESIZE, "%s%s", cs_confdir, cs_srid);
	// A cache for strings within srvids. A checksum is calculated which is the start point in the array (some kind of primitive hash algo).
	// From this point, a sequential search is done. This greatly reduces the amount of string comparisons.
	char **stringcache[1024];
	int32_t allocated[1024] = { 0 };
	int32_t used[1024] = { 0 };
	struct timeb ts, te;
  cs_ftime(&ts);

	memset(last_srvid, 0, sizeof(last_srvid));
	memset(new_cfg_srvid, 0, sizeof(new_cfg_srvid));

	if (!(fp=fopen(token, "r"))) {
		cs_log("can't open file \"%s\" (err=%d %s), no service-id's loaded", token, errno, strerror(errno));
		free(token);
		return(0);
	}

	while (fgets(token, MAXLINESIZE, fp)) {
		int32_t l, j, len=0, len2, srvidtmp;
		uint32_t pos;
		char *srvidasc;
		tmp = trim(token);

		if (tmp[0] == '#') continue;
		if ((l=strlen(tmp)) < 6) continue;
		if (!(srvidasc = strchr(token, ':'))) continue;
		if (!(payload=strchr(token, '|'))) continue;
		*payload++ = '\0';

		if (!cs_malloc(&srvid, sizeof(struct s_srvid), -1)){
			free(token);
			fclose(fp);
			return(1);
		}

		char tmptxt[128];

		int32_t offset[4] = { -1, -1, -1, -1 };
		char *ptr1, *searchptr[4] = { NULL, NULL, NULL, NULL };
		char **ptrs[4] = { &srvid->prov, &srvid->name, &srvid->type, &srvid->desc };

		for (i = 0, ptr1 = strtok_r(payload, "|", &saveptr1); ptr1 && (i < 4) ; ptr1 = strtok_r(NULL, "|", &saveptr1), ++i){
			// check if string is in cache
			len2 = strlen(ptr1);
			pos = 0;
			for(j = 0; j < len2; ++j) pos += (uint8_t)ptr1[j];
			pos = pos%1024;
			for(j = 0; j < used[pos]; ++j){
				if (!strcmp(stringcache[pos][j], ptr1)){
					searchptr[i]=stringcache[pos][j];
					break;
				}
			}
			if (searchptr[i]) continue;

			offset[i]=len;
			cs_strncpy(tmptxt+len, trim(ptr1), sizeof(tmptxt)-len);
			len+=strlen(ptr1)+1;
		}

		char *tmpptr = NULL;
		if (len > 0 && !cs_malloc(&tmpptr, len, 0))
			continue;

		srvid->data=tmpptr;
		memcpy(tmpptr, tmptxt, len);

		for (i=0;i<4;i++) {
			if (searchptr[i]) {
				*ptrs[i] = searchptr[i];
				continue;
			}
			if (offset[i]>-1){
				*ptrs[i] = tmpptr + offset[i];
				// store string in stringcache
				tmp = *ptrs[i];
				len2 = strlen(tmp);
				pos = 0;
				for(j = 0; j < len2; ++j) pos += (uint8_t)tmp[j];
				pos = pos%1024;
				if(used[pos] >= allocated[pos]){
					if(allocated[pos] == 0) cs_malloc(&stringcache[pos], 16 * sizeof(char*), SIGINT);
					else cs_realloc(&stringcache[pos], (allocated[pos] + 16) * sizeof(char*), SIGINT);
					allocated[pos] += 16;
				}
				stringcache[pos][used[pos]] = tmp;
				used[pos] += 1;
			}
		}

		*srvidasc++ = '\0';
		srvidtmp = dyn_word_atob(srvidasc) & 0xFFFF;
		//printf("srvid %s - %d\n",srvidasc,srvid->srvid );

		if (srvidtmp<0) {
			free(tmpptr);
			free(srvid);
			continue;
		} else srvid->srvid = srvidtmp;

		srvid->ncaid = 0;
		for (i = 0, ptr1 = strtok_r(token, ",", &saveptr1); (ptr1) && (i < 10) ; ptr1 = strtok_r(NULL, ",", &saveptr1), i++){
			srvid->caid[i] = dyn_word_atob(ptr1);
			srvid->ncaid = i+1;
			//cs_debug_mask(D_CLIENT, "ld caid: %04X srvid: %04X Prov: %s Chan: %s",srvid->caid[i],srvid->srvid,srvid->prov,srvid->name);
		}
		nr++;

		if (new_cfg_srvid[srvid->srvid>>12])
			last_srvid[srvid->srvid>>12]->next = srvid;
		else
			new_cfg_srvid[srvid->srvid>>12] = srvid;

		last_srvid[srvid->srvid>>12] = srvid;
	}
	for(i = 0; i < 1024; ++i){
		if(allocated[i] > 0) free(stringcache[i]);
	}
	free(token);

	cs_ftime(&te);
	int32_t time = 1000*(te.time-ts.time)+te.millitm-ts.millitm;

	fclose(fp);
	if (nr > 0) {
		cs_log("%d service-id's loaded in %dms", nr, time);
		if (nr > 2000) {
			cs_log("WARNING: You risk high CPU load and high ECM times with more than 2000 service-id�s!");
			cs_log("HINT: --> use optimized lists from http://streamboard.de.vu/wiki/index.php/Srvid");
		}
	} else {
		cs_log("oscam.srvid loading failed, old format");
	}

	//this allows reloading of srvids, so cleanup of old data is needed:
	memcpy(last_srvid, cfg.srvid, sizeof(last_srvid));	//old data
	memcpy(cfg.srvid, new_cfg_srvid, sizeof(last_srvid));	//assign after loading, so everything is in memory

	struct s_client *cl;
	for (cl=first_client->next; cl ; cl=cl->next)
		cl->last_srvidptr=NULL;

	struct s_srvid *ptr;
	for (i=0; i<16; i++) {
		while (last_srvid[i]) { //cleanup old data:
			ptr = last_srvid[i]->next;
			free(last_srvid[i]->data);
			free(last_srvid[i]);
			last_srvid[i] = ptr;
		}
	}

	return(0);
}

int32_t init_tierid(void)
{
	int32_t nr;
	FILE *fp;
	char *payload, *saveptr1 = NULL, *token;
	if(!cs_malloc(&token, MAXLINESIZE, -1)) return 0;
	static struct s_tierid *tierid=NULL, *new_cfg_tierid=NULL;
	snprintf(token, MAXLINESIZE, "%s%s", cs_confdir, cs_trid);

	if (!(fp=fopen(token, "r"))) {
		cs_log("can't open file \"%s\" (err=%d %s), no tier-id's loaded", token, errno, strerror(errno));
		free(token);
		return(0);
	}

	nr=0;
	while (fgets(token, MAXLINESIZE, fp)) {

		int32_t l;
		void *ptr;
		char *tmp, *tieridasc;
		tmp = trim(token);

		if (tmp[0] == '#') continue;
		if ((l=strlen(tmp)) < 6) continue;
		if (!(payload=strchr(token, '|'))) continue;
		if (!(tieridasc = strchr(token, ':'))) continue;
		*payload++ = '\0';

		if (!cs_malloc(&ptr,sizeof(struct s_tierid), -1)){
			free(token);
			fclose(fp);
			return(1);
		}
		if (tierid)
			tierid->next = ptr;
		else
			new_cfg_tierid = ptr;

		tierid = ptr;

		int32_t i;
		char *ptr1 = strtok_r(payload, "|", &saveptr1);
		if (ptr1)
			cs_strncpy(tierid->name, trim(ptr1), sizeof(tierid->name));

		*tieridasc++ = '\0';
		tierid->tierid = dyn_word_atob(tieridasc);
		//printf("tierid %s - %d\n",tieridasc,tierid->tierid );

		tierid->ncaid = 0;
		for (i = 0, ptr1 = strtok_r(token, ",", &saveptr1); (ptr1) && (i < 10) ; ptr1 = strtok_r(NULL, ",", &saveptr1), i++){
			tierid->caid[i] = dyn_word_atob(ptr1);
			tierid->ncaid = i+1;
			// cs_log("ld caid: %04X tierid: %04X name: %s",tierid->caid[i],tierid->tierid,tierid->name);
		}
		nr++;
	}
	free(token);
	fclose(fp);
	if (nr>0)
		cs_log("%d tier-id's loaded", nr);
	else{
		cs_log("%s loading failed", cs_trid);
	}

	//reload function:
	tierid = cfg.tierid;
	cfg.tierid = new_cfg_tierid;
	struct s_tierid *ptr;
	while (tierid) {
		ptr = tierid->next;
		free(tierid);
		tierid = ptr;
	}

	return(0);
}

void chk_reader(char *token, char *value, struct s_reader *rdr)
{
	int32_t i;
	char *ptr, *ptr2, *ptr3, *saveptr1 = NULL;
	/*
	 *  case sensitive first
	 */
	if (!strcmp(token, "device")) {
		for (i = 0, ptr = strtok_r(value, ",", &saveptr1); (i < 3) && (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++) {
			trim(ptr);
			switch(i) {
				case 0:
					cs_strncpy(rdr->device, ptr, sizeof(rdr->device));
					break;

				case 1:
					rdr->r_port = atoi(ptr);
					break;

				case 2:
					rdr->l_port = atoi(ptr);
					break;
			}
		}
		return;
	}

#ifdef WITH_LIBUSB
	if (!strcmp(token, "device_out_endpoint")) {
		if (strlen(value) > 0) {
			sscanf(value, "0x%2X", &i);
			rdr->device_endpoint = i;
		} else {
			rdr->device_endpoint = 0;
		}
		return;
	}
#endif

	if (!strcmp(token, "key")) {
		if (strlen(value) == 0){
			return;
		} else if (key_atob_l(value, rdr->ncd_key, 28)) {
			fprintf(stderr, "Configuration newcamd: Error in Key\n");
			memset(rdr->ncd_key, 0, sizeof(rdr->ncd_key));
		}
		return;
	}

	if (!strcmp(token, "password")) {
		cs_strncpy(rdr->r_pwd, value, sizeof(rdr->r_pwd));
		return;
	}

	if (!strcmp(token, "user")) {
		cs_strncpy(rdr->r_usr, value, sizeof(rdr->r_usr));
		return;
	}

#ifdef WEBIF
	if (!strcmp(token, "description")) {
		NULLFREE(rdr->description);
		if(strlen(value) > 0 && cs_malloc(&rdr->description, strlen(value)+1, -1)){
			cs_strncpy(rdr->description, value, strlen(value)+1);
		}
		return;
	}
#endif

  if (!strcmp(token, "mg-encrypted")) {
    uchar key[16];
    uchar mac[6];
    char tmp_dbg[13];
    uchar *buf = NULL;
    int32_t len = 0;

    memset(&key, 0, 16);
    memset(&mac, 0, 6);

    for (i = 0, ptr = strtok_r(value, ",", &saveptr1); (i < 2) && (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++) {
      trim(ptr);
      switch(i) {
        case 0:
          len = strlen(ptr) / 2 + (16 - (strlen(ptr) / 2) % 16);
          if(!cs_malloc(&buf,len, -1)) return;
          key_atob_l(ptr, buf, strlen(ptr));
          cs_log("enc %d: %s", len, ptr);
          break;

        case 1:
          key_atob_l(ptr, mac, 12);
          cs_log("mac: %s", ptr);
          break;
      }
    }

    if (!memcmp(mac, "\x00\x00\x00\x00\x00\x00", 6)) {
#if defined(__APPLE__) || defined(__FreeBSD__)
      // no mac address specified so use mac of en0 on local box
      struct ifaddrs *ifs, *current;

      if (getifaddrs(&ifs) == 0)
      {
         for (current = ifs; current != 0; current = current->ifa_next)
         {
            if (current->ifa_addr->sa_family == AF_LINK && strcmp(current->ifa_name, "en0") == 0)
            {
               struct sockaddr_dl *sdl = (struct sockaddr_dl *)current->ifa_addr;
               memcpy(mac, LLADDR(sdl), sdl->sdl_alen);
               break;
            }
         }
         freeifaddrs(ifs);
      }
#elif defined(__SOLARIS__)
			// no mac address specified so use first filled mac
			int32_t j, sock, niccount;
			struct ifreq nicnumber[16];
			struct ifconf ifconf;
			struct arpreq arpreq;

			if ((sock=socket(AF_INET,SOCK_DGRAM,0)) > -1){
				ifconf.ifc_buf = (caddr_t)nicnumber;
				ifconf.ifc_len = sizeof(nicnumber);
				if (!ioctl(sock,SIOCGIFCONF,(char*)&ifconf)){
					niccount = ifconf.ifc_len/(sizeof(struct ifreq));
					for(i = 0; i < niccount, ++i){
						memset(&arpreq, 0, sizeof(arpreq));
						((struct sockaddr_in*)&arpreq.arp_pa)->sin_addr.s_addr = ((struct sockaddr_in*)&nicnumber[i].ifr_addr)->sin_addr.s_addr;
						if (!(ioctl(sock,SIOCGARP,(char*)&arpreq))){
							for (j = 0; j < 6; ++j)
								mac[j] = (unsigned char)arpreq.arp_ha.sa_data[j];
							if(check_filled(mac, 6) > 0) break;
						}
					}
				}
				close(sock);
			}
#else
      // no mac address specified so use mac of eth0 on local box
      int32_t fd = socket(PF_INET, SOCK_STREAM, 0);

      struct ifreq ifreq;
      memset(&ifreq, 0, sizeof(ifreq));
      snprintf(ifreq.ifr_name, sizeof(ifreq.ifr_name), "eth0");

      ioctl(fd, SIOCGIFHWADDR, &ifreq);
      memcpy(mac, ifreq.ifr_ifru.ifru_hwaddr.sa_data, 6);

      close(fd);
#endif
			cs_debug_mask(D_TRACE, "Determined local mac address for mg-encrypted as %s", cs_hexdump(1, mac, 6, tmp_dbg, sizeof(tmp_dbg)));
    }

    // decrypt encrypted mgcamd gbox line
    for (i = 0; i < 6; i++)
      key[i * 2] = mac[i];

    AES_KEY aeskey;
    AES_set_decrypt_key(key, 128, &aeskey);
    for (i = 0; i < len; i+=16)
      AES_decrypt(buf + i,buf + i, &aeskey);

    // parse d-line
    for (i = 0, ptr = strtok_r((char *)buf, " {", &saveptr1); (i < 5) && (ptr); ptr = strtok_r(NULL, " {", &saveptr1), i++) {
      trim(ptr);
      switch(i) {
        case 1:    // hostname
          cs_strncpy(rdr->device, ptr, sizeof(rdr->device));
          break;
        case 2:   // local port
          cfg.gbox_port = atoi(ptr);  // ***WARNING CHANGE OF GLOBAL LISTEN PORT FROM WITHIN READER!!!***
          break;
        case 3:   // remote port
          rdr->r_port = atoi(ptr);
          break;
        case 4:   // password
          cs_strncpy(rdr->r_pwd, ptr, sizeof(rdr->r_pwd));
          break;
      }
    }

    free(buf);
    return;
  }

	//legacy parameter containing account=user,pass
	if (!strcmp(token, "account")) {
		if (strstr(value, ",")) {
			for (i = 0, ptr = strtok_r(value, ",", &saveptr1); (i < 2) && (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++) {
				trim(ptr);
				switch(i) {
					case 0:
						cs_strncpy(rdr->r_usr, ptr, sizeof(rdr->r_usr));
						break;

					case 1:
						cs_strncpy(rdr->r_pwd, ptr, sizeof(rdr->r_pwd));
						break;
				}
			}
		} else {
			cs_strncpy(rdr->r_usr, value, sizeof(rdr->r_usr));
		}
		return;
	}

	if (!strcmp(token, "pincode")) {
		cs_strncpy(rdr->pincode, value, sizeof(rdr->pincode));
		return;
	}

	if (!strcmp(token, "readnano")) {
		NULLFREE(rdr->emmfile);
		if (strlen(value) > 0) {
			if(!cs_malloc(&(rdr->emmfile), strlen(value) + 1, -1)) return;
			memcpy(rdr->emmfile, value, strlen(value) + 1);
		}
		return;
	}

	/*
	 *  case insensitive
	 */
	strtolower(value);

	if (!strcmp(token, "enable")) {
		rdr->enable  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "services")) {
		if(strlen(value) == 0) {
			rdr->sidtabok = 0;
			rdr->sidtabno = 0;
			rdr->changes_since_shareupdate = 1;
			return;
		} else {
			chk_services(value, &rdr->sidtabok, &rdr->sidtabno);
			rdr->changes_since_shareupdate = 1;
			return;
		}
	}

	if (!strcmp(token, "inactivitytimeout")) {
		rdr->tcp_ito  = strToIntVal(value, rdr->typ == R_CCCAM?30:DEFAULT_INACTIVITYTIMEOUT);
		return;
	}

	if (!strcmp(token, "resetcycle")) {
		rdr->resetcycle  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "reconnecttimeout")) {
		rdr->tcp_rto  = strToIntVal(value, DEFAULT_TCP_RECONNECT_TIMEOUT);
		return;
	}

	if (!strcmp(token, "disableserverfilter")) {
		rdr->ncd_disable_server_filt  = strToIntVal(value, 0);
		return;
	}

	//FIXME workaround for Smargo until native mode works
	if (!strcmp(token, "smargopatch")) {
		rdr->smargopatch  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "sc8in1_dtrrts_patch")) {
		rdr->sc8in1_dtrrts_patch  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "label")) {
		int32_t found = 0;
		for(i = 0; i < (int)strlen(value); i++) {
			if (value[i] == ' ') {
				value[i] = '_';
				found++;
			}
		}

		if (found) fprintf(stderr, "Configuration reader: corrected label to %s\n",value);
		cs_strncpy(rdr->label, value, sizeof(rdr->label));
		return;
	}

	if (!strcmp(token, "fallback")) {
		rdr->fallback  = strToIntVal(value, 0);
		return;
	}

#ifdef CS_CACHEEX
	if (!strcmp(token, "cacheex")) {
		rdr->cacheex  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "cacheex_maxhop")) {
		rdr->cacheex_maxhop  = strToIntVal(value, 0);
		return;
	}
#endif

	if (!strcmp(token, "logport")) {
		rdr->log_port  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "caid")) {
		if(strlen(value) == 0) {
			clear_caidtab(&rdr->ctab);
			rdr->changes_since_shareupdate = 1;
			return;
		} else {
			chk_caidtab(value, &rdr->ctab);
			rdr->changes_since_shareupdate = 1;
			return;
		}
	}

  if (!strcmp(token, "boxid")) {
    if(strlen(value) == 0) {
      rdr->boxid = 0;
      return;
    } else {
      rdr->boxid = a2i(value, 4);
      return;
    }
  }

  if (!strcmp(token, "fix9993")) {
    rdr->fix_9993 = strToIntVal(value, 0);
    return;
  }

	if (!strcmp(token, "rsakey")) {
		int32_t len = strlen(value);
		if(len != 128 && len != 240) {
			memset(rdr->rsa_mod, 0, 120);
			return;
		} else {
			if (key_atob_l(value, rdr->rsa_mod, len)) {
				fprintf(stderr, "Configuration reader: Error in rsakey\n");
				memset(rdr->rsa_mod, 0, sizeof(rdr->rsa_mod));
			}
			return;
		}
	}

	if (!strcmp(token, "ins7e")) {
		int32_t len = strlen(value);
		if (len != 0x1A*2 || key_atob_l(value, rdr->ins7E, len)) {
			if (len > 0)
				fprintf(stderr, "Configuration reader: Error in ins7E\n");
			memset(rdr->ins7E, 0, sizeof(rdr->ins7E));
		}
		else
			rdr->ins7E[0x1A] = 1; // found and correct
		return;
	}

	if (!strcmp(token, "ins7e11")) {
		int32_t len = strlen(value);
		if (len != 0x01*2 || key_atob_l(value, rdr->ins7E11, len)) {
			if (len > 0)
				fprintf(stderr, "Configuration reader: Error in ins7E11\n");
			memset(rdr->ins7E11, 0, sizeof(rdr->ins7E11));
		}
		else
			rdr->ins7E11[0x01] = 1; // found and correct
		return;
	}

	if (!strcmp(token, "boxkey")) {
		if(strlen(value) != 16 ) {
			memset(rdr->nagra_boxkey, 0, 16);
			return;
		} else {
			if (key_atob_l(value, rdr->nagra_boxkey, 16)) {
				fprintf(stderr, "Configuration reader: Error in boxkey\n");
				memset(rdr->nagra_boxkey, 0, sizeof(rdr->nagra_boxkey));
			}
			return;
		}
	}

	if (!strcmp(token, "force_irdeto")) {
		rdr->force_irdeto  = strToIntVal(value, 0);
		return;
	}


	if ((!strcmp(token, "atr"))) {
		memset(rdr->atr, 0, sizeof(rdr->atr));
		rdr->atrlen = strlen(value);
		if(rdr->atrlen == 0) {
			return;
		} else {
			if(rdr->atrlen > (int32_t)sizeof(rdr->atr) * 2)
				rdr->atrlen = (int32_t)sizeof(rdr->atr) * 2;
			key_atob_l(value, rdr->atr, rdr->atrlen);
			return;
		}
	}

	if (!strcmp(token, "ecmwhitelist")) {
		struct s_ecmWhitelist *tmp, *last;
		struct s_ecmWhitelistIdent *tmpIdent, *lastIdent;
		struct s_ecmWhitelistLen *tmpLen, *lastLen;
		for(tmp = rdr->ecmWhitelist; tmp; tmp=tmp->next){
			for(tmpIdent = tmp->idents; tmpIdent; tmpIdent=tmpIdent->next){
				for(tmpLen = tmpIdent->lengths; tmpLen; tmpLen=tmpLen->next){
					add_garbage(tmpLen);
				}
				add_garbage(tmpIdent);
			}
			add_garbage(tmp);
		}
		rdr->ecmWhitelist = NULL;
		if(strlen(value) > 0){
			char *saveptr1=NULL, *saveptr2 = NULL;
			for (ptr = strtok_r(value, ";", &saveptr1); ptr; ptr = strtok_r(NULL, ";", &saveptr1)) {
				int16_t caid = 0, len;
				uint32_t ident = 0;
				ptr2=strchr(ptr,':');
				if(ptr2 != NULL){
					ptr2[0] = '\0';
					++ptr2;
					ptr3=strchr(ptr,'@');
					if(ptr3 != NULL){
						ptr3[0] = '\0';
						++ptr3;
						ident = (uint32_t)a2i(ptr3, 6);
					}
					caid = (int16_t)dyn_word_atob(ptr);
				} else ptr2 = ptr;
				for (ptr2 = strtok_r(ptr2, ",", &saveptr2); ptr2; ptr2 = strtok_r(NULL, ",", &saveptr2)) {
					len = (int16_t)dyn_word_atob(ptr2);
					last = NULL, tmpIdent = NULL, lastIdent = NULL, tmpLen = NULL, lastLen = NULL;
					for(tmp = rdr->ecmWhitelist; tmp; tmp=tmp->next){
						last = tmp;
						if(tmp->caid == caid){
							for(tmpIdent = tmp->idents; tmpIdent; tmpIdent=tmpIdent->next){
								lastIdent = tmpIdent;
								if(tmpIdent->ident == ident){
									for(tmpLen = tmpIdent->lengths; tmpLen; tmpLen=tmpLen->next){
										lastLen = tmpLen;
										if(tmpLen->len == len) break;
									}
									break;
								}
							}
						}
					}
					if(tmp == NULL){
						if (cs_malloc(&tmp, sizeof(struct s_ecmWhitelist), -1)) {
							tmp->caid = caid;
							tmp->idents = NULL;
							tmp->next = NULL;
							if(last == NULL){
								rdr->ecmWhitelist = tmp;
							} else {
								last->next = tmp;
							}
						}
					}
					if(tmp != NULL && tmpIdent == NULL){
						if (cs_malloc(&tmpIdent, sizeof(struct s_ecmWhitelistIdent), -1)) {
							tmpIdent->ident = ident;
							tmpIdent->lengths = NULL;
							tmpIdent->next = NULL;
							if(lastIdent == NULL){
								tmp->idents = tmpIdent;
							} else {
								lastIdent->next = tmpIdent;
							}
						}
					}
					if(tmp != NULL && tmpIdent != NULL && tmpLen == NULL){
						if (cs_malloc(&tmpLen, sizeof(struct s_ecmWhitelistLen), -1)) {
							tmpLen->len = len;
							tmpLen->next = NULL;
							if(lastLen == NULL){
								tmpIdent->lengths = tmpLen;
							} else {
								lastLen->next = tmpLen;
							}
						}
					}
				}
			}
		}
		return;
	}

	if (!strcmp(token, "detect")) {
		for (i = 0; RDR_CD_TXT[i]; i++) {
			if (!strcmp(value, RDR_CD_TXT[i])) {
				rdr->detect = i;
			}
			else {
				if ((value[0] == '!') && (!strcmp(value+1, RDR_CD_TXT[i])))
					rdr->detect = i|0x80;
			}
		}
		return;
	}

	if (!strcmp(token, "nagra_read")) {
		rdr->nagra_read  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "mhz")) {
		rdr->mhz  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "cardmhz")) {
		rdr->cardmhz  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "protocol")) {

		for (i=0; i<CS_MAX_MOD; i++) {
			if (cardreader[i].desc && strcmp(value, cardreader[i].desc) == 0) {
				rdr->crdr = cardreader[i];
				rdr->crdr.active = 1;
				rdr->typ = cardreader[i].typ; //FIXME
				return;
			}
		}

		if (!strcmp(value, "mp35")) {
			rdr->typ = R_MP35;
			return;
		}

		if (!strcmp(value, "mouse")) {
			rdr->typ = R_MOUSE;
			return;
		}

		if (!strcmp(value, "sc8in1")) {
			rdr->typ = R_SC8in1;
			return;
		}

		if (!strcmp(value, "smartreader")) {
			rdr->typ = R_SMART;
			return;
		}

		if (!strcmp(value, "internal")) {
			rdr->typ = R_INTERNAL;
			return;
		}

#ifdef WITH_PCSC
		if (!strcmp(value, "pcsc")) {
			rdr->typ = R_PCSC;
			return;
		}
#endif

		if (!strcmp(value, "serial")) {
			rdr->typ = R_SERIAL;
			return;
		}

		if (!strcmp(value, "camd35")) {
			rdr->typ = R_CAMD35;
			return;
		}

		if (!strcmp(value, "cs378x")) {
			rdr->typ = R_CS378X;
			return;
		}

		if (!strcmp(value, "cs357x")) {
			rdr->typ = R_CAMD35;
			return;
		}

		if (!strcmp(value, "gbox")) {
			rdr->typ = R_GBOX;
			return;
		}

		if (!strcmp(value, "cccam") || !strcmp(value, "cccam ext")) {
			rdr->typ = R_CCCAM;
			//strcpy(value, "1");
			//chk_caidtab(value, &rdr->ctab);
			//this is a MAJOR hack for auto multiple caid support (not currently working due to ncd table issue)
			return;
		}

		if (!strcmp(value, "constcw")) {
			rdr->typ = R_CONSTCW;
			return;
		}

		if (!strcmp(value, "radegast")) {
			rdr->typ = R_RADEGAST;
			return;
		}

		if (!strcmp(value, "newcamd") || !strcmp(value, "newcamd525")) {
			rdr->typ = R_NEWCAMD;
			rdr->ncd_proto = NCD_525;
			return;
		}

		if (!strcmp(value, "newcamd524")) {
			rdr->typ = R_NEWCAMD;
			rdr->ncd_proto = NCD_524;
			return;
		}

		fprintf(stderr, "WARNING: value '%s' in protocol-line not recognized, assuming MOUSE\n",value);
		rdr->typ = R_MOUSE;
		return;
	}
#ifdef WITH_COOLAPI
	if (!strcmp(token, "cool_timeout_init")) {
		rdr->cool_timeout_init  = strToIntVal(value, 0);
		return;
	}
	if (!strcmp(token, "cool_timeout_after_init")) {
		rdr->cool_timeout_after_init  = strToIntVal(value, 0);
		return;
	}
#endif
	if (!strcmp(token, "ident")) {
		if(strlen(value) == 0) {
			clear_ftab(&rdr->ftab);
			rdr->changes_since_shareupdate = 1;
			return;
		} else {
			chk_ftab(value, &rdr->ftab,"reader",rdr->label,"provid");
			rdr->changes_since_shareupdate = 1;
			return;
		}
	}

	if (!strcmp(token, "class")) {
		chk_cltab(value, &rdr->cltab);
		return;
	}

	if (!strcmp(token, "chid")) {
		chk_ftab(value, &rdr->fchid,"reader",rdr->label,"chid");
		rdr->changes_since_shareupdate = 1;
		return;
	}

	if (!strcmp(token, "group")) {
		rdr->grp = 0;
		for (ptr = strtok_r(value, ",", &saveptr1); ptr; ptr = strtok_r(NULL, ",", &saveptr1)) {
			int32_t g;
			g = atoi(ptr);
			if ((g>0) && (g<65)) {
				rdr->grp |= (((uint64_t)1)<<(g-1));
			}
		}
		return;
	}

	if (!strcmp(token, "cooldown")) {
		if(strlen(value) == 0) {
			rdr->cooldown[0] = 0;
			rdr->cooldown[1] = 0;
			return;
		} else {
			for (i = 0, ptr = strtok_r(value, ",", &saveptr1); (i < 2) && (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++) {
				switch(i) {
				case 0:
					rdr->cooldown[0] = atoi(ptr);
					break;

				case 1:
					rdr->cooldown[1] = atoi(ptr);
					break;
				}
			}

			if (!rdr->cooldown[0] || !rdr->cooldown[1]) {
				fprintf(stderr, "cooldown must have 2 values (x,y) set values %d,%d ! cooldown deactivated\n",
						rdr->cooldown[0], rdr->cooldown[1]);

				rdr->cooldown[0] = 0;
				rdr->cooldown[1] = 0;
			}

		}
		return;
	}

	if (!strcmp(token, "emmcache")) {
		if(strlen(value) == 0) {
			rdr->cachemm = 0;
			rdr->rewritemm = 0;
			rdr->logemm = 0;
			return;
		} else {
			for (i = 0, ptr = strtok_r(value, ",", &saveptr1); (i < 3) && (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++) {
				switch(i)
				{
					case 0:
						rdr->cachemm = atoi(ptr);
						break;

					case 1:
						rdr->rewritemm = atoi(ptr);
						break;

					case 2: rdr->logemm = atoi(ptr);
					break;
				}
			}

			if (rdr->rewritemm <= 0) {
				fprintf(stderr, "Notice: Setting EMMCACHE to %i,1,%i instead of %i,%i,%i. ",
						rdr->cachemm, rdr->logemm,
						rdr->cachemm, rdr->rewritemm,
						rdr->logemm);

				fprintf(stderr, "Zero or negative number of rewrites is silly\n");
				rdr->rewritemm = 1;
			}
			return;
		}
	}

	if (!strcmp(token, "blocknano")) {
		rdr->b_nano = 0;
		if (strlen(value) > 0) {
			if (!strcmp(value,"all")) {
				rdr->b_nano = 0xFFFF;
			} else {
				for (ptr = strtok_r(value, ",", &saveptr1); ptr; ptr = strtok_r(NULL, ",", &saveptr1)) {
					i = (byte_atob(ptr) % 0x80);
					if (i >= 0 && i <= 16)
						rdr->b_nano |= (1 << i);
				}
			}
		}
		return;
	}

	if (!strcmp(token, "savenano")) {
		rdr->s_nano = 0;
		if (strlen(value) > 0) {
			if (!strcmp(value,"all")) {
				rdr->s_nano = 0xFFFF;
			} else {
				for (ptr = strtok_r(value, ",", &saveptr1); ptr; ptr = strtok_r(NULL, ",", &saveptr1)) {
					i = (byte_atob(ptr) % 0x80);
					if (i >= 0 && i <= 16)
						rdr->s_nano |= (1 << i);
				}
			}
		}
		return;
	}

	if (!strcmp(token, "blockemm-unknown")) {
		i=atoi(value);
		if (!i && (rdr->blockemm & EMM_UNKNOWN))
			rdr->blockemm -= EMM_UNKNOWN;
		if (i)
			rdr->blockemm |= EMM_UNKNOWN;
		return;
	}

	if (!strcmp(token, "blockemm-u")) {
		i=atoi(value);
		if (!i && (rdr->blockemm & EMM_UNIQUE))
			rdr->blockemm -= EMM_UNIQUE;
		if (i)
			rdr->blockemm |= EMM_UNIQUE;
		return;
	}

	if (!strcmp(token, "blockemm-s")) {
		i=atoi(value);
		if (!i && (rdr->blockemm & EMM_SHARED))
			rdr->blockemm -= EMM_SHARED;
		if (i)
			rdr->blockemm |= EMM_SHARED;
		return;
	}

	if (!strcmp(token, "blockemm-g")) {
		i=atoi(value);
		if (!i && (rdr->blockemm & EMM_GLOBAL))
			rdr->blockemm -= EMM_GLOBAL;
		if (i)
			rdr->blockemm |= EMM_GLOBAL;
		return;
	}

	if (!strcmp(token, "saveemm-unknown")) {
		i=atoi(value);
		if (!i && (rdr->saveemm & EMM_UNKNOWN))
			rdr->saveemm -= EMM_UNKNOWN;
		if (i)
			rdr->saveemm |= EMM_UNKNOWN;
		return;
	}

	if (!strcmp(token, "saveemm-u")) {
		i=atoi(value);
		if (!i && (rdr->saveemm & EMM_UNIQUE))
			rdr->saveemm -= EMM_UNIQUE;
		if (i)
			rdr->saveemm |= EMM_UNIQUE;
		return;
	}

	if (!strcmp(token, "saveemm-s")) {
		i=atoi(value);
		if (!i && (rdr->saveemm & EMM_SHARED))
			rdr->saveemm -= EMM_SHARED;
		if (i)
			rdr->saveemm |= EMM_SHARED;
		return;
	}

	if (!strcmp(token, "saveemm-g")) {
		i=atoi(value);
		if (!i && (rdr->saveemm & EMM_GLOBAL))
			rdr->saveemm -= EMM_GLOBAL;
		if (i)
			rdr->saveemm |= EMM_GLOBAL;
		return;
	}

	if (!strcmp(token, "blockemm-bylen")) {
		for (i = 0; i < CS_MAXEMMBLOCKBYLEN; i++)
			rdr->blockemmbylen[i] = 0;
		for (i = 0, ptr = strtok_r(value, ",", &saveptr1); (i < CS_MAXEMMBLOCKBYLEN) && (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++)
			rdr->blockemmbylen[i] = atoi(ptr);

		return;
	}

#ifdef WITH_LB
	if (!strcmp(token, "lb_weight")) {
		if(strlen(value) == 0) {
			rdr->lb_weight = 100;
			return;
		} else {
			rdr->lb_weight = atoi(value);
			if (rdr->lb_weight > 1000) rdr->lb_weight = 1000;
			else if (rdr->lb_weight <= 0) rdr->lb_weight = 100;
			return;
		}
	}
#endif

#ifdef MODULE_CCCAM
	if (!strcmp(token, "cccversion")) {
		// cccam version
		memset(rdr->cc_version, 0, sizeof(rdr->cc_version));
		if (strlen(value) > sizeof(rdr->cc_version) - 1) {
			fprintf(stderr, "cccam config: version too long.\n");
		}	else
			cs_strncpy(rdr->cc_version, value, sizeof(rdr->cc_version));
		return;
	}

	if (!strcmp(token, "cccmaxhop") || !strcmp(token, "cccmaxhops")) { //Schlocke: cccmaxhops is better!
		// cccam max card distance
		rdr->cc_maxhop  = strToIntVal(value, DEFAULT_CC_MAXHOP);
		return;
	}

	if (!strcmp(token, "cccmindown") ) {
		// cccam min downhops
		rdr->cc_mindown  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "cccwantemu")) {
		rdr->cc_want_emu  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "ccckeepalive")) {
		rdr->cc_keepalive  = strToIntVal(value, DEFAULT_CC_KEEPALIVE);
		return;
	}

	if (!strcmp(token, "ccchopsaway") || !strcmp(token, "cccreshar")  || !strcmp(token, "cccreshare")) {
		rdr->cc_reshare = strToIntVal(value, DEFAULT_CC_RESHARE);
		return;
	}

	if (!strcmp(token, "ccchop")) {
		rdr->cc_hop = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "cccreconnect")) {
		rdr->cc_reconnect = strToIntVal(value, DEFAULT_CC_RECONNECT);
		return;
	}

#endif

#ifdef MODULE_PANDORA
	if (!strcmp(token, "pand_send_ecm")) {
		rdr->pand_send_ecm = strToIntVal(value, 0);
		return;
	}

#endif
	if (!strcmp(token, "deprecated")) {
		rdr->deprecated  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "audisabled")) {
		rdr->audisabled  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "auprovid")) {
		if (strlen(value) == 0) {
			rdr->auprovid = 0;
			return;
		} else {
			rdr->auprovid = a2i(value, 3);
			return;
		}
	}
	// new code for multiple aes key per reader
	if (!strcmp(token, "aeskeys")) {
		parse_aes_keys(rdr,value);
		return;
	}

	if (!strcmp(token, "ndsversion")) {
		rdr->ndsversion = strToIntVal(value, 0);
		return;
	}


#ifdef WITH_AZBOX
	if (!strcmp(token, "mode")) {
		rdr->mode = strToIntVal(value, -1);
		return;
	}
#endif

	//ratelimit
	if (!strcmp(token, "ratelimitecm")) {
		if (strlen(value) == 0) {
			rdr->ratelimitecm = 0;
			return;
		} else {
			rdr->ratelimitecm = atoi(value);
			int32_t h;
			for (h=0;h<rdr->ratelimitecm;h++) rdr->rlecmh[h].last=-1;
			return;
		}
	}
	if (!strcmp(token, "ratelimitseconds")) {
		if (strlen(value) == 0) {
			if (rdr->ratelimitecm>0) {
				rdr->ratelimitseconds = 10;
			} else {
				rdr->ratelimitseconds = 0;
			}
			return;
		} else {
			rdr->ratelimitseconds = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "dropbadcws")) {
		rdr->dropbadcws = strToIntVal(value, 0);
		return;
	}

    if (!strcmp(token, "disablecrccws")) {
        rdr->disablecrccws = strToIntVal(value, 0);
        return;
    }

	if (!strcmp(token, "use_gpio")) {
		rdr->use_gpio = strToIntVal(value, 0);
		return;
	}

	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in reader section not recognized\n",token);
}

#ifdef IRDETO_GUESSING
int32_t init_irdeto_guess_tab(void)
{
  int32_t i, j, skip;
  int32_t b47;
  FILE *fp;
  char token[128], *ptr, *saveptr1 = NULL;
  char zSid[5];
  uchar b3;
  uint16_t caid, sid;
  struct s_irdeto_quess *ird_row, *head;

  memset(cfg.itab, 0, sizeof(cfg.itab));
  snprintf(token, sizeof(token), "%s%s", cs_confdir, cs_ird);
  if (!(fp=fopen(token, "r")))
  {
    cs_log("can't open file \"%s\" (errno=%d %s) irdeto guessing not loaded",
           token, errno, strerror(errno));
    return(1);
  }
  while (fgets(token, sizeof(token), fp))
  {
    if( strlen(token)<20 ) continue;
    for( i=b3=b47=caid=sid=skip=0, ptr=strtok_r(token, ":", &saveptr1); (i<4)&&(ptr); ptr=strtok_r(NULL, ":", &saveptr1), i++ )
    {
      trim(ptr);
      if( *ptr==';' || *ptr=='#' || *ptr=='-' ) {
        skip=1;
        break;
      }
      switch(i)
      {
        case 0: b3   = a2i(ptr, 2); break;
        case 1: b47  = a2i(ptr, 8); break;
        case 2: caid = a2i(ptr, 4); break;
        case 3:
          for( j=0; j<4; j++ )
            zSid[j]=ptr[j];
          zSid[4]=0;
          sid  = a2i(zSid, 4);
          break;
      }
    }
    if( !skip )
    {
      if (!cs_malloc(&ird_row, sizeof(struct s_irdeto_quess), -1)) {
        fclose(fp);
        return(1);
      }
      ird_row->b47  = b47;
      ird_row->caid = caid;
      ird_row->sid  = sid;
      ird_row->next = 0;

      head = cfg.itab[b3];
      if( head ) {
        while( head->next )
          head=head->next;
        head->next=ird_row;
      }
      else
        cfg.itab[b3]=ird_row;
        //cs_debug_mask(D_CLIENT, "%02X:%08X:%04X:%04X", b3, b47, caid, sid);
    }
  }
  fclose(fp);

  for( i=0; i<0xff; i++ )
  {
    head=cfg.itab[i];
    while(head)
    {
      cs_debug_mask(D_CLIENT, "itab[%02X]: b47=%08X, caid=%04X, sid=%04X",
               i, head->b47, head->caid, head->sid);
      head=head->next;
    }
  }
  return(0);
}
#endif

/**
 * frees a reader
 **/
void free_reader(struct s_reader *rdr)
{
	NULLFREE(rdr->emmfile);

	struct s_ecmWhitelist *tmp;
	struct s_ecmWhitelistIdent *tmpIdent;
	struct s_ecmWhitelistLen *tmpLen;
	for(tmp = rdr->ecmWhitelist; tmp; tmp=tmp->next){
		for(tmpIdent = tmp->idents; tmpIdent; tmpIdent=tmpIdent->next){
			for(tmpLen = tmpIdent->lengths; tmpLen; tmpLen=tmpLen->next){
				add_garbage(tmpLen);
			}
			add_garbage(tmpIdent);
		}
		add_garbage(tmp);
	}
	rdr->ecmWhitelist = NULL;

	clear_ftab(&rdr->ftab);

#ifdef WITH_LB
	if (rdr->lb_stat) {
		cs_lock_destroy(&rdr->lb_stat_lock);
		ll_destroy_data(rdr->lb_stat);
		rdr->lb_stat = NULL;
	}

#endif
	add_garbage(rdr);
}

int32_t init_readerdb(void)
{
	int32_t tag = 0;
	FILE *fp;
	char *value, *token;
	if(!cs_malloc(&token, MAXLINESIZE, -1)) return 1;
	configured_readers = ll_create("configured_readers");

	snprintf(token, MAXLINESIZE, "%s%s", cs_confdir, cs_srvr);
	if (!(fp=fopen(token, "r"))) {
		cs_log("can't open file \"%s\" (errno=%d %s)\n", token, errno, strerror(errno));
		free(token);
		return(1);
	}
	struct s_reader *rdr;
	cs_malloc(&rdr, sizeof(struct s_reader), SIGINT);

	ll_append(configured_readers, rdr);
	while (fgets(token, MAXLINESIZE, fp)) {
		int32_t i, l;
		if ((l = strlen(trim(token))) < 3)
			continue;
		if ((token[0] == '[') && (token[l-1] == ']')) {
			token[l-1] = 0;
			tag = (!strcmp("reader", strtolower(token+1)));
			if (rdr->label[0] && rdr->typ) {
				struct s_reader *newreader;
				if(cs_malloc(&newreader, sizeof(struct s_reader), -1)){
					ll_append(configured_readers, newreader);
					rdr = newreader;
				}
			}
			memset(rdr->hexserial, 0, sizeof(rdr->hexserial));
			memset(rdr->rom, 0, sizeof(rdr->rom));
			rdr->enable = 1;
			rdr->tcp_rto = DEFAULT_TCP_RECONNECT_TIMEOUT;
			rdr->tcp_ito = DEFAULT_INACTIVITYTIMEOUT;
			rdr->nagra_read = 0;
			rdr->mhz = 357;
			rdr->cardmhz = 357;
#ifdef WITH_AZBOX
			rdr->mode = -1;
#endif
			rdr->deprecated = 0;
			rdr->force_irdeto = 0;
#ifdef MODULE_CCCAM
			rdr->cc_reshare = DEFAULT_CC_RESHARE;
			rdr->cc_maxhop  = DEFAULT_CC_MAXHOP;
			rdr->cc_mindown = 0;
			rdr->cc_reconnect = DEFAULT_CC_RECONNECT;
#endif
#ifdef WITH_LB
			rdr->lb_weight = 100;
#endif
			cs_strncpy(rdr->pincode, "none", sizeof(rdr->pincode));
			rdr->ndsversion = 0;
			rdr->ecmWhitelist = NULL;
			for (i=1; i<CS_MAXCAIDTAB; rdr->ctab.mask[i++]=0xffff);
			continue;
		}

		if (!tag)
			continue;
		if (!(value=strchr(token, '=')))
			continue;
		*value++ ='\0';
		chk_reader(trim(strtolower(token)), trim(value), rdr);
	}
	free(token);
	LL_ITER itr = ll_iter_create(configured_readers);
	while((rdr = ll_iter_next(&itr))) { //build active readers list
		int32_t i;
		if (rdr->typ & R_IS_CASCADING) {
			for (i=0; i<CS_MAX_MOD; i++) {
				if (ph[i].num && rdr->typ==ph[i].num) {
					rdr->ph=ph[i];
					if(rdr->device[0]) rdr->ph.active=1;
				}
			}
		}
	}
	fclose(fp);
	return(0);
}

#ifdef CS_ANTICASC
void init_ac(void)
{
  int32_t nr;
  FILE *fp;
  char *saveptr1 = NULL, *token;
  if(!cs_malloc(&token, MAXLINESIZE, -1)) return;

  snprintf(token, MAXLINESIZE, "%s%s", cs_confdir, cs_ac);
  if (!(fp=fopen(token, "r")))
  {
    cs_log("can't open file \"%s\" (errno=%d %s) anti-cascading table not loaded",
            token, errno, strerror(errno));
    free(token);
    return;
  }

  struct s_cpmap *cur_cpmap, *first_cpmap = NULL, *last_cpmap = NULL;

  for(nr=0; fgets(token, MAXLINESIZE, fp);)
  {
    int32_t i, skip;
    uint16_t caid, sid, chid, dwtime;
    uint32_t  provid;
    char *ptr, *ptr1;

    if( strlen(token)<4 ) continue;

    caid=sid=chid=dwtime=0;
    provid=0;
    skip=0;
    ptr1=0;
    for( i=0, ptr=strtok_r(token, "=", &saveptr1); (i<2)&&(ptr); ptr=strtok_r(NULL, "=", &saveptr1), i++ )
    {
      trim(ptr);
      if( *ptr==';' || *ptr=='#' || *ptr=='-' ) {
        skip=1;
        break;
      }
      switch( i )
      {
        case 0:
          ptr1=ptr;
          break;
        case 1:
          dwtime = atoi(ptr);
          break;
      }
    }

    if( !skip )
    {
      for( i=0, ptr=strtok_r(ptr1, ":", &saveptr1); (i<4)&&(ptr); ptr=strtok_r(NULL, ":", &saveptr1), i++ )
      {
        trim(ptr);
        switch( i )
        {
        case 0:
          if( *ptr=='*' ) caid = 0;
          else caid = a2i(ptr, 4);
          break;
        case 1:
          if( *ptr=='*' ) provid = 0;
          else provid = a2i(ptr, 6);
          break;
        case 2:
          if( *ptr=='*' ) sid = 0;
          else sid = a2i(ptr, 4);
          break;
        case 3:
          if( *ptr=='*' ) chid = 0;
          else chid = a2i(ptr, 4);
          break;
        }
      }
      if (!cs_malloc(&cur_cpmap, sizeof(struct s_cpmap), -1)){
      	for(cur_cpmap = first_cpmap; cur_cpmap; cur_cpmap = cur_cpmap->next)
      		free(cur_cpmap);
      	free(token);
      	return;
      }
      if(last_cpmap)
        last_cpmap->next=cur_cpmap;
      else
        first_cpmap=cur_cpmap;
      last_cpmap=cur_cpmap;

      cur_cpmap->caid   = caid;
      cur_cpmap->provid = provid;
      cur_cpmap->sid    = sid;
      cur_cpmap->chid   = chid;
      cur_cpmap->dwtime = dwtime;
      cur_cpmap->next   = 0;

      cs_debug_mask(D_CLIENT, "nr=%d, caid=%04X, provid=%06X, sid=%04X, chid=%04X, dwtime=%d",
                nr, caid, provid, sid, chid, dwtime);
      nr++;
    }
  }
  free(token);
  fclose(fp);

  last_cpmap = cfg.cpmap;
  cfg.cpmap = first_cpmap;
  for(cur_cpmap = last_cpmap; cur_cpmap; cur_cpmap = cur_cpmap->next)
    add_garbage(cur_cpmap);
  //cs_log("%d lengths for caid guessing loaded", nr);
  return;
}
#endif

int32_t match_whitelist(ECM_REQUEST *er, struct s_global_whitelist *entry) {
	return ((!entry->caid || entry->caid == er->caid)
			&& (!entry->provid || entry->provid == er->prid)
			&& (!entry->srvid || entry->srvid == er->srvid)
			&& (!entry->chid || entry->chid == er->chid)
			&& (!entry->pid || entry->pid == er->pid)
			&& (!entry->ecmlen || entry->ecmlen == er->l));
}

int32_t chk_global_whitelist(ECM_REQUEST *er, uint32_t *line)
{
	*line = -1;
	if (!cfg.global_whitelist)
		return 1;

	struct s_global_whitelist *entry;

	//check mapping:
	if (cfg.global_whitelist_use_m) {
		entry = cfg.global_whitelist;
		while (entry) {
			if (entry->type == 'm') {
				if (match_whitelist(er, entry)) {
					er->caid = entry->mapcaid;
					er->prid = entry->mapprovid;
					cs_debug_mask(D_TRACE, "whitelist: mapped %04X:%06X to %04X:%06X", er->caid, er->prid, entry->mapcaid, entry->mapprovid);
					break;
				}
			}
			entry = entry->next;
		}
	}

	if (cfg.global_whitelist_use_l) { //Check caid/prov/srvid etc matching, except ecm-len:
		entry = cfg.global_whitelist;
		int8_t caidprov_matches = 0;
		while (entry) {
			if (entry->type == 'l') {
				if (match_whitelist(er, entry)) {
					*line = entry->line;
					return 1;
				}
				if ((!entry->caid || entry->caid == er->caid)
						&& (!entry->provid || entry->provid == er->prid)
						&& (!entry->srvid || entry->srvid == er->srvid)
						&& (!entry->chid || entry->chid == er->chid)
						&& (!entry->pid || entry->pid == er->pid))
					caidprov_matches = 1;
			}
			entry = entry->next;
		}
		if (caidprov_matches) //...but not ecm-len!
			return 0;
	}

	entry = cfg.global_whitelist;
	while (entry) {
		if (match_whitelist(er, entry)) {
			*line = entry->line;
			if (entry->type == 'w')
				return 1;
			else if (entry->type == 'i')
				return 0;
		}
		entry = entry->next;
	}
	return 0;
}

//Format:
//Whitelist-Entry:
//w:caid:prov:srvid:pid:chid:ecmlen
//Ignore-Entry:
//i:caid:prov:srvid:pid:chid:ecmlen
//ECM len check - Entry:
//l:caid:prov:srvid:pid:chid:ecmlen

//Mapping:
//m:caid:prov:srvid:pid:chid:ecmlen caidto:provto

static struct s_global_whitelist *global_whitelist_read_int(void) {
	FILE *fp;
	char token[1024], str1[1024];
	unsigned char type;
	int32_t i, ret, count=0;
	struct s_global_whitelist *new_whitelist = NULL, *entry, *last=NULL;
	uint32_t line = 0;

	const char *cs_whitelist="oscam.whitelist";
	cfg.global_whitelist_use_l = 0;
	cfg.global_whitelist_use_m = 0;

	snprintf(token, sizeof(token), "%s%s", cs_confdir, cs_whitelist);
	fp=fopen(token, "r");

	if (!fp) {
		cs_log("can't open whitelist file %s", token);
		return NULL;
	}

	while (fgets(token, sizeof(token), fp)) {
		line++;
		if (strlen(token) <= 1) continue;
		if (token[0]=='#' || token[0]=='/') continue;
		if (strlen(token)>1024) continue;

		for (i=0;i<(int)strlen(token);i++) {
			if ((token[i]==':' || token[i]==' ') && token[i+1]==':') {
				memmove(token+i+2, token+i+1, strlen(token)-i+1);
				token[i+1]='0';
			}
			if (token[i]=='#' || token[i]=='/') {
				token[i]='\0';
				break;
			}
		}

		type = 'w';
		uint32_t caid=0, provid=0, srvid=0, pid=0, chid=0, ecmlen=0, mapcaid=0, mapprovid=0;
		memset(str1, 0, sizeof(str1));

		ret = sscanf(token, "%c:%4x:%6x:%4x:%4x:%4x:%1023s", &type, &caid, &provid, &srvid, &pid, &chid, str1);

		type = tolower(type);

		//w=whitelist
		//i=ignore
		//l=len-check
		//m=map caid/prov
		if (ret < 1 || (type != 'w' && type != 'i' && type != 'l' && type != 'm'))
			continue;

		if (type == 'm') {
			char *p = strstr(token+4, " ");
			if (!p || sscanf(p+1, "%4x:%6x", &mapcaid, &mapprovid) < 2) {
				cs_debug_mask(D_TRACE, "whitelist: wrong mapping: %s", token);
				continue;
			}
			str1[0]=0;
			cfg.global_whitelist_use_m = 1;
		}
		strncat(str1, ",", sizeof(str1));
		char *p = str1, *p2 = str1;
		while (*p) {
			if (*p == ',') {
				*p = 0;
				ecmlen = 0;
				sscanf(p2, "%4x", &ecmlen);

				if (!cs_malloc(&entry, sizeof(struct s_global_whitelist), -1)) {
					fclose(fp);
					return new_whitelist;
				}

				count++;
				entry->line = line;
				entry->type = type;
				entry->caid = caid;
				entry->provid = provid;
				entry->srvid = srvid;
				entry->pid = pid;
				entry->chid = chid;
				entry->ecmlen = ecmlen;
				entry->mapcaid = mapcaid;
				entry->mapprovid = mapprovid;
				if (entry->type == 'l')
					cfg.global_whitelist_use_l = 1;

				if (type == 'm')
					cs_debug_mask(D_TRACE,
							"whitelist: %c: %04X:%06X:%04X:%04X:%04X:%02X map to %04X:%06X", entry->type, entry->caid, entry->provid, entry->srvid, entry->pid, entry->chid, entry->ecmlen, entry->mapcaid, entry->mapprovid);
				else
					cs_debug_mask(D_TRACE,
						"whitelist: %c: %04X:%06X:%04X:%04X:%04X:%02X", entry->type, entry->caid, entry->provid, entry->srvid, entry->pid, entry->chid, entry->ecmlen);

				if (!new_whitelist) {
					new_whitelist = entry;
					last = new_whitelist;
				} else {
					last->next = entry;
					last = entry;
				}

				p2 = p + 1;
			}
			p++;
			}
	}

	cs_log("%d entries read from %s", count, cs_whitelist);

	fclose(fp);

	return new_whitelist;
}

void global_whitelist_read(void) {

	struct s_global_whitelist *entry, *old_list = cfg.global_whitelist;

	old_list = cfg.global_whitelist;
	cfg.global_whitelist = global_whitelist_read_int();

	while (old_list) {
		entry = old_list->next;
		free(old_list);
		old_list = entry;
	}
}

#ifdef CS_CACHEEX

struct s_cacheex_matcher *is_cacheex_matcher_matching(ECM_REQUEST *from_er, ECM_REQUEST *to_er)
{
	struct s_cacheex_matcher *entry = cfg.cacheex_matcher;
	int8_t v_ok = (from_er && to_er)?2:1;
	while (entry) {
		int8_t ok = 0;
		if (from_er
				&& (!entry->caid || entry->caid == from_er->caid)
				&& (!entry->provid || entry->provid == from_er->prid)
				&& (!entry->srvid || entry->srvid == from_er->srvid)
				&& (!entry->chid || entry->chid == from_er->chid)
				&& (!entry->pid || entry->pid == from_er->pid)
				&& (!entry->ecmlen || entry->ecmlen == from_er->l))
			ok++;

		if (to_er
				&& (!entry->to_caid || entry->to_caid == to_er->caid)
				&& (!entry->to_provid || entry->to_provid == to_er->prid)
				&& (!entry->to_srvid || entry->to_srvid == to_er->srvid)
				&& (!entry->to_chid || entry->to_chid == to_er->chid)
				&& (!entry->to_pid || entry->to_pid == to_er->pid)
				&& (!entry->to_ecmlen || entry->to_ecmlen == to_er->l))
			ok++;

		if (ok == v_ok) {
			if (!from_er || !to_er || from_er->srvid == to_er->srvid)
				return entry;
		}
		entry = entry->next;
	}
	return NULL;
}

//Format:
//caid:prov:srvid:pid:chid:ecmlen=caid:prov:srvid:pid:chid:ecmlen[,validfrom,validto]
//validfrom: default=-2000
//validto: default=4000
//valid time if found in cache
static struct s_cacheex_matcher *cacheex_matcher_read_int(void) {
	FILE *fp;
	char token[1024];
	unsigned char type;
	int32_t i, ret, count=0;
	struct s_cacheex_matcher *new_cacheex_matcher = NULL, *entry, *last=NULL;
	uint32_t line = 0;

	const char *cs_cacheex_matcher="oscam.cacheex";

	snprintf(token, sizeof(token), "%s%s", cs_confdir, cs_cacheex_matcher);
	fp=fopen(token, "r");

	if (!fp) {
		cs_log("can't open cacheex-matcher file %s", token);
		return NULL;
	}

	while (fgets(token, sizeof(token), fp)) {
		line++;
		if (strlen(token) <= 1) continue;
		if (token[0]=='#' || token[0]=='/') continue;
		if (strlen(token)>100) continue;

		for (i=0;i<(int)strlen(token);i++) {
			if ((token[i]==':' || token[i]==' ') && token[i+1]==':') {
				memmove(token+i+2, token+i+1, strlen(token)-i+1);
				token[i+1]='0';
			}
			if (token[i]=='#' || token[i]=='/') {
				token[i]='\0';
				break;
			}
		}

		type = 'm';
		uint32_t caid=0, provid=0, srvid=0, pid=0, chid=0, ecmlen=0;
		uint32_t to_caid=0, to_provid=0, to_srvid=0, to_pid=0, to_chid=0, to_ecmlen=0;
		int32_t valid_from=-2000, valid_to=4000;

		ret = sscanf(token, "%c:%4x:%6x:%4x:%4x:%4x:%4X=%4x:%6x:%4x:%4x:%4x:%4X,%4d,%4d",
				&type,
				&caid, &provid, &srvid, &pid, &chid, &ecmlen,
				&to_caid, &to_provid, &to_srvid, &to_pid, &to_chid, &to_ecmlen,
				&valid_from, &valid_to);

		type = tolower(type);

		if (ret<7 || type != 'm')
			continue;

		if(!cs_malloc(&entry,sizeof(struct s_cacheex_matcher), -1)){
			fclose(fp);
			return new_cacheex_matcher;
		}
		count++;
		entry->line=line;
		entry->type=type;
		entry->caid=caid;
		entry->provid=provid;
		entry->srvid=srvid;
		entry->pid=pid;
		entry->chid=chid;
		entry->ecmlen=ecmlen;
		entry->to_caid=to_caid;
		entry->to_provid=to_provid;
		entry->to_srvid=to_srvid;
		entry->to_pid=to_pid;
		entry->to_chid=to_chid;
		entry->to_ecmlen=to_ecmlen;
		entry->valid_from=valid_from;
		entry->valid_to=valid_to;

		cs_debug_mask(D_TRACE, "cacheex-matcher: %c: %04X:%06X:%04X:%04X:%04X:%02X = %04X:%06X:%04X:%04X:%04X:%02X valid %d/%d",
				entry->type, entry->caid, entry->provid, entry->srvid, entry->pid, entry->chid, entry->ecmlen,
				entry->to_caid, entry->to_provid, entry->to_srvid, entry->to_pid, entry->to_chid, entry->to_ecmlen,
				entry->valid_from, entry->valid_to);

		if (!new_cacheex_matcher) {
			new_cacheex_matcher=entry;
			last = new_cacheex_matcher;
		} else {
			last->next = entry;
			last = entry;
		}
	}

	cs_log("%d entries read from %s", count, cs_cacheex_matcher);

	fclose(fp);

	return new_cacheex_matcher;
}

void cacheex_matcher_read(void) {

	struct s_cacheex_matcher *entry, *old_list = cfg.cacheex_matcher;

	old_list = cfg.cacheex_matcher;
	cfg.cacheex_matcher = cacheex_matcher_read_int();

	while (old_list) {
		entry = old_list->next;
		free(old_list);
		old_list = entry;
	}
}
#endif

void init_len4caid(void)
{
	int32_t nr;
	FILE *fp;
	char *value, *token;
	if(!cs_malloc(&token, MAXLINESIZE, -1)) return;

	memset(len4caid, 0, sizeof(uint16_t)<<8);
	snprintf(token, MAXLINESIZE, "%s%s", cs_confdir, cs_l4ca);
	if (!(fp = fopen(token, "r"))){
		free(token);
		return;
	}
	for(nr = 0; fgets(token, MAXLINESIZE, fp);) {
		int32_t i, c;
		char *ptr;
		if (!(value=strchr(token, ':')))
			continue;
		*value++ ='\0';
		if( (ptr = strchr(value, '#')) )
			*ptr = '\0';
		if (strlen(trim(token)) != 2)
			continue;
		if (strlen(trim(value)) != 4)
			continue;
		if ((i = byte_atob(token)) < 0)
			continue;
		if ((c = word_atob(value)) < 0)
			continue;
		len4caid[i] = c;
		nr++;
	}
	free(token);
	fclose(fp);
	cs_log("%d lengths for caid guessing loaded", nr);
	return;
}
