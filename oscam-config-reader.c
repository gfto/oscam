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

#include "oscam-aes.h"
#include "oscam-conf.h"
#include "oscam-conf-chk.h"
#include "oscam-conf-mk.h"
#include "oscam-garbage.h"
#include "oscam-lock.h"
#include "oscam-reader.h"
#include "oscam-string.h"

#define cs_srvr "oscam.server"

extern struct s_module modules[CS_MAX_MOD];
extern struct s_cardreader cardreaders[CS_MAX_MOD];

static void mgencrypted_fn(const char *UNUSED(token), char *value, void *setting, FILE *UNUSED(f)) {
	struct s_reader *rdr = setting;

	if (value) {
		uchar key[16];
		uchar mac[6];
		char tmp_dbg[13];
		uchar *buf = NULL;
		int32_t i, len = 0;
		char *ptr, *saveptr1 = NULL;

		memset(&key, 0, 16);
		memset(&mac, 0, 6);

		for (i = 0, ptr = strtok_r(value, ",", &saveptr1); (i < 2) && (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++) {
			trim(ptr);
			switch(i) {
			case 0:
				len = strlen(ptr) / 2 + (16 - (strlen(ptr) / 2) % 16);
				if (!cs_malloc(&buf, len)) return;
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
			switch (i) {
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
}

static void ecmwhitelist_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_reader *rdr = setting;
	if (value) {
		char *ptr, *ptr2, *ptr3, *saveptr1 = NULL;
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
			saveptr1 = NULL;
			char *saveptr2 = NULL;
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
						if (cs_malloc(&tmp, sizeof(struct s_ecmWhitelist))) {
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
						if (cs_malloc(&tmpIdent, sizeof(struct s_ecmWhitelistIdent))) {
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
						if (cs_malloc(&tmpLen, sizeof(struct s_ecmWhitelistLen))) {
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

	value = mk_t_ecmwhitelist(rdr->ecmWhitelist);
	if (strlen(value) > 0 || cfg.http_full_cfg)
		fprintf_conf(f, token, "%s\n", value);
	free_mk_t(value);
}

static void ecmheaderwhitelist_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_reader *rdr = setting;
	if (value) {
		char *ptr, *ptr2, *ptr3;
		struct s_ecmHeaderwhitelist *tmp, *last = NULL;

		if (strlen(value) == 0) {
			for (tmp = rdr->ecmHeaderwhitelist; tmp; tmp=tmp->next)
				add_garbage(tmp);
			rdr->ecmHeaderwhitelist = NULL;
		} else {
			char *ptr4, *ptr5, *ptr6, *saveptr = NULL, *saveptr4 = NULL, *saveptr5 = NULL, *saveptr6 = NULL;
			uint16_t caid = 0;
			uint32_t provid = 0;
			int16_t len = 0;
			for (ptr = strtok_r(value, ";", &saveptr); ptr; ptr = strtok_r(NULL, ";", &saveptr)) {
				caid = 0;
				provid = 0;
				ptr2 = strchr(ptr, '@');
				ptr3 = strchr(ptr, ':');
				if (ptr2 == NULL && ptr3 == NULL) { //no Caid no Provid
					for (ptr4 = strtok_r(ptr, ",", &saveptr4); ptr4; ptr4 = strtok_r(NULL, ",", &saveptr4)) {
						if (cs_malloc(&tmp, sizeof(struct s_ecmHeaderwhitelist))) {
							ptr4 = trim(ptr4);
							len = strlen(ptr4);
							key_atob_l(ptr4, tmp->header, len);
							tmp->len = len;
							tmp->caid = 0;
							tmp->provid = 0;
							tmp->next = NULL;
							if (last == NULL) {
								rdr->ecmHeaderwhitelist = tmp;
							} else {
								last->next = tmp;
							}
							last = tmp;
						}
					}
				}

				if (ptr3 != NULL && ptr2 == NULL) { // only with Caid
					ptr3[0] = '\0';
					++ptr3;
					caid = (int16_t)dyn_word_atob(ptr);
					for (ptr5 = strtok_r(ptr3, ",", &saveptr5); ptr5; ptr5 = strtok_r(NULL, ",", &saveptr5)) {
						if (cs_malloc(&tmp, sizeof(struct s_ecmHeaderwhitelist))) {
							tmp->caid = caid;
							tmp->provid = 0;
							ptr5 = trim(ptr5);
							len = strlen(ptr5);
							key_atob_l(ptr5, tmp->header, len);
							tmp->len = len;
							tmp->next = NULL;
							if (last == NULL) {
								rdr->ecmHeaderwhitelist = tmp;
							} else {
								last->next = tmp;
							}
							last = tmp;
						}
					}
				}

				if (ptr3 != NULL && ptr2 != NULL) { // with Caid & Provid
					ptr2[0] = '\0';
					++ptr2; // -> provid
					ptr3[0] = '\0';
					++ptr3; // -> headers
					caid = (int16_t)dyn_word_atob(ptr);
					provid = (uint32_t)a2i(ptr2, 6);
					for (ptr6 = strtok_r(ptr3, ",", &saveptr6); ptr6; ptr6 = strtok_r(NULL, ",", &saveptr6)) {
						if (cs_malloc(&tmp, sizeof(struct s_ecmHeaderwhitelist))) {
							tmp->caid = caid;
							tmp->provid = provid;
							ptr6 = trim(ptr6);
							len = strlen(ptr6);
							key_atob_l(ptr6, tmp->header, len);
							tmp->len = len;
							tmp->next = NULL;
							if (last == NULL) {
								rdr->ecmHeaderwhitelist = tmp;
							} else {
								last->next = tmp;
							}
							last = tmp;
						}
					}
				}
			}
		}
/*	if (rdr->ecmHeaderwhitelist != NULL) { // debug
		cs_log("**********Begin ECM Header List for Reader: %s **************", rdr->label);

		struct s_ecmHeaderwhitelist *tmp;
		for(tmp = rdr->ecmHeaderwhitelist; tmp; tmp=tmp->next){
			cs_log("Caid: %i Provid: %i Header: %02X Len: %i", tmp->caid, tmp->provid, tmp->header[0], tmp->len);
		}
		cs_log("***********End ECM Header List for Reader: %s ***************", rdr->label);
	} */
		return;
	}

	value = mk_t_ecmheaderwhitelist(rdr->ecmHeaderwhitelist);
	if (strlen(value) > 0 || cfg.http_full_cfg)
		fprintf_conf(f, token, "%s\n", value);
	free_mk_t(value);
}

static void protocol_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_reader *rdr = setting;
	if (value) {
		struct protocol_map {
			char *name;
			int typ;
		} protocols[] = {
			{ "serial",     R_SERIAL },
			{ "camd35",     R_CAMD35 },
			{ "cs378x",     R_CS378X },
			{ "cs357x",     R_CAMD35 },
			{ "camd33",     R_CAMD33 },
			{ "gbox",       R_GBOX },
			{ "cccam",      R_CCCAM },
			{ "cccam ext",  R_CCCAM },
			{ "constcw",    R_CONSTCW },
			{ "radegast",   R_RADEGAST },
			{ "ghttp",      R_GHTTP },
			{ "newcamd",    R_NEWCAMD },
			{ "newcamd525", R_NEWCAMD },
			{ "newcamd524", R_NEWCAMD },
			{ NULL        , 0 }
		}, *p;
		int i;
		// Parse card readers
		for (i = 0; i < CS_MAX_MOD; i++) {
			if (streq(value, cardreaders[i].desc)) {
				rdr->crdr = cardreaders[i];
				rdr->typ  = cardreaders[i].typ;
				return;
			}
		}
		// Parse protocols
		for(i = 0, p = &protocols[0]; p->name; p = &protocols[++i]) {
			if (streq(p->name, value)) {
				rdr->typ = p->typ;
				break;
			}
		}
		if (rdr->typ == R_NEWCAMD)
			rdr->ncd_proto = streq(value, "newcamd524") ? NCD_524 : NCD_525;
		if (!rdr->typ)
			fprintf(stderr, "ERROR: '%s' is unsupported reader protocol!\n", value);
		return;
	}
	fprintf_conf(f, token, "%s\n", reader_get_type_desc(rdr, 0));
}

static void device_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_reader *rdr = setting;
	int32_t isphysical = !is_network_reader(rdr);
	if (value) {
		int32_t i;
		char *ptr, *saveptr1 = NULL;
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
	fprintf_conf(f, token, "%s", rdr->device); // it should not have \n at the end
	if ((rdr->r_port || cfg.http_full_cfg) && !isphysical)
		fprintf(f, ",%d", rdr->r_port);
	if ((rdr->l_port || cfg.http_full_cfg) && !isphysical && strncmp(reader_get_type_desc(rdr, 0), "cccam", 5))
		fprintf(f, ",%d", rdr->l_port);
	fprintf(f, "\n");
}

static void key_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_reader *rdr = setting;
	if (value) {
		if (strlen(value) == 0)
			return;
		if (key_atob_l(value, rdr->ncd_key, 28)) {
			fprintf(stderr, "reader key parse error, %s=%s\n", token, value);
			memset(rdr->ncd_key, 0, sizeof(rdr->ncd_key));
		}
		return;
	}
	if (rdr->ncd_key[0] || rdr->ncd_key[13] || cfg.http_full_cfg) {
		fprintf_conf(f, token, "%s", ""); // it should not have \n at the end
		if (rdr->ncd_key[0] || rdr->ncd_key[13]) {
			int j;
			for (j = 0; j < 14; j++) {
				fprintf(f, "%02X", rdr->ncd_key[j]);
			}
		}
		fprintf(f, "\n");
	}
}

static void services_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_reader *rdr = setting;
	if (value) {
		if (strlen(value)) {
			chk_services(value, &rdr->sidtabok, &rdr->sidtabno);
		} else {
			rdr->sidtabok = 0;
			rdr->sidtabno = 0;
		}
		rdr->changes_since_shareupdate = 1;
		return;
	}
	value = mk_t_service((uint64_t)rdr->sidtabok, (uint64_t)rdr->sidtabno);
	if (strlen(value) > 0 || cfg.http_full_cfg)
		fprintf_conf(f, token, "%s\n", value);
	free_mk_t(value);
}

#ifdef CS_CACHEEX
static void cacheex_ecm_filter_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_reader *rdr = setting;
	if (value) {
		if (strlen(value)) {
			chk_hitvaluetab(value, &rdr->cacheex.filter_caidtab);
		} else {
			clear_csptab(&rdr->cacheex.filter_caidtab);
		}
		return;
	}
	value = mk_t_hitvaluetab(&rdr->cacheex.filter_caidtab);
	if (strlen(value) > 0 || cfg.http_full_cfg)
		fprintf_conf(f, token, "%s\n", value);
	free_mk_t(value);
}
#endif

static void caid_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_reader *rdr = setting;
	if (value) {
		if (strlen(value)) {
			chk_caidtab(value, &rdr->ctab);
		} else {
			clear_caidtab(&rdr->ctab);
		}
		rdr->changes_since_shareupdate = 1;
		return;
	}
	value = mk_t_caidtab(&rdr->ctab);
	if (strlen(value) > 0 || cfg.http_full_cfg)
		fprintf_conf(f, token, "%s\n", value);
	free_mk_t(value);
}

static void boxid_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_reader *rdr = setting;
	if (value) {
		rdr->boxid = strlen(value) ? a2i(value, 4) : 0;
		return;
	}
	int32_t isphysical = !is_network_reader(rdr);
	if (rdr->boxid && isphysical)
		fprintf_conf(f, token, "%08X\n", rdr->boxid);
	else if (cfg.http_full_cfg && isphysical)
		fprintf_conf(f, token, "\n");
}

static void rsakey_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_reader *rdr = setting;
	if (value) {
		int32_t len = strlen(value);
		if(len != 128 && len != 240) {
			memset(rdr->rsa_mod, 0, 120);
		} else {
			if (key_atob_l(value, rdr->rsa_mod, len)) {
				fprintf(stderr, "reader rsakey parse error, %s=%s\n", token, value);
				memset(rdr->rsa_mod, 0, sizeof(rdr->rsa_mod));
			}
		}
		return;
	}
	int32_t isphysical = !is_network_reader(rdr);
	int32_t len = check_filled(rdr->rsa_mod, 120);
	if (len > 0 && isphysical) {
		if(len > 64) len = 120;
		else len = 64;
		char tmp[len*2+1];
		fprintf_conf(f, "rsakey", "%s\n", cs_hexdump(0, rdr->rsa_mod, len, tmp, sizeof(tmp)));
	} else if(cfg.http_full_cfg && isphysical)
		fprintf_conf(f, "rsakey", "\n");
}

static void flags_fn(const char *token, char *value, void *setting, long flag, FILE *f) {
	uint32_t *var = setting;
	if (value) {
		int i = atoi(value);
		if (!i && (*var & flag))
			*var -= flag;
		if (i)
			*var |= flag;
		return;
	}
	if ((*var & flag) || cfg.http_full_cfg)
		fprintf_conf(f, token, "%d\n", (*var & flag) ? 1 : 0);
}

void chk_reader(char *token, char *value, struct s_reader *rdr)
{
	int32_t i;
	char *ptr, *saveptr1 = NULL;
	/*
	 *  case sensitive first
	 */

	if (streq(token, "device")) {
		device_fn(token, value, rdr, NULL);
		return;
	}

	if (streq(token, "key")) {
		key_fn(token, value, rdr, NULL);
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
		if (strlen(value))
			rdr->description = cs_strdup(value);
		return;
	}
#endif

	if (streq(token, "mg-encrypted")) {
		mgencrypted_fn(token, value, rdr, NULL);
		return;
	}

	if (!strcmp(token, "pincode")) {
		cs_strncpy(rdr->pincode, value, sizeof(rdr->pincode));
		return;
	}

	if (!strcmp(token, "readnano")) {
		NULLFREE(rdr->emmfile);
		if (strlen(value) > 0)
			rdr->emmfile = cs_strdup(value);
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

	if (streq(token, "services")) {
		services_fn(token, value, rdr, NULL);
		return;
	}
	if (!strcmp(token, "inactivitytimeout")) {
		rdr->tcp_ito  = strToIntVal(value, DEFAULT_INACTIVITYTIMEOUT);
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
		rdr->cacheex.mode  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "cacheex_maxhop")) {
		rdr->cacheex.maxhop  = strToIntVal(value, 0);
		return;
	}

	if (streq(token, "cacheex_ecm_filter")) {
		cacheex_ecm_filter_fn(token, value, rdr, NULL);
		return;
	}
	if (!strcmp(token, "cacheex_allow_request")) {
		rdr->cacheex.allow_request  = strToIntVal(value, 1);
		return;
	}
	if (!strcmp(token, "cacheex_drop_csp")) {
		rdr->cacheex.drop_csp  = strToIntVal(value, 0);
		return;
	}
#endif

	if (!strcmp(token, "logport")) {
		rdr->log_port  = strToIntVal(value, 0);
		return;
	}

	if (streq(token, "caid")) {
		caid_fn(token, value, rdr, NULL);
		return;
	}

	if (streq(token, "boxid")) {
		boxid_fn(token, value, rdr, NULL);
		return;
	}
  if (!strcmp(token, "fix9993")) {
    rdr->fix_9993 = strToIntVal(value, 0);
    return;
  }

	if (streq(token, "rsakey")) {
		rsakey_fn(token, value, rdr, NULL);
		return;
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

	if (streq(token, "ecmwhitelist")) {
		ecmwhitelist_fn(token, value, rdr, NULL);
		return;
	}

	if (streq(token, "ecmheaderwhitelist")) {
		ecmheaderwhitelist_fn(token, value, rdr, NULL);
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

	if (streq(token, "protocol")) {
		protocol_fn(token, value, rdr, NULL);
		return;
	}

#ifdef WITH_COOLAPI
	if (!strcmp(token, "cool_timeout_init")) {
		rdr->cool_timeout_init  = strToIntVal(value, 50);
		return;
	}
	if (!strcmp(token, "cool_timeout_after_init")) {
		rdr->cool_timeout_after_init  = strToIntVal(value, 150);
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

	if (streq(token, "blockemm-unknown")) {
		flags_fn(token, value, &rdr->blockemm, EMM_UNKNOWN, NULL);
		return;
	}

	if (streq(token, "blockemm-u")) {
		flags_fn(token, value, &rdr->blockemm, EMM_UNIQUE, NULL);
		return;
	}

	if (streq(token, "blockemm-s")) {
		flags_fn(token, value, &rdr->blockemm, EMM_SHARED, NULL);
		return;
	}

	if (streq(token, "blockemm-g")) {
		flags_fn(token, value, &rdr->blockemm, EMM_GLOBAL, NULL);
		return;
	}

	if (streq(token, "saveemm-unknown")) {
		flags_fn(token, value, &rdr->saveemm, EMM_UNKNOWN, NULL);
		return;
	}

	if (streq(token, "saveemm-u")) {
		flags_fn(token, value, &rdr->saveemm, EMM_UNIQUE, NULL);
		return;
	}

	if (streq(token, "saveemm-s")) {
		flags_fn(token, value, &rdr->saveemm, EMM_SHARED, NULL);
		return;
	}

	if (streq(token, "saveemm-g")) {
		flags_fn(token, value, &rdr->saveemm, EMM_GLOBAL, NULL);
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

	if (!strcmp(token, "cccmaxhops")) {
		// cccam max card distance
		rdr->cc_maxhops = strToIntVal(value, DEFAULT_CC_MAXHOPS);
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

	if (!strcmp(token, "cccreshare")) {
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
		rdr->azbox_mode = strToIntVal(value, -1);
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
			for (i = 0; i < MAXECMRATELIMIT; i++) { // reset all slots
				rdr->rlecmh[i].srvid = -1;
				rdr->rlecmh[i].last = -1;
			}
			return;
		}
	}
	if (!strcmp(token, "ratelimitseconds")) {
		if (strlen(value) == 0) {
			if (rdr->ratelimitecm > 0) {
				rdr->ratelimitseconds = 10;
			} else {
				rdr->ratelimitecm = 0; // in case someone set a negative value
				rdr->ratelimitseconds = 0;
			}
			return;
		} else {
			rdr->ratelimitseconds = atoi(value);
			return;
		}
	}

	// cooldown for readout of oscam.server file
	if (!strcmp(token, "cooldown")) {
		if(strlen(value) == 0) {
			rdr->cooldown[0] = 0;
			rdr->cooldown[1] = 0;
			return;
		} else {
			for (i = 0, ptr = strtok_r(value, ",", &saveptr1); (i < 2) && (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++) {
				rdr->cooldown[i] = atoi(ptr);
/*				switch(i) {
				case 0:
					rdr->cooldown[0] = atoi(ptr);
					break;

				case 1:
					rdr->cooldown[1] = atoi(ptr);
					break;
				}
*/			}

			if (rdr->cooldown[0] <= 0 || rdr->cooldown[1] <= 0) {
				fprintf(stderr, "cooldown must have 2 positive values (x,y) set values %d,%d ! cooldown deactivated\n",
						rdr->cooldown[0], rdr->cooldown[1]);

				rdr->cooldown[0] = 0;
				rdr->cooldown[1] = 0;
			}

		}
		return;
	}

	// cooldown setting loading for web interface
	if (!strcmp(token, "cooldowndelay")) {
		if (strlen(value) == 0) {
			rdr->cooldown[0] = 0;
			return;
		} else {
			rdr->cooldown[0] = atoi(value);
			return;
		}
	}
	if (!strcmp(token, "cooldowntime")) {
		if (strlen(value) == 0) {
			rdr->cooldown[0] = 0; // no cooling down time means no cooling set
			rdr->cooldown[1] = 0;
			return;
		} else {
			rdr->cooldown[1] = atoi(value);
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


void reader_set_defaults(struct s_reader *rdr) {
	int i;
	rdr->enable = 1;
	rdr->tcp_rto = DEFAULT_TCP_RECONNECT_TIMEOUT;
	rdr->tcp_ito = DEFAULT_INACTIVITYTIMEOUT;
	rdr->mhz = 357;
	rdr->cardmhz = 357;
#ifdef WITH_AZBOX
	rdr->azbox_mode = -1;
#endif
#ifdef MODULE_CCCAM
	rdr->cc_reshare = DEFAULT_CC_RESHARE;
	rdr->cc_maxhops = DEFAULT_CC_MAXHOPS;
	rdr->cc_reconnect = DEFAULT_CC_RECONNECT;
#endif
#ifdef WITH_LB
	rdr->lb_weight = 100;
#endif
#ifdef CS_CACHEEX
	rdr->cacheex.allow_request = 1;
#endif
	cs_strncpy(rdr->pincode, "none", sizeof(rdr->pincode));
	for (i=1; i<CS_MAXCAIDTAB; rdr->ctab.mask[i++]=0xffff);
}

int32_t init_readerdb(void)
{
	configured_readers = ll_create("configured_readers");

	FILE *fp = open_config_file(cs_srvr);
	if (!fp)
		return 1;

	int32_t tag = 0;
	char *value, *token;

	if (!cs_malloc(&token, MAXLINESIZE))
		return 1;

	struct s_reader *rdr;
	if (!cs_malloc(&rdr, sizeof(struct s_reader))) {
		free(token);
		return 1;
	}

	ll_append(configured_readers, rdr);
	while (fgets(token, MAXLINESIZE, fp)) {
		int32_t l;
		if ((l = strlen(trim(token))) < 3)
			continue;
		if ((token[0] == '[') && (token[l-1] == ']')) {
			token[l-1] = 0;
			tag = (!strcmp("reader", strtolower(token+1)));
			if (rdr->label[0] && rdr->typ) {
				struct s_reader *newreader;
				if (cs_malloc(&newreader, sizeof(struct s_reader))) {
					ll_append(configured_readers, newreader);
					rdr = newreader;
				}
			}
			reader_set_defaults(rdr);
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
		if (is_cascading_reader(rdr)) {
			for (i=0; i<CS_MAX_MOD; i++) {
				if (modules[i].num && rdr->typ==modules[i].num) {
					rdr->ph=modules[i];
					if(rdr->device[0]) rdr->ph.active=1;
				}
			}
		}
	}
	fclose(fp);
	return(0);
}

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

	struct s_ecmHeaderwhitelist *tmp1;
	for(tmp1 = rdr->ecmHeaderwhitelist; tmp1; tmp1=tmp1->next){
		add_garbage(tmp1);
	}
	rdr->ecmHeaderwhitelist = NULL;

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

int32_t write_server(void)
{
	int32_t j;
	char *value;
	FILE *f = create_config_file(cs_srvr);
	if (!f)
		return 1;

	struct s_reader *rdr;
	LL_ITER itr = ll_iter_create(configured_readers);
	while((rdr = ll_iter_next(&itr))) {
		if ( rdr->label[0]) {
			int32_t isphysical = !is_network_reader(rdr);

			fprintf(f,"[reader]\n");

			fprintf_conf(f, "label", "%s\n", rdr->label);

#ifdef WEBIF
			if (rdr->description || cfg.http_full_cfg)
				fprintf_conf(f, "description", "%s\n", rdr->description?rdr->description:"");
#endif

			if (rdr->enable == 0 || cfg.http_full_cfg)
				fprintf_conf(f, "enable", "%d\n", rdr->enable);

			protocol_fn("protocol", NULL, rdr, f);
			device_fn("device", NULL, rdr, f);
			key_fn("key", NULL, rdr, f);

			if ((rdr->r_usr[0] || cfg.http_full_cfg) && !isphysical)
				fprintf_conf(f, "user", "%s\n", rdr->r_usr);

			if (strlen(rdr->r_pwd) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "password", "%s\n", rdr->r_pwd);

			if(strcmp(rdr->pincode, "none") || cfg.http_full_cfg)
				fprintf_conf(f, "pincode", "%s\n", rdr->pincode);

			if ((rdr->emmfile || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "readnano", "%s\n", rdr->emmfile?rdr->emmfile:"");

			services_fn("services", NULL, rdr, f);

			if ((rdr->tcp_ito != DEFAULT_INACTIVITYTIMEOUT || cfg.http_full_cfg) && !isphysical)
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
			if (rdr->cacheex.mode || cfg.http_full_cfg)
				fprintf_conf(f, "cacheex", "%d\n", rdr->cacheex.mode);

			if (rdr->cacheex.maxhop || cfg.http_full_cfg)
				fprintf_conf(f, "cacheex_maxhop", "%d\n", rdr->cacheex.maxhop);

			cacheex_ecm_filter_fn("cacheex_ecm_filter", NULL, rdr, f);

			if (!rdr->cacheex.allow_request || cfg.http_full_cfg)
							fprintf_conf(f, "cacheex_allow_request", "%d\n", rdr->cacheex.allow_request);

			if (rdr->cacheex.drop_csp || cfg.http_full_cfg)
							fprintf_conf(f, "cacheex_drop_csp", "%d\n", rdr->cacheex.drop_csp);
#endif

#ifdef WITH_COOLAPI
			if (rdr->cool_timeout_init != 50 || cfg.http_full_cfg)
				fprintf_conf(f, "cool_timeout_init", "%d\n", rdr->cool_timeout_init);
			if (rdr->cool_timeout_after_init != 150 || cfg.http_full_cfg)
				fprintf_conf(f, "cool_timeout_after_init", "%d\n", rdr->cool_timeout_after_init);
#endif
			if (rdr->log_port || cfg.http_full_cfg)
				fprintf_conf(f, "logport", "%d\n", rdr->log_port);

			caid_fn("caid", NULL, rdr, f);

			boxid_fn("boxid", NULL, rdr, f);

			if((rdr->fix_9993 || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "fix9993", "%d\n", rdr->fix_9993);

			rsakey_fn("rsakey", NULL, rdr, f);

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

			int32_t len = check_filled(rdr->nagra_boxkey, 8);
			if ((len > 0 || cfg.http_full_cfg) && isphysical){
				char tmp[17];
				fprintf_conf(f, "boxkey", "%s\n", len>0?cs_hexdump(0, rdr->nagra_boxkey, 8, tmp, sizeof(tmp)):"");
			}

			if ((rdr->atr[0] || cfg.http_full_cfg) && isphysical) {
				fprintf_conf(f, "atr", "%s", ""); // it should not have \n at the end
				if(rdr->atr[0]){
					for (j=0; j < rdr->atrlen/2; j++) {
						fprintf(f, "%02X", rdr->atr[j]);
					}
				}
				fprintf(f, "\n");
			}

			ecmwhitelist_fn("ecmwhitelist", NULL, rdr, f);
			ecmheaderwhitelist_fn("ecmheaderwhitelist", NULL, rdr, f);

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
			if ((rdr->azbox_mode != -1 || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "mode", "%d\n", rdr->azbox_mode);
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

			flags_fn("blockemm-unknown", NULL, &rdr->blockemm, EMM_UNKNOWN, f);
			flags_fn("blockemm-u"      , NULL, &rdr->blockemm, EMM_UNIQUE, f);
			flags_fn("blockemm-s"      , NULL, &rdr->blockemm, EMM_SHARED, f);
			flags_fn("blockemm-g"      , NULL, &rdr->blockemm, EMM_GLOBAL, f);

			flags_fn("saveemm-unknown" , NULL, &rdr->saveemm, EMM_UNKNOWN, f);
			flags_fn("saveemm-u"       , NULL, &rdr->saveemm, EMM_UNIQUE, f);
			flags_fn("saveemm-s"       , NULL, &rdr->saveemm, EMM_SHARED, f);
			flags_fn("saveemm-g"       , NULL, &rdr->saveemm, EMM_GLOBAL, f);

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

				if (rdr->cc_maxhops != DEFAULT_CC_MAXHOPS || cfg.http_full_cfg)
					fprintf_conf(f, "cccmaxhops", "%d\n", rdr->cc_maxhops);

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

	return flush_config_file(f, cs_srvr);
}
