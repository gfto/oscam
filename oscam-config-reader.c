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
#include "oscam-config.h"
#include "oscam-garbage.h"
#include "oscam-lock.h"
#include "oscam-reader.h"
#include "oscam-string.h"

#define cs_srvr "oscam.server"

extern struct s_module modules[CS_MAX_MOD];
extern struct s_cardreader cardreaders[CS_MAX_MOD];

static void reader_label_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_reader *rdr = setting;
	if (value) {
		int i, found = 0;
		if (!strlen(value))
			return;
		for (i = 0; i < (int)strlen(value); i++) {
			if (value[i] == ' ') {
				value[i] = '_';
				found++;
			}
		}
		if (found)
			fprintf(stderr, "Configuration reader: corrected label to %s\n", value);
		cs_strncpy(rdr->label, value, sizeof(rdr->label));
		return;
	}
	fprintf_conf(f, token, "%s\n", rdr->label);
}

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
		if (!buf)
			return;

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
		if (strlen(value) == 0)
			return;
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

static void services_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_reader *rdr = setting;
	if (value) {
		if (strlen(value)) {
			strtolower(value);
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
	if (rdr->boxid)
		fprintf_conf(f, token, "%08X\n", rdr->boxid);
	else if (cfg.http_full_cfg)
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
	int32_t len = check_filled(rdr->rsa_mod, 120);
	if (len > 0) {
		if(len > 64) len = 120;
		else len = 64;
		char tmp[len*2+1];
		fprintf_conf(f, "rsakey", "%s\n", cs_hexdump(0, rdr->rsa_mod, len, tmp, sizeof(tmp)));
	} else if(cfg.http_full_cfg)
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

static void ins7E_fn(const char *token, char *value, void *setting, long var_size, FILE *f) {
	uint8_t *var = setting;
	var_size -= 1; // var_size contains sizeof(var) which is [X + 1]
	if (value) {
		int32_t len = strlen(value);
		if (len != var_size * 2 || key_atob_l(value, var, len)) {
			if (len > 0)
				fprintf(stderr, "reader %s parse error, %s=%s\n", token, token, value);
			memset(var, 0, var_size + 1);
		} else {
			var[var_size] = 1; // found and correct
		}
		return;
	}
	if (var[var_size]) {
		char tmp[var_size * 2 + 1];
		fprintf_conf(f, token, "%s\n", cs_hexdump(0, var, var_size, tmp, sizeof(tmp)));
	} else if (cfg.http_full_cfg)
		fprintf_conf(f, token, "\n");
}

static void atr_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_reader *rdr = setting;
	if (value) {
		memset(rdr->atr, 0, sizeof(rdr->atr));
		rdr->atrlen = strlen(value);
		if (rdr->atrlen) {
			if (rdr->atrlen > (int32_t)sizeof(rdr->atr) * 2)
				rdr->atrlen = (int32_t)sizeof(rdr->atr) * 2;
			key_atob_l(value, rdr->atr, rdr->atrlen);
		}
		return;
	}
	if (rdr->atr[0] || cfg.http_full_cfg) {
		int j;
		fprintf_conf(f, token, "%s", ""); // it should not have \n at the end
		if (rdr->atr[0]) {
			for (j = 0; j < rdr->atrlen / 2; j++) {
				fprintf(f, "%02X", rdr->atr[j]);
			}
		}
		fprintf(f, "\n");
	}
}

static void detect_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_reader *rdr = setting;
	if (value) {
		int i;
		for (i = 0; RDR_CD_TXT[i]; i++) {
			if (!strcmp(value, RDR_CD_TXT[i])) {
				rdr->detect = i;
			} else {
				if (value[0] == '!' && streq(value + 1, RDR_CD_TXT[i]))
					rdr->detect = i | 0x80;
			}
		}
		return;
	}
	fprintf_conf(f, token, "%s%s\n", rdr->detect & 0x80 ? "!" : "", RDR_CD_TXT[rdr->detect & 0x7f]);
}

static void ident_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_reader *rdr = setting;
	if (value) {
		if (strlen(value)) {
			strtolower(value);
			chk_ftab(value, &rdr->ftab, "reader", rdr->label, "provid");
		} else {
			clear_ftab(&rdr->ftab);
		}
		rdr->changes_since_shareupdate = 1;
		return;
	}
	value = mk_t_ftab(&rdr->ftab);
	if (strlen(value) > 0 || cfg.http_full_cfg)
		fprintf_conf(f, token, "%s\n", value);
	free_mk_t(value);
}

static void chid_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_reader *rdr = setting;
	if (value) {
		strtolower(value);
		chk_ftab(value, &rdr->fchid, "reader", rdr->label, "chid");
		rdr->changes_since_shareupdate = 1;
		return;
	}
	value = mk_t_ftab(&rdr->fchid);
	if (strlen(value) > 0 || cfg.http_full_cfg)
		fprintf_conf(f, token, "%s\n", value);
	free_mk_t(value);
}

static void aeskeys_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_reader *rdr = setting;
	if (value) {
		parse_aes_keys(rdr,value);
		return;
	}
	value = mk_t_aeskeys(rdr);
	if (strlen(value) > 0 || cfg.http_full_cfg)
		fprintf_conf(f, token, "%s\n", value);
	free_mk_t(value);
}

static void group_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_reader *rdr = setting;
	if (value) {
		char *ptr, *saveptr1 = NULL;
		rdr->grp = 0;
		for (ptr = strtok_r(value, ",", &saveptr1); ptr; ptr = strtok_r(NULL, ",", &saveptr1)) {
			int32_t g;
			g = atoi(ptr);
			if (g > 0 && g < 65) {
				rdr->grp |= (((uint64_t)1)<<(g-1));
			}
		}
		return;
	}
	value = mk_t_group(rdr->grp);
	if (strlen(value) > 0 || cfg.http_full_cfg)
		fprintf_conf(f, token, "%s\n", value);
	free_mk_t(value);
}

static void emmcache_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_reader *rdr = setting;
	if (value) {
		rdr->cachemm   = 0;
		rdr->rewritemm = 0;
		rdr->logemm    = 0;
		if (strlen(value)) {
			int i;
			char *ptr, *saveptr1 = NULL;
			for (i = 0, ptr = strtok_r(value, ",", &saveptr1); (i < 3) && (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++) {
				switch(i) {
				case 0: rdr->cachemm = atoi(ptr);   break;
				case 1: rdr->rewritemm = atoi(ptr); break;
				case 2: rdr->logemm = atoi(ptr);    break;
				}
			}
			if (rdr->rewritemm <= 0) {
				fprintf(stderr, "Setting reader \"emmcache\" to %i,%d,%i instead of %i,%i,%i.",
						rdr->cachemm, 1, rdr->logemm,
						rdr->cachemm, rdr->rewritemm, rdr->logemm);
				fprintf(stderr, "Zero or negative number of rewrites is silly\n");
				rdr->rewritemm = 1;
			}
		}
		return;
	}
	if (rdr->cachemm || cfg.http_full_cfg)
		fprintf_conf(f, token, "%d,%d,%d\n", rdr->cachemm, rdr->rewritemm, rdr->logemm);
}

static void blockemm_bylen_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_reader *rdr = setting;
	if (value) {
		int32_t i;
		char *ptr, *saveptr1 = NULL;
		for (i = 0; i < CS_MAXEMMBLOCKBYLEN; i++)
			rdr->blockemmbylen[i] = 0;
		for (i = 0, ptr = strtok_r(value, ",", &saveptr1); (i < CS_MAXEMMBLOCKBYLEN) && (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++)
			rdr->blockemmbylen[i] = atoi(ptr);
		return;
	}
	value = mk_t_emmbylen(rdr);
	if (strlen(value) > 0 || cfg.http_full_cfg)
		fprintf_conf(f, token, "%s\n", value);
	free_mk_t(value);
}

static void nano_fn(const char *token, char *value, void *setting, FILE *f) {
	uint16_t *nano = setting;
	if (value) {
		*nano = 0;
		if (strlen(value) > 0) {
			if (streq(value, "all")) {
				*nano = 0xFFFF;
			} else {
				int32_t i;
				char *ptr, *saveptr1 = NULL;
				for (ptr = strtok_r(value, ",", &saveptr1); ptr; ptr = strtok_r(NULL, ",", &saveptr1)) {
					i = (byte_atob(ptr) % 0x80);
					if (i >= 0 && i <= 16)
						*nano |= (1 << i);
				}
			}
		}
		return;
	}
	value = mk_t_nano(*nano);
	if (strlen(value) > 0 || cfg.http_full_cfg)
		fprintf_conf(f, token, "%s\n", value);
	free_mk_t(value);
}

static void boxkey_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_reader *rdr = setting;
	if (value) {
		if (strlen(value) != 16) {
			memset(rdr->nagra_boxkey, 0, 16);
		} else {
			if (key_atob_l(value, rdr->nagra_boxkey, 16)) {
				fprintf(stderr, "Configuration reader: Error in boxkey\n");
				memset(rdr->nagra_boxkey, 0, sizeof(rdr->nagra_boxkey));
			}
		}
		return;
	}
	int32_t len = check_filled(rdr->nagra_boxkey, 8);
	if (len > 0 || cfg.http_full_cfg) {
		char tmp[17];
		fprintf_conf(f, token, "%s\n", len > 0 ?
			cs_hexdump(0, rdr->nagra_boxkey, 8, tmp, sizeof(tmp)) : "");
	}
}

static void auprovid_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_reader *rdr = setting;
	if (value) {
		rdr->auprovid = 0;
		if (strlen(value))
			rdr->auprovid = a2i(value, 3);
		return;
	}
	if (rdr->auprovid)
		fprintf_conf(f, token, "%06X\n", rdr->auprovid);
	else if (cfg.http_full_cfg)
		fprintf_conf(f, token, "\n");
}

static void ratelimitecm_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_reader *rdr = setting;
	if (value) {
		rdr->ratelimitecm = 0;
		if (strlen(value)) {
			int i;
			rdr->ratelimitecm = atoi(value);
			for (i = 0; i < MAXECMRATELIMIT; i++) { // reset all slots
				rdr->rlecmh[i].srvid = -1;
				rdr->rlecmh[i].last = -1;
			}
		}
		return;
	}
	if (rdr->ratelimitecm || cfg.http_full_cfg)
		fprintf_conf(f, token, "%d\n", rdr->ratelimitecm);
}

static void ratelimitseconds_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_reader *rdr = setting;
	if (value) {
		if (strlen(value) == 0) {
			if (rdr->ratelimitecm > 0) {
				rdr->ratelimitseconds = 10;
			} else {
				rdr->ratelimitecm = 0; // in case someone set a negative value
				rdr->ratelimitseconds = 0;
			}
		} else {
			rdr->ratelimitseconds = atoi(value);
		}
		return;
	}
	if (rdr->ratelimitecm || cfg.http_full_cfg)
		fprintf_conf(f, token, "%d\n", rdr->ratelimitseconds);
}

static void cooldown_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_reader *rdr = setting;
	if (value) {
		if(strlen(value) == 0) {
			rdr->cooldown[0] = 0;
			rdr->cooldown[1] = 0;
		} else {
			int32_t i;
			char *ptr, *saveptr1 = NULL;
			for (i = 0, ptr = strtok_r(value, ",", &saveptr1); (i < 2) && (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++) {
				rdr->cooldown[i] = atoi(ptr);
			}
			if (rdr->cooldown[0] <= 0 || rdr->cooldown[1] <= 0) {
				fprintf(stderr, "cooldown must have 2 positive values (x,y) set values %d,%d ! cooldown deactivated\n",
						rdr->cooldown[0], rdr->cooldown[1]);
				rdr->cooldown[0] = 0;
				rdr->cooldown[1] = 0;
			}
		}
		return;
	}
	if (rdr->cooldown[0] || cfg.http_full_cfg) {
		fprintf_conf(f, token, "%d,%d\n", rdr->cooldown[0], rdr->cooldown[1]);
	}
}

static void cooldowndelay_fn(const char *UNUSED(token), char *value, void *setting, FILE *UNUSED(f)) {
	struct s_reader *rdr = setting;
	if (value) {
		rdr->cooldown[0] = strlen(value) ? atoi(value) : 0;
	}
	// This option is *not* written in the config file.
	// It is only set by WebIf as convenience
}

static void cooldowntime_fn(const char *UNUSED(token), char *value, void *setting, FILE *UNUSED(f)) {
	struct s_reader *rdr = setting;
	if (value) {
		if (strlen(value) == 0) {
			rdr->cooldown[0] = 0; // no cooling down time means no cooling set
			rdr->cooldown[1] = 0;
		} else {
			rdr->cooldown[1] = atoi(value);
		}
		return;
	}
	// This option is *not* written in the config file.
	// It is only set by WebIf as convenience
}

#ifdef WITH_LB
static void reader_fixups_fn(void *var) {
	struct s_reader *rdr = var;
	if (rdr->lb_weight > 1000)
		rdr->lb_weight = 1000;
	else if (rdr->lb_weight <= 0)
		rdr->lb_weight = 100;
}
#endif

#define OFS(X) offsetof(struct s_reader, X)
#define SIZEOF(X) sizeof(((struct s_reader *)0)->X)

static const struct config_list reader_opts[] = {
#ifdef WITH_LB
	DEF_OPT_FIXUP_FUNC(reader_fixups_fn),
#endif
	DEF_OPT_FUNC("label"				, 0,							reader_label_fn ),
#ifdef WEBIF
	DEF_OPT_STR("description"			, OFS(description),				NULL ),
#endif
	DEF_OPT_INT8("enable"				, OFS(enable),					1 ),
	DEF_OPT_FUNC("protocol"				, 0,							protocol_fn ),
	DEF_OPT_FUNC("device"				, 0,							device_fn ),
	DEF_OPT_FUNC("key"					, OFS(ncd_key),					newcamd_key_fn ),
	DEF_OPT_SSTR("user"					, OFS(r_usr),					"", SIZEOF(r_usr) ),
	DEF_OPT_SSTR("password"				, OFS(r_pwd),					"", SIZEOF(r_pwd) ),
	DEF_OPT_SSTR("pincode"				, OFS(pincode),					"none", SIZEOF(pincode) ),
	DEF_OPT_FUNC("mg-encrypted"			, 0,							mgencrypted_fn ),
	DEF_OPT_STR("readnano"				, OFS(emmfile),					NULL ),
	DEF_OPT_FUNC("services"				, 0,							services_fn ),
	DEF_OPT_INT32("inactivitytimeout"	, OFS(tcp_ito),					DEFAULT_INACTIVITYTIMEOUT ),
	DEF_OPT_INT32("reconnecttimeout"	, OFS(tcp_rto),					DEFAULT_TCP_RECONNECT_TIMEOUT ),
	DEF_OPT_INT32("resetcycle"			, OFS(resetcycle),				0 ),
	DEF_OPT_INT8("disableserverfilter"	, OFS(ncd_disable_server_filt),	0 ),
	DEF_OPT_INT8("smargopatch"			, OFS(smargopatch),				0 ),
	DEF_OPT_UINT8("sc8in1_dtrrts_patch"	, OFS(sc8in1_dtrrts_patch),		0 ),
	DEF_OPT_INT8("fallback"				, OFS(fallback),				0 ),
#ifdef CS_CACHEEX
	DEF_OPT_INT8("cacheex"				, OFS(cacheex.mode),			0 ),
	DEF_OPT_INT8("cacheex_maxhop"		, OFS(cacheex.maxhop),			0 ),
	DEF_OPT_FUNC("cacheex_ecm_filter"		, OFS(cacheex.filter_caidtab),	hitvaluetab_fn ),
	DEF_OPT_UINT8("cacheex_allow_request"	, OFS(cacheex.allow_request),	1 ),
	DEF_OPT_UINT8("cacheex_drop_csp"		, OFS(cacheex.drop_csp),		0 ),
#endif
#ifdef WITH_COOLAPI
	DEF_OPT_INT32("cool_timeout_init"			, OFS(cool_timeout_init),			50 ),
	DEF_OPT_INT32("cool_timeout_after_init"		, OFS(cool_timeout_after_init),		150 ),
#endif
	DEF_OPT_INT32("logport"				, OFS(log_port),				0 ),
	DEF_OPT_FUNC("caid"					, 0,							caid_fn ),
	DEF_OPT_FUNC("atr"					, 0,							atr_fn ),
	DEF_OPT_FUNC("boxid"				, 0,							boxid_fn ),
	DEF_OPT_FUNC("boxkey"				, 0,							boxkey_fn ),
	DEF_OPT_FUNC("rsakey"				, 0,							rsakey_fn ),
	DEF_OPT_FUNC_X("ins7e"				, OFS(ins7E),					ins7E_fn, SIZEOF(ins7E) ),
	DEF_OPT_FUNC_X("ins7e11"			, OFS(ins7E11),					ins7E_fn, SIZEOF(ins7E11) ),
	DEF_OPT_INT8("fix9993"				, OFS(fix_9993),				0 ),
	DEF_OPT_INT8("force_irdeto"			, OFS(force_irdeto),			0 ),
	DEF_OPT_FUNC("ecmwhitelist"			, 0,							ecmwhitelist_fn ),
	DEF_OPT_FUNC("ecmheaderwhitelist"	, 0,							ecmheaderwhitelist_fn ),
	DEF_OPT_FUNC("detect"				, 0,							detect_fn ),
	DEF_OPT_INT8("nagra_read"			, OFS(nagra_read),				0 ),
	DEF_OPT_INT32("mhz"					, OFS(mhz),						357 ),
	DEF_OPT_INT32("cardmhz"				, OFS(cardmhz),					357 ),
#ifdef WITH_AZBOX
	DEF_OPT_INT32("mode"				, OFS(azbox_mode),				-1 ),
#endif
	DEF_OPT_FUNC("ident"				, 0,							ident_fn ),
	DEF_OPT_FUNC("chid"					, 0,							chid_fn ),
	DEF_OPT_FUNC("class"				, OFS(cltab),					class_fn ),
	DEF_OPT_FUNC("aeskeys"				, 0,							aeskeys_fn ),
	DEF_OPT_FUNC("group"				, 0,							group_fn ),
	DEF_OPT_FUNC("emmcache"				, 0,							emmcache_fn ),
	DEF_OPT_FUNC_X("blockemm-unknown"	, OFS(blockemm),				flags_fn, EMM_UNKNOWN ),
	DEF_OPT_FUNC_X("blockemm-u"			, OFS(blockemm),				flags_fn, EMM_UNIQUE ),
	DEF_OPT_FUNC_X("blockemm-s"			, OFS(blockemm),				flags_fn, EMM_SHARED ),
	DEF_OPT_FUNC_X("blockemm-g"			, OFS(blockemm),				flags_fn, EMM_GLOBAL ),
	DEF_OPT_FUNC_X("saveemm-unknown"	, OFS(saveemm),					flags_fn, EMM_UNKNOWN ),
	DEF_OPT_FUNC_X("saveemm-u"			, OFS(saveemm),					flags_fn, EMM_UNIQUE ),
	DEF_OPT_FUNC_X("saveemm-s"			, OFS(saveemm),					flags_fn, EMM_SHARED ),
	DEF_OPT_FUNC_X("saveemm-g"			, OFS(saveemm),					flags_fn, EMM_GLOBAL ),
	DEF_OPT_FUNC("blockemm-bylen"		, 0,							blockemm_bylen_fn ),
#ifdef WITH_LB
	DEF_OPT_INT32("lb_weight"			, OFS(lb_weight),				100 ),
#endif
	DEF_OPT_FUNC("savenano"				, OFS(s_nano),					nano_fn ),
	DEF_OPT_FUNC("blocknano"			, OFS(b_nano),					nano_fn ),
	DEF_OPT_INT8("dropbadcws"			, OFS(dropbadcws),				0 ),
	DEF_OPT_INT8("disablecrccws"		, OFS(disablecrccws),			0 ),
	DEF_OPT_INT32("use_gpio"			, OFS(use_gpio),				0 ),
#ifdef MODULE_PANDORA
	DEF_OPT_UINT8("pand_send_ecm"		, OFS(pand_send_ecm),			0 ),
#endif
#ifdef MODULE_CCCAM
	DEF_OPT_SSTR("cccversion"			, OFS(cc_version),				"", SIZEOF(cc_version) ),
	DEF_OPT_INT8("cccmaxhops"			, OFS(cc_maxhops),				DEFAULT_CC_MAXHOPS ),
	DEF_OPT_INT8("cccmindown"			, OFS(cc_mindown),				0 ),
	DEF_OPT_INT8("cccwantemu"			, OFS(cc_want_emu),				0 ),
	DEF_OPT_INT8("ccckeepalive"			, OFS(cc_keepalive),			DEFAULT_CC_KEEPALIVE ),
	DEF_OPT_INT8("cccreshare"			, OFS(cc_reshare),				DEFAULT_CC_RESHARE ),
	DEF_OPT_INT32("cccreconnect"		, OFS(cc_reconnect),			DEFAULT_CC_RECONNECT ),
	DEF_OPT_INT8("ccchop"				, OFS(cc_hop),					0 ),
#endif
	DEF_OPT_INT8("deprecated"			, OFS(deprecated),				0 ),
	DEF_OPT_INT8("audisabled"			, OFS(audisabled),				0 ),
	DEF_OPT_FUNC("auprovid"				, 0,							auprovid_fn ),
	DEF_OPT_INT8("ndsversion"			, OFS(ndsversion),				0 ),
	DEF_OPT_FUNC("ratelimitecm"			, 0,							ratelimitecm_fn ),
	DEF_OPT_FUNC("ratelimitseconds"		, 0,							ratelimitseconds_fn ),
	DEF_OPT_FUNC("cooldown"				, 0,							cooldown_fn ),
	DEF_OPT_FUNC("cooldowndelay"		, 0,							cooldowndelay_fn ),
	DEF_OPT_FUNC("cooldowntime"			, 0,							cooldowntime_fn ),
	DEF_LAST_OPT
};

static inline bool in_list(const char *token, const char *list[]) {
	int i;
	for(i = 0; list[i]; i++) {
		if (streq(token, list[i]))
			return true;
	}
	return false;
}

static bool reader_check_setting(const struct config_list *UNUSED(clist), void *config_data, const char *setting)
{
	struct s_reader *reader = config_data;
	// These are written only when the reader is physical reader
	static const char *hw_only_settings[] = {
		"readnano", "resetcycle", "smargopatch", "sc8in1_dtrrts_patch", "boxid",
		"fix9993", "rsakey", "ins7e", "ins7e11", "force_irdeto", "boxkey",
		"atr", "detect", "nagra_read", "mhz", "cardmhz",
#ifdef WITH_AZBOX
		"mode",
#endif
		"deprecated", "ndsversion", "ratelimitecm", "ratelimitseconds",
		"cooldown",
		0
	};
	// These are written only when the reader is network reader
	static const char *network_only_settings[] = {
		"user", "inactivitytimeout", "reconnecttimeout",
		0
	};
	if (is_network_reader(reader)) {
		if (in_list(setting, hw_only_settings))
			return false;
	} else {
		if (in_list(setting, network_only_settings))
			return false;
	}

	// These are not written in the config file
	static const char *deprecated_settings[] = {
		"cooldowndelay", "cooldowntime", "mg-encrypted",
		0
	};
	if (in_list(setting, deprecated_settings))
		return false;

	// Special settings for NEWCAMD
	if (reader->typ != R_NEWCAMD && streq(setting, "disableserverfilter"))
		return false;

#ifdef MODULE_CCCAM
	// These are written only when the reader is CCCAM
	static const char *cccam_settings[] = {
		"cccversion", "cccmaxhops", "cccmindown", "cccwantemu", "ccckeepalive",
		"cccreshare", "cccreconnect",
		0
	};
	// Special settings for CCCAM
	if (reader->typ != R_CCCAM) {
		if (in_list(setting, cccam_settings))
			return false;
	} else if (streq(setting, "ccchop")) {
		return false;
	}
#endif

#ifdef MODULE_PANDORA
	// Special settings for PANDORA
	if (reader->typ != R_PANDORA && streq(setting, "pand_send_ecm"))
		return false;
#endif

	return true; // Write the setting
}


void chk_reader(char *token, char *value, struct s_reader *rdr)
{
	if (config_list_parse(reader_opts, token, value, rdr))
		return;
	else if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in reader section not recognized\n", token);
}

void reader_set_defaults(struct s_reader *rdr) {
	config_list_set_defaults(reader_opts, rdr);
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
	FILE *f = create_config_file(cs_srvr);
	if (!f)
		return 1;
	struct s_reader *rdr;
	LL_ITER itr = ll_iter_create(configured_readers);
	while((rdr = ll_iter_next(&itr))) {
		if (rdr->label[0]) {
			fprintf(f,"[reader]\n");
			config_list_apply_fixups(reader_opts, rdr);
			config_list_save_ex(f, reader_opts, rdr, cfg.http_full_cfg, reader_check_setting);
			fprintf(f, "\n");
		}
	}
	return flush_config_file(f, cs_srvr);
}
