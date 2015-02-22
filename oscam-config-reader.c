#define MODULE_LOG_PREFIX "config"

#include "globals.h"
#include "module-gbox.h"
#include "module-stat.h"
#include "oscam-aes.h"
#include "oscam-array.h"
#include "oscam-conf.h"
#include "oscam-conf-chk.h"
#include "oscam-conf-mk.h"
#include "oscam-config.h"
#include "oscam-garbage.h"
#include "oscam-lock.h"
#include "oscam-reader.h"
#include "oscam-string.h"

#define cs_srvr "oscam.server"

extern const struct s_cardreader *cardreaders[];
extern char *RDR_CD_TXT[];

static void reader_label_fn(const char *token, char *value, void *setting, FILE *f)
{
	struct s_reader *rdr = setting;
	if(value)
	{
		int i, found = 0;
		if(!strlen(value))
			{ return; }
		for(i = 0; i < (int)strlen(value); i++)
		{
			if(value[i] == ' ')
			{
				value[i] = '_';
				found++;
			}
		}
		if(found)
			{ fprintf(stderr, "Configuration reader: corrected label to %s\n", value); }
		cs_strncpy(rdr->label, value, sizeof(rdr->label));
		return;
	}
	fprintf_conf(f, token, "%s\n", rdr->label);
}

static void ecmwhitelist_fn(const char *token, char *value, void *setting, FILE *f)
{
	struct s_reader *rdr = setting;
	if(value)
	{
		if(strlen(value))
			chk_ecm_whitelist(value, &rdr->ecm_whitelist);
		else
			ecm_whitelist_clear(&rdr->ecm_whitelist);
		return;
	}

	value = mk_t_ecm_whitelist(&rdr->ecm_whitelist);
	if(strlen(value) > 0 || cfg.http_full_cfg)
		{ fprintf_conf(f, token, "%s\n", value); }
	free_mk_t(value);
}

static void ecmheaderwhitelist_fn(const char *token, char *value, void *setting, FILE *f)
{
	struct s_reader *rdr = setting;
	if(value)
	{
		if(strlen(value))
			chk_ecm_hdr_whitelist(value, &rdr->ecm_hdr_whitelist);
		else
			ecm_hdr_whitelist_clear(&rdr->ecm_hdr_whitelist);
		return;
	}

	value = mk_t_ecm_hdr_whitelist(&rdr->ecm_hdr_whitelist);
	if(strlen(value) > 0 || cfg.http_full_cfg)
		{ fprintf_conf(f, token, "%s\n", value); }
	free_mk_t(value);
}

static void protocol_fn(const char *token, char *value, void *setting, FILE *f)
{
	struct s_reader *rdr = setting;
	if(value)
	{
		if(strlen(value) == 0)
			{ return; }
		struct protocol_map
		{
			char *name;
			int typ;
		} protocols[] =
		{
			{ "serial",     R_SERIAL },
			{ "camd35",     R_CAMD35 },
			{ "cs378x",     R_CS378X },
			{ "cs357x",     R_CAMD35 },
			{ "camd33",     R_CAMD33 },
			{ "gbox",       R_GBOX },
			{ "cccam",      R_CCCAM },
			{ "cccam_ext",  R_CCCAM },
			{ "constcw",    R_CONSTCW },
			{ "radegast",   R_RADEGAST },
			{ "scam",       R_SCAM },
			{ "ghttp",      R_GHTTP },
			{ "newcamd",    R_NEWCAMD },
			{ "newcamd525", R_NEWCAMD },
			{ "newcamd524", R_NEWCAMD },
			{ NULL        , 0 }
		}, *p;
		int i;
		// Parse card readers
		for(i = 0; cardreaders[i]; i++)
		{
			if(streq(value, cardreaders[i]->desc))
			{
				rdr->crdr = cardreaders[i];
				rdr->typ  = cardreaders[i]->typ;
				return;
			}
		}
		// Parse protocols
		for(i = 0, p = &protocols[0]; p->name; p = &protocols[++i])
		{
			if(streq(p->name, value))
			{
				rdr->typ = p->typ;
				break;
			}
		}
		if(rdr->typ == R_NEWCAMD)
			{ rdr->ncd_proto = streq(value, "newcamd524") ? NCD_524 : NCD_525; }
		if(!rdr->typ)
			{
				fprintf(stderr, "ERROR: '%s' is unsupported reader protocol!\n", value);
				rdr->enable = 0;
			}
		return;
	}
	fprintf_conf(f, token, "%s\n", reader_get_type_desc(rdr, 0));
}

static void device_fn(const char *token, char *value, void *setting, FILE *f)
{
	struct s_reader *rdr = setting;
	int32_t isphysical = !is_network_reader(rdr);
	if(value)
	{
		int32_t i;
		char *ptr, *saveptr1 = NULL;
		for(i = 0, ptr = strtok_r(value, ",", &saveptr1); (i < 3) && (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++)
		{
			trim(ptr);
			switch(i)
			{
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
	if((rdr->r_port || cfg.http_full_cfg) && !isphysical)
		{ fprintf(f, ",%d", rdr->r_port); }
	if((rdr->l_port || cfg.http_full_cfg) && !isphysical && strncmp(reader_get_type_desc(rdr, 0), "cccam", 5))
		{ fprintf(f, ",%d", rdr->l_port); }
	fprintf(f, "\n");
}

static void reader_services_fn(const char *token, char *value, void *setting, FILE *f)
{
	services_fn(token, value, setting, f);
	if(value)
	{
		struct s_reader *rdr = container_of(setting, struct s_reader, sidtabs);
		if(rdr)
			{ rdr->changes_since_shareupdate = 1; }
	}
}

static void reader_lb_services_fn(const char *token, char *value, void *setting, FILE *f)
{
	services_fn(token, value, setting, f);
	if(value)
	{
		struct s_reader *rdr = container_of(setting, struct s_reader, lb_sidtabs);
		if(rdr)
			{ rdr->changes_since_shareupdate = 1; }
	}
}

static void reader_caid_fn(const char *token, char *value, void *setting, FILE *f)
{
	check_caidtab_fn(token, value, setting, f);
	if(value)
	{
		struct s_reader *rdr = container_of(setting, struct s_reader, ctab);
		if(rdr)
			{ rdr->changes_since_shareupdate = 1; }
	}
}

static void boxid_fn(const char *token, char *value, void *setting, FILE *f)
{
	struct s_reader *rdr = setting;
	if(value)
	{
		rdr->boxid = strlen(value) ? a2i(value, 4) : 0;
		return;
	}
	if(rdr->boxid)
		{ fprintf_conf(f, token, "%08X\n", rdr->boxid); }
	else if(cfg.http_full_cfg)
		{ fprintf_conf(f, token, "\n"); }
}

static void rsakey_fn(const char *token, char *value, void *setting, FILE *f)
{
	struct s_reader *rdr = setting;
	if(value)
	{
		int32_t len = strlen(value);
		if(len != 128 && len != 240)
		{
			memset(rdr->rsa_mod, 0, 120);
		}
		else
		{
			if(key_atob_l(value, rdr->rsa_mod, len))
			{
				fprintf(stderr, "reader rsakey parse error, %s=%s\n", token, value);
				memset(rdr->rsa_mod, 0, sizeof(rdr->rsa_mod));
			}
		}
		return;
	}
	int32_t len = check_filled(rdr->rsa_mod, 120);
	if(len > 0)
	{
		if(len > 64) { len = 120; }
		else { len = 64; }
		char tmp[len * 2 + 1];
		fprintf_conf(f, "rsakey", "%s\n", cs_hexdump(0, rdr->rsa_mod, len, tmp, sizeof(tmp)));
	}
	else if(cfg.http_full_cfg)
		{ fprintf_conf(f, "rsakey", "\n"); }
}

static void boxkey_fn(const char *token, char *value, void *setting, FILE *f)
{
	struct s_reader *rdr = setting;
	if(value)
	{
		int32_t len = strlen(value);
		if(len != 16 && len != 32)
		{
			memset(rdr->boxkey, 0, sizeof(rdr->boxkey));
		}
		else
		{
			if(key_atob_l(value, rdr->boxkey, len))
			{
				fprintf(stderr, "reader boxkey parse error, %s=%s\n", token, value);
				memset(rdr->boxkey, 0, sizeof(rdr->boxkey));
			}
		}
		return;
	}
	int32_t len = check_filled(rdr->boxkey, sizeof(rdr->boxkey));
	if(len > 0)
	{
		if(len > 8) { len = 16; }
		else { len = 8; }
		char tmp[len * 2 + 1];
		fprintf_conf(f, "boxkey", "%s\n", cs_hexdump(0, rdr->boxkey, len, tmp, sizeof(tmp)));
	}
	else if(cfg.http_full_cfg)
		{ fprintf_conf(f, "boxkey", "\n"); }
}

static void flags_fn(const char *token, char *value, void *setting, long flag, FILE *f)
{
	uint32_t *var = setting;
	if(value)
	{
		int i = atoi(value);
		if(!i && (*var & flag))
			{ *var -= flag; }
		if(i)
			{ *var |= flag; }
		return;
	}
	if((*var & flag) || cfg.http_full_cfg)
		{ fprintf_conf(f, token, "%d\n", (*var & flag) ? 1 : 0); }
}

static void ins7E_fn(const char *token, char *value, void *setting, long var_size, FILE *f)
{
	uint8_t *var = setting;
	var_size -= 1; // var_size contains sizeof(var) which is [X + 1]
	if(value)
	{
		int32_t len = strlen(value);
		if(len != var_size * 2 || key_atob_l(value, var, len))
		{
			if(len > 0)
				{ fprintf(stderr, "reader %s parse error, %s=%s\n", token, token, value); }
			memset(var, 0, var_size + 1);
		}
		else
		{
			var[var_size] = 1; // found and correct
		}
		return;
	}
	if(var[var_size])
	{
		char tmp[var_size * 2 + 1];
		fprintf_conf(f, token, "%s\n", cs_hexdump(0, var, var_size, tmp, sizeof(tmp)));
	}
	else if(cfg.http_full_cfg)
		{ fprintf_conf(f, token, "\n"); }
}

static void atr_fn(const char *token, char *value, void *setting, FILE *f)
{
	struct s_reader *rdr = setting;
	if(value)
	{
		memset(rdr->atr, 0, sizeof(rdr->atr));
		rdr->atrlen = strlen(value);
		if(rdr->atrlen)
		{
			if(rdr->atrlen > (int32_t)sizeof(rdr->atr) * 2)
				{ rdr->atrlen = (int32_t)sizeof(rdr->atr) * 2; }
			key_atob_l(value, rdr->atr, rdr->atrlen);
		}
		return;
	}
	if(rdr->atr[0] || cfg.http_full_cfg)
	{
		int j;
		fprintf_conf(f, token, "%s", ""); // it should not have \n at the end
		if(rdr->atr[0])
		{
			for(j = 0; j < rdr->atrlen / 2; j++)
			{
				fprintf(f, "%02X", rdr->atr[j]);
			}
		}
		fprintf(f, "\n");
	}
}

static void detect_fn(const char *token, char *value, void *setting, FILE *f)
{
	struct s_reader *rdr = setting;
	if(value)
	{
		int i;
		for(i = 0; RDR_CD_TXT[i]; i++)
		{
			if(!strcmp(value, RDR_CD_TXT[i]))
			{
				rdr->detect = i;
			}
			else
			{
				if(value[0] == '!' && streq(value + 1, RDR_CD_TXT[i]))
					{ rdr->detect = i | 0x80; }
			}
		}
		return;
	}
	fprintf_conf(f, token, "%s%s\n", rdr->detect & 0x80 ? "!" : "", RDR_CD_TXT[rdr->detect & 0x7f]);
}

void ftab_fn(const char *token, char *value, void *setting, long ftab_type, FILE *f)
{
	FTAB *ftab = setting;
	if(value)
	{
		if(strlen(value))
			chk_ftab(value, ftab);
		else
			ftab_clear(ftab);
		return;
	}
	if(ftab_type & FTAB_READER)
	{
		struct s_reader *rdr = NULL;
		if(ftab_type & FTAB_PROVID)     { rdr = container_of(setting, struct s_reader, ftab); }
		if(ftab_type & FTAB_CHID)       { rdr = container_of(setting, struct s_reader, fchid); }
		if(ftab_type & FTAB_FBPCAID)    { rdr = container_of(setting, struct s_reader, fallback_percaid); }
		if(ftab_type & FTAB_LOCALCARDS) { rdr = container_of(setting, struct s_reader, localcards); }
		if(rdr)
			{ rdr->changes_since_shareupdate = 1; }
	}
	value = mk_t_ftab(ftab);
	if(strlen(value) > 0 || cfg.http_full_cfg)
		{ fprintf_conf(f, token, "%s\n", value); }
	free_mk_t(value);
}

static void aeskeys_fn(const char *token, char *value, void *setting, FILE *f)
{
	struct s_reader *rdr = setting;
	if(value)
	{
		parse_aes_keys(rdr, value);
		return;
	}
	value = mk_t_aeskeys(rdr);
	if(strlen(value) > 0 || cfg.http_full_cfg)
		{ fprintf_conf(f, token, "%s\n", value); }
	free_mk_t(value);
}

static void emmcache_fn(const char *token, char *value, void *setting, FILE *f)
{
	struct s_reader *rdr = setting;
	if(value)
	{
		rdr->cachemm   = 0;
		rdr->rewritemm = 0;
		rdr->logemm    = 0;
		if(strlen(value))
		{
			int i;
			char *ptr, *saveptr1 = NULL;
			for(i = 0, ptr = strtok_r(value, ",", &saveptr1); (i < 3) && (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++)
			{
				switch(i)
				{
				case 0:
					rdr->cachemm = atoi(ptr);
					break;
				case 1:
					rdr->rewritemm = atoi(ptr);
					break;
				case 2:
					rdr->logemm = atoi(ptr);
					break;
				}
			}
			if(rdr->rewritemm <= 0)
			{
				fprintf(stderr, "Setting reader \"emmcache\" to %i,%d,%i instead of %i,%i,%i.",
						rdr->cachemm, 1, rdr->logemm,
						rdr->cachemm, rdr->rewritemm, rdr->logemm);
				fprintf(stderr, "Zero or negative number of rewrites is silly\n");
				rdr->rewritemm = 1;
			}
		}
		return;
	}
	if(rdr->cachemm || cfg.http_full_cfg)
		{ fprintf_conf(f, token, "%d,%d,%d\n", rdr->cachemm, rdr->rewritemm, rdr->logemm); }
}

static void blockemm_bylen_fn(const char *token, char *value, void *setting, FILE *f)
{
	struct s_reader *rdr = setting;
	if(value)
	{
		char *ptr, *saveptr1 = NULL, dash;
		struct s_emmlen_range *blocklen;
		uint32_t num;

		if(!strlen(value))
		{
			ll_destroy_data(&rdr->blockemmbylen);
			return;
		}

		if(!rdr->blockemmbylen)
			{ rdr->blockemmbylen = ll_create("blockemmbylen"); }
		else
			{ ll_clear_data(rdr->blockemmbylen); }

		for(ptr = strtok_r(value, ",", &saveptr1); ptr;
				ptr = strtok_r(NULL, ",", &saveptr1))
		{
			if(!cs_malloc(&blocklen, sizeof(*blocklen)))
				{ return; }
			num = sscanf(ptr, "%hd%c%hd", &blocklen->min, &dash, &blocklen->max);
			if(num <= 0)
			{
				NULLFREE(blocklen);
				fprintf(stderr, "blockemm-bylen parse error: %s\n", value);
				continue;
			}
			if(num == 1)  // single values: x1,x2,x3,...
				{ blocklen->max = blocklen->min; }
			else if(num == 2)  // range values with open end: x1-
				{ blocklen->max = 0; }
			ll_append(rdr->blockemmbylen, blocklen);
		}
		return;
	}
	value = mk_t_emmbylen(rdr);
	if(strlen(value) > 0 || cfg.http_full_cfg)
		{ fprintf_conf(f, token, "%s\n", value); }
	free_mk_t(value);
}

static void nano_fn(const char *token, char *value, void *setting, FILE *f)
{
	uint16_t *nano = setting;
	if(value)
	{
		*nano = 0;
		if(strlen(value) > 0)
		{
			if(streq(value, "all"))
			{
				*nano = 0xFFFF;
			}
			else
			{
				int32_t i;
				char *ptr, *saveptr1 = NULL;
				for(ptr = strtok_r(value, ",", &saveptr1); ptr; ptr = strtok_r(NULL, ",", &saveptr1))
				{
					i = (byte_atob(ptr) % 0x80);
					if(i >= 0 && i <= 16)
						{ *nano |= (1 << i); }
				}
			}
		}
		return;
	}
	value = mk_t_nano(*nano);
	if(strlen(value) > 0 || cfg.http_full_cfg)
		{ fprintf_conf(f, token, "%s\n", value); }
	free_mk_t(value);
}

static void auprovid_fn(const char *token, char *value, void *setting, FILE *f)
{
	struct s_reader *rdr = setting;
	if(value)
	{
		rdr->auprovid = 0;
		if(strlen(value))
			{ rdr->auprovid = a2i(value, 3); }
		return;
	}
	if(rdr->auprovid)
		{ fprintf_conf(f, token, "%06X\n", rdr->auprovid); }
	else if(cfg.http_full_cfg)
		{ fprintf_conf(f, token, "\n"); }
}

static void ratelimitecm_fn(const char *token, char *value, void *setting, FILE *f)
{
	struct s_reader *rdr = setting;
	if(value)
	{
		rdr->ratelimitecm = 0;
		if(strlen(value))
		{
			int i;
			rdr->ratelimitecm = atoi(value);
			for(i = 0; i < MAXECMRATELIMIT; i++)    // reset all slots
			{
				rdr->rlecmh[i].srvid = -1;
				rdr->rlecmh[i].last.time = -1;
			}
		}
		return;
	}
	if(rdr->ratelimitecm || cfg.http_full_cfg)
		{ fprintf_conf(f, token, "%d\n", rdr->ratelimitecm); }
}

static void ratelimittime_fn(const char *token, char *value, void *setting, FILE *f)
{
	struct s_reader *rdr = setting;
	if(value)
	{
		if(strlen(value) == 0)
		{
			if(rdr->ratelimitecm > 0)
			{
				rdr->ratelimittime = 9000; // default 9 seconds
				rdr->srvidholdtime = 2000; // default 2 seconds hold
			}
			else
			{
				rdr->ratelimitecm = 0; // in case someone set a negative value
				rdr->ratelimittime = 0;
				rdr->srvidholdtime = 0;
			}
		}
		else
		{
			rdr->ratelimittime = atoi(value);
			if (rdr->ratelimittime < 60) rdr->ratelimittime *=1000;
		}
		return;
	}
	if(rdr->ratelimitecm || cfg.http_full_cfg)
		{ fprintf_conf(f, token, "%d\n", rdr->ratelimittime); }
}
static void srvidholdtime_fn(const char *token, char *value, void *setting, FILE *f)
{
	struct s_reader *rdr = setting;
	if(value)
	{
		if(strlen(value) == 0)
		{
			if(rdr->ratelimitecm > 0)
			{
				rdr->srvidholdtime = 2000; // default 2 seconds hold
			}
			else
			{
				rdr->ratelimitecm = 0; // in case someone set a negative value
				rdr->srvidholdtime = 0;
			}
		}
		else
		{
			rdr->srvidholdtime = atoi(value);
			if (rdr->srvidholdtime < 60) rdr->srvidholdtime *=1000;
		}
		return;
	}
	if(rdr->ratelimitecm || cfg.http_full_cfg)
		{ fprintf_conf(f, token, "%d\n", rdr->srvidholdtime); }
}

static void cooldown_fn(const char *token, char *value, void *setting, FILE *f)
{
	struct s_reader *rdr = setting;
	if(value)
	{
		if(strlen(value) == 0)
		{
			rdr->cooldown[0] = 0;
			rdr->cooldown[1] = 0;
		}
		else
		{
			int32_t i;
			char *ptr, *saveptr1 = NULL;
			for(i = 0, ptr = strtok_r(value, ",", &saveptr1); (i < 2) && (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++)
			{
				rdr->cooldown[i] = atoi(ptr);
			}
			if(rdr->cooldown[0] <= 0 || rdr->cooldown[1] <= 0)
			{
				fprintf(stderr, "cooldown must have 2 positive values (x,y) set values %d,%d ! cooldown deactivated\n",
						rdr->cooldown[0], rdr->cooldown[1]);
				rdr->cooldown[0] = 0;
				rdr->cooldown[1] = 0;
			}
		}
		return;
	}
	if(rdr->cooldown[0] || cfg.http_full_cfg)
	{
		fprintf_conf(f, token, "%d,%d\n", rdr->cooldown[0], rdr->cooldown[1]);
	}
}

static void cooldowndelay_fn(const char *UNUSED(token), char *value, void *setting, FILE *UNUSED(f))
{
	struct s_reader *rdr = setting;
	if(value)
	{
		rdr->cooldown[0] = strlen(value) ? atoi(value) : 0;
	}
	// This option is *not* written in the config file.
	// It is only set by WebIf as convenience
}

static void cooldowntime_fn(const char *UNUSED(token), char *value, void *setting, FILE *UNUSED(f))
{
	struct s_reader *rdr = setting;
	if(value)
	{
		if(strlen(value) == 0)
		{
			rdr->cooldown[0] = 0; // no cooling down time means no cooling set
			rdr->cooldown[1] = 0;
		}
		else
		{
			rdr->cooldown[1] = atoi(value);
		}
		return;
	}
	// This option is *not* written in the config file.
	// It is only set by WebIf as convenience
}


static void reader_fixups_fn(void *var)
{
	struct s_reader *rdr = var;
#ifdef WITH_LB
	if(rdr->lb_weight > 1000)
		{ rdr->lb_weight = 1000; }
	else if(rdr->lb_weight <= 0)
		{ rdr->lb_weight = 100; }
#endif

	if(is_cascading_reader(rdr) && (rdr->typ == R_CAMD35 || rdr->typ == R_CS378X))
	{
#ifdef CS_CACHEEX
		if(rdr && rdr->cacheex.mode>1)
			{ rdr->keepalive = 1; }   //with cacheex, it is required!
		else
#endif
		if(rdr->typ == R_CAMD35)
			{ rdr->keepalive = 0; }   //with NO-cacheex, and UDP, keepalive is not required!
	}
}


#define OFS(X) offsetof(struct s_reader, X)
#define SIZEOF(X) sizeof(((struct s_reader *)0)->X)

static const struct config_list reader_opts[] =
{
	DEF_OPT_FIXUP_FUNC(reader_fixups_fn),
	DEF_OPT_FUNC("label"                , 0,                            reader_label_fn),
#ifdef WEBIF
	DEF_OPT_STR("description"           , OFS(description),             NULL),
#endif
	DEF_OPT_INT8("enable"               , OFS(enable),                  1),
	DEF_OPT_FUNC("protocol"             , 0,                            protocol_fn),
	DEF_OPT_FUNC("device"               , 0,                            device_fn),
	DEF_OPT_HEX("key"                   , OFS(ncd_key),                 SIZEOF(ncd_key)),
	DEF_OPT_SSTR("user"                 , OFS(r_usr),                   "", SIZEOF(r_usr)),
	DEF_OPT_SSTR("password"             , OFS(r_pwd),                   "", SIZEOF(r_pwd)),
	DEF_OPT_SSTR("pincode"              , OFS(pincode),                 "none", SIZEOF(pincode)),
#ifdef MODULE_GBOX
	DEF_OPT_UINT8("gbox_max_distance"	, OFS(gbox_maxdist),		DEFAULT_GBOX_MAX_DIST),
	DEF_OPT_UINT8("gbox_max_ecm_send"	, OFS(gbox_maxecmsend),		DEFAULT_GBOX_MAX_ECM_SEND),
	DEF_OPT_UINT8("gbox_reshare"		, OFS(gbox_reshare),		DEFAULT_GBOX_RESHARE),
	DEF_OPT_UINT8("cccam_reshare"		, OFS(gbox_cccam_reshare),	DEFAULT_GBOX_RESHARE),
#endif
	DEF_OPT_STR("readnano"              , OFS(emmfile),                 NULL),
	DEF_OPT_FUNC("services"             , OFS(sidtabs),                 reader_services_fn),
	DEF_OPT_FUNC("lb_whitelist_services"    , OFS(lb_sidtabs),              reader_lb_services_fn),
	DEF_OPT_INT32("inactivitytimeout"   , OFS(tcp_ito),                 DEFAULT_INACTIVITYTIMEOUT),
	DEF_OPT_INT32("reconnecttimeout"    , OFS(tcp_rto),                 DEFAULT_TCP_RECONNECT_TIMEOUT),
	DEF_OPT_INT32("reconnectdelay"		, OFS(tcp_reconnect_delay),		60000),
	DEF_OPT_INT32("resetcycle"          , OFS(resetcycle),              0),
	DEF_OPT_INT8("disableserverfilter"  , OFS(ncd_disable_server_filt), 0),
	DEF_OPT_INT8("connectoninit"        , OFS(ncd_connect_on_init),     0),
	DEF_OPT_UINT8("keepalive"           , OFS(keepalive),               0),
	DEF_OPT_INT8("smargopatch"          , OFS(smargopatch),             0),
	DEF_OPT_INT8("autospeed"            , OFS(autospeed),               1),
	DEF_OPT_UINT8("sc8in1_dtrrts_patch" , OFS(sc8in1_dtrrts_patch),     0),
	DEF_OPT_INT8("fallback"             , OFS(fallback),                0),
	DEF_OPT_FUNC_X("fallback_percaid"   , OFS(fallback_percaid),        ftab_fn, FTAB_READER | FTAB_FBPCAID),
	DEF_OPT_FUNC_X("localcards"         , OFS(localcards),        		ftab_fn, FTAB_READER | FTAB_LOCALCARDS),
#ifdef CS_CACHEEX
	DEF_OPT_INT8("cacheex"              , OFS(cacheex.mode),            0),
	DEF_OPT_INT8("cacheex_maxhop"       , OFS(cacheex.maxhop),          0),
	DEF_OPT_FUNC("cacheex_ecm_filter"       , OFS(cacheex.filter_caidtab),  cacheex_hitvaluetab_fn),
	DEF_OPT_UINT8("cacheex_allow_request"   , OFS(cacheex.allow_request),   0),
	DEF_OPT_UINT8("cacheex_drop_csp"        , OFS(cacheex.drop_csp),        0),
	DEF_OPT_UINT8("cacheex_allow_filter", OFS(cacheex.allow_filter),    1),	
#endif
	DEF_OPT_FUNC("caid"                 , OFS(ctab),                    reader_caid_fn),
	DEF_OPT_FUNC("atr"                  , 0,                            atr_fn),
	DEF_OPT_FUNC("boxid"                , 0,                            boxid_fn),
	DEF_OPT_FUNC("boxkey"               , 0,                            boxkey_fn),
	DEF_OPT_FUNC("rsakey"               , 0,                            rsakey_fn),
	DEF_OPT_FUNC_X("ins7e"              , OFS(ins7E),                   ins7E_fn, SIZEOF(ins7E)),
	DEF_OPT_FUNC_X("ins7e11"            , OFS(ins7E11),                 ins7E_fn, SIZEOF(ins7E11)),
	DEF_OPT_FUNC_X("ins2e06"            , OFS(ins2e06),                 ins7E_fn, SIZEOF(ins2e06)),
	DEF_OPT_INT8("fix07"                , OFS(fix_07),                  1),
	DEF_OPT_INT8("fix9993"              , OFS(fix_9993),                0),
	DEF_OPT_INT8("readtiers"           	, OFS(readtiers),              	1),
	DEF_OPT_INT8("force_irdeto"         , OFS(force_irdeto),            0),
	DEF_OPT_INT8("needsemmfirst"        , OFS(needsemmfirst),           0),
	DEF_OPT_UINT32("ecmnotfoundlimit"   , OFS(ecmnotfoundlimit),        0),
	DEF_OPT_FUNC("ecmwhitelist"         , 0,                            ecmwhitelist_fn),
	DEF_OPT_FUNC("ecmheaderwhitelist"   , 0,                            ecmheaderwhitelist_fn),
	DEF_OPT_FUNC("detect"               , 0,                            detect_fn),
	DEF_OPT_INT8("nagra_read"           , OFS(nagra_read),              0),
	DEF_OPT_INT32("mhz"                 , OFS(mhz),                     357),
	DEF_OPT_INT32("cardmhz"             , OFS(cardmhz),                 357),
#ifdef WITH_AZBOX
	DEF_OPT_INT32("mode"                , OFS(azbox_mode),              -1),
#endif
	DEF_OPT_FUNC_X("ident"              , OFS(ftab),                    ftab_fn, FTAB_READER | FTAB_PROVID),
	DEF_OPT_FUNC_X("chid"               , OFS(fchid),                   ftab_fn, FTAB_READER | FTAB_CHID),
	DEF_OPT_FUNC("class"                , OFS(cltab),                   class_fn),
	DEF_OPT_FUNC("aeskeys"              , 0,                            aeskeys_fn),
	DEF_OPT_FUNC("group"                , OFS(grp),                     group_fn),
	DEF_OPT_FUNC("emmcache"             , 0,                            emmcache_fn),
	DEF_OPT_FUNC_X("blockemm-unknown"   , OFS(blockemm),                flags_fn, EMM_UNKNOWN),
	DEF_OPT_FUNC_X("blockemm-u"         , OFS(blockemm),                flags_fn, EMM_UNIQUE),
	DEF_OPT_FUNC_X("blockemm-s"         , OFS(blockemm),                flags_fn, EMM_SHARED),
	DEF_OPT_FUNC_X("blockemm-g"         , OFS(blockemm),                flags_fn, EMM_GLOBAL),
	DEF_OPT_FUNC_X("saveemm-unknown"    , OFS(saveemm),                 flags_fn, EMM_UNKNOWN),
	DEF_OPT_FUNC_X("saveemm-u"          , OFS(saveemm),                 flags_fn, EMM_UNIQUE),
	DEF_OPT_FUNC_X("saveemm-s"          , OFS(saveemm),                 flags_fn, EMM_SHARED),
	DEF_OPT_FUNC_X("saveemm-g"          , OFS(saveemm),                 flags_fn, EMM_GLOBAL),
	DEF_OPT_FUNC("blockemm-bylen"       , 0,                            blockemm_bylen_fn),
#ifdef WITH_LB
	DEF_OPT_INT32("lb_weight"           , OFS(lb_weight),               100),
	DEF_OPT_INT8("lb_force_fallback"    , OFS(lb_force_fallback),       0),
#endif
	DEF_OPT_FUNC("savenano"             , OFS(s_nano),                  nano_fn),
	DEF_OPT_FUNC("blocknano"            , OFS(b_nano),                  nano_fn),
	DEF_OPT_INT8("dropbadcws"           , OFS(dropbadcws),              0),
	DEF_OPT_INT8("disablecrccws"        , OFS(disablecrccws),           0),
	DEF_OPT_INT32("use_gpio"            , OFS(use_gpio),                0),
#ifdef MODULE_PANDORA
	DEF_OPT_UINT8("pand_send_ecm"       , OFS(pand_send_ecm),           0),
#endif
#ifdef MODULE_CCCAM
	DEF_OPT_SSTR("cccversion"           , OFS(cc_version),              "", SIZEOF(cc_version)),
	DEF_OPT_INT8("cccmaxhops"           , OFS(cc_maxhops),              DEFAULT_CC_MAXHOPS),
	DEF_OPT_INT8("cccmindown"           , OFS(cc_mindown),              0),
	DEF_OPT_INT8("cccwantemu"           , OFS(cc_want_emu),             0),
	DEF_OPT_INT8("ccckeepalive"         , OFS(cc_keepalive),            DEFAULT_CC_KEEPALIVE),
	DEF_OPT_INT8("cccreshare"           , OFS(cc_reshare),              DEFAULT_CC_RESHARE),
	DEF_OPT_INT32("cccreconnect"        , OFS(cc_reconnect),            DEFAULT_CC_RECONNECT),
	DEF_OPT_INT8("ccchop"               , OFS(cc_hop),                  0),
#endif
#ifdef MODULE_GHTTP
	DEF_OPT_UINT8("use_ssl"             , OFS(ghttp_use_ssl),           0),
#endif
	DEF_OPT_INT8("deprecated"           , OFS(deprecated),              0),
	DEF_OPT_INT8("audisabled"           , OFS(audisabled),              0),
	DEF_OPT_FUNC("auprovid"             , 0,                            auprovid_fn),
	DEF_OPT_INT8("ndsversion"           , OFS(ndsversion),              0),
	DEF_OPT_FUNC("ratelimitecm"         , 0,                            ratelimitecm_fn),
	DEF_OPT_FUNC("ratelimittime"        , 0,                            ratelimittime_fn),
	DEF_OPT_INT8("ecmunique"            , OFS(ecmunique),               0),
	DEF_OPT_FUNC("srvidholdtime"        , 0,                            srvidholdtime_fn),
	DEF_OPT_FUNC("cooldown"             , 0,                            cooldown_fn),
	DEF_OPT_FUNC("cooldowndelay"        , 0,                            cooldowndelay_fn),
	DEF_OPT_FUNC("cooldowntime"         , 0,                            cooldowntime_fn),
#ifdef MODULE_CAMD35
	DEF_OPT_INT8("via_emm_global"       , OFS(via_emm_global),          0),
#endif
	DEF_OPT_UINT8("read_old_classes"    , OFS(read_old_classes),        0),
	DEF_LAST_OPT
};

static inline bool in_list(const char *token, const char *list[])
{
	int i;
	for(i = 0; list[i]; i++)
	{
		if(streq(token, list[i]))
			{ return true; }
	}
	return false;
}

static bool reader_check_setting(const struct config_list *UNUSED(clist), void *config_data, const char *setting)
{
	struct s_reader *reader = config_data;
	// These are written only when the reader is physical reader
	static const char *hw_only_settings[] =
	{
		"readnano", "resetcycle", "smargopatch", "autospeed", "sc8in1_dtrrts_patch", "boxid","fix07",
		"fix9993", "rsakey", "ins7e", "ins7e11", "ins2e06", "force_irdeto", "needsemmfirst", "boxkey",
		"atr", "detect", "nagra_read", "mhz", "cardmhz", "readtiers", "read_old_classes",
#ifdef WITH_AZBOX
		"mode",
#endif
		"deprecated", "ndsversion",
		0
	};
	// These are written only when the reader is network reader
	static const char *network_only_settings[] =
	{
		"user", "inactivitytimeout", "reconnecttimeout",
		0
	};
	if(is_network_reader(reader))
	{
		if(in_list(setting, hw_only_settings))
			{ return false; }
	}
	else
	{
		if(in_list(setting, network_only_settings))
			{ return false; }
	}

	// These are not written in the config file
	static const char *deprecated_settings[] =
	{
		"cooldowndelay", "cooldowntime", "mg-encrypted",
		0
	};
	if(in_list(setting, deprecated_settings))
		{ return false; }

	// Special settings for NEWCAMD
	static const char *newcamd_settings[] =
	{
		"disableserverfilter", "connectoninit",
		0
	};
	if(reader->typ != R_NEWCAMD && in_list(setting, newcamd_settings))
		{ return false; }
#ifdef MODULE_CAMD35
	// Special settings for CAMD35 or CS357X only written if rader is CAMD35/CS357X
	static const char *camd35_settings[] =
	{
		"via_emm_global",
		0
	};
	if(reader->typ != R_CAMD35 && in_list(setting, camd35_settings))
		{ return false; }
#endif
#ifdef MODULE_CCCAM
	// These are written only when the reader is CCCAM
	static const char *cccam_settings[] =
	{
		"cccversion", "cccmaxhops", "cccmindown", "cccwantemu", "ccckeepalive",
		"cccreconnect",
		0
	};
	// Special settings for CCCAM
	if(reader->typ != R_CCCAM)
	{
		if(in_list(setting, cccam_settings))
			{ return false; }
	}
	else if(streq(setting, "ccchop"))
	{
		return false;
	}
#endif

#ifdef MODULE_PANDORA
	// Special settings for PANDORA
	if(reader->typ != R_PANDORA && streq(setting, "pand_send_ecm"))
		{ return false; }
#endif

	return true; // Write the setting
}


void chk_reader(char *token, char *value, struct s_reader *rdr)
{
	if(config_list_parse(reader_opts, token, value, rdr))
		{ return; }
	else if(token[0] != '#')
		{ fprintf(stderr, "Warning: keyword '%s' in reader section not recognized\n", token); }
}

void reader_set_defaults(struct s_reader *rdr)
{
	config_list_set_defaults(reader_opts, rdr);
}

int32_t init_readerdb(void)
{
	configured_readers = ll_create("configured_readers");

	FILE *fp = open_config_file(cs_srvr);
	if(!fp)
		{ return 1; }

	int32_t tag = 0;
	char *value, *token;

	if(!cs_malloc(&token, MAXLINESIZE))
		{ return 1; }

	struct s_reader *rdr;
	if(!cs_malloc(&rdr, sizeof(struct s_reader)))
	{
		NULLFREE(token);
		return 1;
	}

	ll_append(configured_readers, rdr);
	while(fgets(token, MAXLINESIZE, fp))
	{
		int32_t l;
		if((l = strlen(trim(token))) < 3)
			{ continue; }
		if((token[0] == '[') && (token[l - 1] == ']'))
		{
			token[l - 1] = 0;
			tag = (!strcmp("reader", strtolower(token + 1)));
			if(rdr->label[0] && rdr->typ)
			{
				struct s_reader *newreader;
				if(cs_malloc(&newreader, sizeof(struct s_reader)))
				{
					ll_append(configured_readers, newreader);
					rdr = newreader;
				}
			}
			reader_set_defaults(rdr);
			continue;
		}

		if(!tag)
			{ continue; }
		if(!(value = strchr(token, '=')))
			{ continue; }
		*value++ = '\0';
		chk_reader(trim(strtolower(token)), trim(value), rdr);
	}
	NULLFREE(token);
	LL_ITER itr = ll_iter_create(configured_readers);
	while((rdr = ll_iter_next(&itr)))   //build active readers list
	{
		reader_fixups_fn(rdr);
		module_reader_set(rdr);
	}
	fclose(fp);
	return (0);
}

void free_reader(struct s_reader *rdr)
{
	NULLFREE(rdr->emmfile);

	ecm_whitelist_clear(&rdr->ecm_whitelist);
	ecm_hdr_whitelist_clear(&rdr->ecm_hdr_whitelist);

	ftab_clear(&rdr->fallback_percaid);
	ftab_clear(&rdr->localcards);
	ftab_clear(&rdr->fchid);
	ftab_clear(&rdr->ftab);

	caidtab_clear(&rdr->ctab);

	lb_destroy_stats(rdr);

	cs_clear_entitlement(rdr);
	ll_destroy(&rdr->ll_entitlements);

	if(rdr->csystem && rdr->csystem->card_done)
		rdr->csystem->card_done(rdr);
	NULLFREE(rdr->csystem_data);

	ll_destroy_data(&rdr->blockemmbylen);

	ll_destroy_data(&rdr->emmstat);

	aes_clear_entries(&rdr->aes_list);
	
	config_list_gc_values(reader_opts, rdr);
	add_garbage(rdr);
}

int32_t free_readerdb(void)
{
	int count = 0;
	struct s_reader *rdr;
	LL_ITER itr = ll_iter_create(configured_readers);
	while((rdr = ll_iter_next(&itr)))
	{
		free_reader(rdr);
		count++;
	}
	cs_log("readerdb %d readers freed", count);
	ll_destroy(&configured_readers);
	return count;
}

int32_t write_server(void)
{
	FILE *f = create_config_file(cs_srvr);
	if(!f)
		{ return 1; }
	struct s_reader *rdr;
	LL_ITER itr = ll_iter_create(configured_readers);
	while((rdr = ll_iter_next(&itr)))
	{
		if(rdr->label[0])
		{
			fprintf(f, "[reader]\n");
			config_list_apply_fixups(reader_opts, rdr);
			config_list_save_ex(f, reader_opts, rdr, cfg.http_full_cfg, reader_check_setting);
			fprintf(f, "\n");
		}
	}
	return flush_config_file(f, cs_srvr);
}

void reload_readerdb(void)
{
	struct s_reader *rdr;
	LL_ITER itr = ll_iter_create(configured_readers);
	while((rdr = ll_iter_next(&itr)))
	{
		// disable the current reader
		rdr->enable = 0;
		restart_cardreader(rdr,1);
	}
	free_readerdb(); // release the old readerdb
	init_readerdb(); // reload the new readerdb
	init_cardreader(); // start the readers
}
