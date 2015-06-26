#define MODULE_LOG_PREFIX "dvbapi"

#include "globals.h"

#ifdef HAVE_DVBAPI

#include "oscam-config.h"
#include "oscam-ecm.h"
#include "oscam-string.h"
#include "module-dvbapi.h"
#include "module-dvbapi-chancache.h"

extern DEMUXTYPE demux[MAX_DEMUX];

static LLIST *channel_cache;

void dvbapi_save_channel_cache(void)
{
	if(boxtype_is("dbox2")) return; // dont save channelcache on these boxes, they lack resources and will crash!
	
	if (USE_OPENXCAS) // Why?
		return;

	char fname[256];
	int32_t result = 0;
	get_config_filename(fname, sizeof(fname), "oscam.ccache");
	FILE *file = fopen(fname, "w");

	if(!file)
	{
		cs_log("dvbapi channelcache can't write to file %s", fname);
		return;
	}

	LL_ITER it = ll_iter_create(channel_cache);
	struct s_channel_cache *c;
	while((c = ll_iter_next(&it)))
	{
		result = fprintf(file, "%04X,%06X,%04X,%04X,%06X\n", c->caid, c->prid, c->srvid, c->pid, c->chid);
		if(result < 0)
		{
			fclose(file);
			result = remove(fname);
			if(!result)
			{
				cs_log("error writing cache -> cache file removed!");
			}
			else
			{
				cs_log("error writing cache -> cache file could not be removed either!");
			}
			return;
		}
	}

	fclose(file);
	cs_log("dvbapi channelcache saved to %s", fname);
}

void dvbapi_load_channel_cache(void)
{
	if(boxtype_is("dbox2")) return; // dont load channelcache on these boxes, they lack resources and will crash!
	
	if (USE_OPENXCAS) // Why?
		return;

	char fname[256];
	char line[1024];
	FILE *file;
	struct s_channel_cache *c;

	get_config_filename(fname, sizeof(fname), "oscam.ccache");
	file = fopen(fname, "r");
	if(!file)
	{
		cs_log_dbg(D_TRACE, "dvbapi channelcache can't read from file %s", fname);
		return;
	}
	
	int32_t i = 1;
	int32_t valid = 0;
	char *ptr, *saveptr1 = NULL;
	char *split[6];

	memset(line, 0, sizeof(line));
	while(fgets(line, sizeof(line), file))
	{
		if(!line[0] || line[0] == '#' || line[0] == ';')
			{ continue; }

		for(i = 0, ptr = strtok_r(line, ",", &saveptr1); ptr && i < 6 ; ptr = strtok_r(NULL, ",", &saveptr1), i++)
		{
			split[i] = ptr;
		}

		valid = (i == 5);
		if(valid)
		{
			if(!cs_malloc(&c, sizeof(struct s_channel_cache)))
			{ continue; }
			c->caid = a2i(split[0], 4);
			c->prid = a2i(split[1], 6);
			c->srvid = a2i(split[2], 4);
			c->pid = a2i(split[3], 4);
			c->chid = a2i(split[4], 6);

			if(valid && c->caid != 0)
			{
				if(!channel_cache)
				{
					channel_cache = ll_create("channel cache");
				}

				ll_append(channel_cache, c);
			}
			else
			{
				NULLFREE(c);
			}
		}
	}
	fclose(file);
	cs_log("dvbapi channelcache loaded from %s", fname);
}

struct s_channel_cache *dvbapi_find_channel_cache(int32_t demux_id, int32_t pidindex, int8_t caid_and_prid_only)
{
	struct s_ecmpids *p = &demux[demux_id].ECMpids[pidindex];
	struct s_channel_cache *c;
	LL_ITER it;

	if(!channel_cache)
		{ channel_cache = ll_create("channel cache"); }

	it = ll_iter_create(channel_cache);
	while((c = ll_iter_next(&it)))
	{

		if(caid_and_prid_only)
		{
			if(p->CAID == c->caid && (p->PROVID == c->prid || p->PROVID == 0))  // PROVID ==0 some provider no provid in PMT table
				{ return c; }
		}
		else
		{
			if(demux[demux_id].program_number == c->srvid
					&& p->CAID == c->caid
					&& p->ECM_PID == c->pid
					&& (p->PROVID == c->prid || p->PROVID == 0)) // PROVID ==0 some provider no provid in PMT table
			{

#ifdef WITH_DEBUG
				char buf[ECM_FMT_LEN];
				ecmfmt(buf, ECM_FMT_LEN, c->caid, 0, c->prid, c->chid, c->pid, c->srvid, 0, 0, 0, 0, 0, 0, NULL);
				cs_log_dbg(D_DVBAPI, "Demuxer %d found in channel cache: %s", demux_id, buf);
#endif
				return c;
			}
		}
	}
	return NULL;
}

int32_t dvbapi_edit_channel_cache(int32_t demux_id, int32_t pidindex, uint8_t add)
{
	struct s_ecmpids *p = &demux[demux_id].ECMpids[pidindex];
	struct s_channel_cache *c;
	LL_ITER it;
	int32_t count = 0;

	if(!channel_cache)
		{ channel_cache = ll_create("channel cache"); }

	it = ll_iter_create(channel_cache);
	while((c = ll_iter_next(&it)))
	{
		if(demux[demux_id].program_number == c->srvid
				&& p->CAID == c->caid
				&& p->ECM_PID == c->pid
				&& (p->PROVID == c->prid || p->PROVID == 0))
		{
			if(add && p->CHID == c->chid)
			{
				return 0; //already added
			}
			ll_iter_remove_data(&it);
			count++;
		}
	}

	if(add)
	{
		if(!cs_malloc(&c, sizeof(struct s_channel_cache)))
			{ return count; }
		c->srvid = demux[demux_id].program_number;
		c->caid = p->CAID;
		c->pid = p->ECM_PID;
		c->prid = p->PROVID;
		c->chid = p->CHID;
		ll_append(channel_cache, c);
#ifdef WITH_DEBUG
		char buf[ECM_FMT_LEN];
		ecmfmt(buf, ECM_FMT_LEN, c->caid, 0, c->prid, c->chid, c->pid, c->srvid, 0, 0, 0, 0, 0, 0, NULL);
		cs_log_dbg(D_DVBAPI, "Demuxer %d added to channel cache: %s", demux_id, buf);
#endif
		count++;
	}

	return count;
}

#endif
