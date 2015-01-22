#ifndef MODULE_DVBAPI_CHANCACHE_H_
#define MODULE_DVBAPI_CHANCACHE_H_

#ifdef HAVE_DVBAPI

struct s_channel_cache
{
	uint16_t    caid;
	uint32_t    prid;
	uint16_t    srvid;
	uint16_t    pid;
	uint32_t    chid;
};

void dvbapi_save_channel_cache(void);
void dvbapi_load_channel_cache(void);
struct s_channel_cache *dvbapi_find_channel_cache(int32_t demux_id, int32_t pidindex, int8_t caid_and_prid_only);
int32_t dvbapi_edit_channel_cache(int32_t demux_id, int32_t pidindex, uint8_t add);

#else
static inline void dvbapi_save_channel_cache(void) { }
#endif

#endif
