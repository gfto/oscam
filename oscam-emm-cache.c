#define MODULE_LOG_PREFIX "emmcache"

#include "globals.h"
#include "oscam-config.h"
#include "oscam-string.h"
#include "oscam-emm-cache.h"
#include "oscam-files.h"
#include "oscam-time.h"
#include "oscam-lock.h"
#include "cscrypt/md5.h"
#define LINESIZE 1024
#define DEFAULT_LOCK_TIMEOUT 1000000

static LLIST *emm_cache;

bool emm_cache_configured(void)
{
	struct s_reader *rdr;
	bool enable = false;
	LL_ITER itr = ll_iter_create(configured_readers);
	while((rdr = ll_iter_next(&itr)))
	{
		if(rdr->cachemm == 1)
		{
			enable = true;
		}
	}
	return enable;
}

void emm_save_cache(void)
{
	if(boxtype_is("dbox2")) return; // dont save emmcache on these boxes, they lack resources and will crash!
	
	if(!emm_cache_configured()){
		cs_log("saving emmcache disabled since no reader is using it!");
		return;
	}

	char fname[256];
	struct timeb ts, te;
	
	if(!cfg.emmlogdir)
	{
		get_tmp_dir_filename(fname, sizeof(fname), "oscam.emmcache");
	}
	else
	{
		get_config_filename(fname, sizeof(fname), "oscam.emmcache");
	}
	FILE *file = fopen(fname, "w");

	if(!file)
	{
		cs_log("can't write emmcache to file %s", fname);
		return;
	}

	cs_ftime(&ts);
	int32_t count = 0, result = 0;
	LL_ITER it = ll_iter_create(emm_cache);
	struct s_emmcache *c;
	while((c = ll_iter_next(&it)))
	{
		uchar tmp_emmd5[MD5_DIGEST_LENGTH * 2 + 1];
		char_to_hex(c->emmd5, MD5_DIGEST_LENGTH, tmp_emmd5); 
		uchar tmp_emm[c->len * 2 + 1];
		char_to_hex(c->emm, c->len, tmp_emm);
		result = fprintf(file, "%s,%ld,%ld,%02X,%04X,%s\n", tmp_emmd5, c->firstseen.time, c->lastseen.time, c->type, c->len, tmp_emm);
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
		count++;
	}

	fclose(file);
	cs_ftime(&te);
	int64_t load_time = comp_timeb(&te, &ts);
	cs_log("saved %d emmcache records to %s in %"PRId64" ms", count, fname, load_time);
}

void load_emmstat_from_file(void)
{
	if(boxtype_is("dbox2")) return; // dont load emmstat on these boxes, they lack resources and will crash!
	
	if(!emm_cache_configured()){
		cs_log("loading emmstats disabled since no reader is using it!");
		return;
	}

	char buf[256];
	char fname[256];
	char *line;
	FILE *file;
	
	if(!cfg.emmlogdir)
	{
		get_tmp_dir_filename(fname, sizeof(fname), "oscam.emmstat");
	}
	else
	{
		get_config_filename(fname, sizeof(fname), "oscam.emmstat");
	}
	file = fopen(fname, "r");
	if(!file)
	{
		cs_log_dbg(D_TRACE, "can't read emmstats from file %s", fname);
		return;
	}

	if(!cs_malloc(&line, LINESIZE))
	{
		fclose(file);
		return;
	}

	struct timeb ts, te;
	cs_ftime(&ts);

	struct s_reader *rdr = NULL;
	struct s_emmstat *s;

	int32_t i = 1;
	int32_t valid = 0;
	int32_t count = 0;
	char *ptr, *saveptr1 = NULL;
	char *split[7];

	while(fgets(line, LINESIZE, file))
	{
		if(!line[0] || line[0] == '#' || line[0] == ';')
			{ continue; }

		if(!cs_malloc(&s, sizeof(struct s_emmstat)))
			{ continue; }

		for(i = 0, ptr = strtok_r(line, ",", &saveptr1); ptr && i < 7 ; ptr = strtok_r(NULL, ",", &saveptr1), i++)
		{ split[i] = ptr; }
		valid = (i == 6);
		if(valid)
		{
			strncpy(buf, split[0], sizeof(buf) - 1);
			key_atob_l(split[1], s->emmd5, MD5_DIGEST_LENGTH*2);
			s->firstwritten.time = atol(split[2]);
			s->lastwritten.time = atol(split[3]);
			s->type = a2i(split[4], 2);
			s->count = a2i(split[5], 4);
			
			LL_ITER itr = ll_iter_create(configured_readers);
			
			while((rdr = ll_iter_next(&itr)))
			{
				if(rdr->cachemm !=1) //skip: emmcache save is disabled
				{
					continue;
				}
				if(strcmp(rdr->label, buf) == 0)
				{
					break;
				}
			}

			if(rdr != NULL)
			{
				if(!rdr->emmstat)
				{
					rdr->emmstat = ll_create("emmstat");
					cs_lock_create(&rdr->emmstat_lock, rdr->label, DEFAULT_LOCK_TIMEOUT);
				}

				ll_append(rdr->emmstat, s);
				count++;
			}
			else
			{
				cs_log("emmstats could not be loaded for %s", buf);
				NULLFREE(s);
			}
		}
		else
		{
			cs_log_dbg(D_EMM, "emmstat ERROR: %s count=%d type=%d", buf, s->count, s->type);
			NULLFREE(s);
		}
	}

	fclose(file);
	NULLFREE(line);
	
	cs_ftime(&te);
	int64_t load_time = comp_timeb(&te, &ts);
	cs_log("loaded %d emmstat records from %s in %"PRId64" ms", count, fname, load_time);
}

void save_emmstat_to_file(void)
{
	if(boxtype_is("dbox2")) return; // dont save emmstat on these boxes, they lack resources and will crash!
	
	if(!emm_cache_configured()){
		cs_log("saving emmstats disabled since no reader is using it!");
		return;
	}
	
	char fname[256];

	if(!cfg.emmlogdir)
	{
		get_tmp_dir_filename(fname, sizeof(fname), "oscam.emmstat");
	}
	else
	{
		get_config_filename(fname, sizeof(fname), "oscam.emmstat");
	}
	FILE *file = fopen(fname, "w");

	if(!file)
	{
		cs_log("can't write to file %s", fname);
		return;
	}

	struct timeb ts, te;
	cs_ftime(&ts);

	int32_t count = 0, result = 0;
	struct s_reader *rdr;
	LL_ITER itr = ll_iter_create(configured_readers);
	while((rdr = ll_iter_next(&itr)))
	{
		if(!rdr->cachemm || rdr->cachemm == 2)
		{
			cs_log("reader %s skipped since emmcache save is disabled", rdr->label);
			continue;
		}

		if(rdr->emmstat)
		{
			cs_writelock(&rdr->emmstat_lock);
			LL_ITER it = ll_iter_create(rdr->emmstat);
			struct s_emmstat *s;
			while((s = ll_iter_next(&it)))
			{
				uchar tmp_emmd5[MD5_DIGEST_LENGTH * 2 + 1];
				char_to_hex(s->emmd5, MD5_DIGEST_LENGTH, tmp_emmd5);
				result = fprintf(file, "%s,%s,%ld,%ld,%02X,%04X\n", rdr->label, tmp_emmd5, s->firstwritten.time, s->lastwritten.time, s->type, s->count);
				if(result < 0)
				{
					cs_writeunlock(&rdr->emmstat_lock);
					fclose(file);
					result = remove(fname);
					if(!result)
					{
						cs_log("error writing stats -> stat file removed!");
					}
					else
					{
						cs_log("error writing stats -> stat file could not be removed either!");
					}
					return;
				}	
				count++;
			}
			cs_writeunlock(&rdr->emmstat_lock);
		}
	}

	fclose(file);
	
	cs_ftime(&te);
	int64_t load_time = comp_timeb(&te, &ts);

	cs_log("saved %d emmstat records to %s in %"PRId64" ms", count, fname, load_time);
}

void emm_load_cache(void)
{
	if(boxtype_is("dbox2")) return; // dont load emmcache on these boxes, they lack resources and will crash!
	
	if(!emm_cache_configured()){
		cs_log("loading emmcache disabled since no reader is using it!");
		return;
	}
	
	char fname[256];
	char line[1024];
	FILE *file;
	struct s_emmcache *c;

	if(!cfg.emmlogdir)
	{
		get_tmp_dir_filename(fname, sizeof(fname), "oscam.emmcache");
	}
	else
	{
		get_config_filename(fname, sizeof(fname), "oscam.emmcache");
	}
	
	file = fopen(fname, "r");
	if(!file)
	{
		cs_log_dbg(D_TRACE, "can't read emmcache from file %s", fname);
		return;
	}

	struct timeb ts, te;
	cs_ftime(&ts);

	int32_t count = 0;
	int32_t i = 1;
	int32_t valid = 0;
	char *ptr, *saveptr1 = NULL;
	char *split[7];

	memset(line, 0, sizeof(line));
	while(fgets(line, sizeof(line), file))
	{
		if(!line[0] || line[0] == '#' || line[0] == ';')
			{ continue; }

		for(i = 0, ptr = strtok_r(line, ",", &saveptr1); ptr && i < 7 ; ptr = strtok_r(NULL, ",", &saveptr1), i++)
		{
			split[i] = ptr;
		}

		valid = (i == 6);
		if(valid)
		{
			if(!cs_malloc(&c, sizeof(struct s_emmcache)))
			{ continue; }
			key_atob_l(split[0], c->emmd5, MD5_DIGEST_LENGTH*2);
			c->firstseen.time = atol(split[1]);
			c->lastseen.time = atol(split[2]);
			c->type = a2i(split[3], 2);
			c->len = a2i(split[4], 4);
			key_atob_l(split[5], c->emm, c->len*2);

			if(valid && c->len != 0)
			{
				if(!emm_cache)
				{
					emm_cache = ll_create("emm cache");
				}

				ll_append(emm_cache, c);
				count++;
			}
			else
			{
				NULLFREE(c);
			}
		}
	}
	fclose(file);
	cs_ftime(&te);
	int64_t load_time = comp_timeb(&te, &ts);
	cs_log("loaded %d emmcache records from %s in %"PRId64" ms", count, fname, load_time);
}

struct s_emmcache *find_emm_cache(uchar *emmd5)
{
	struct s_emmcache *c;
	LL_ITER it;

	if(!emm_cache)
		{ emm_cache = ll_create("emm cache"); }

	it = ll_iter_create(emm_cache);
	while((c = ll_iter_next(&it)))
	{ 
		if(!memcmp(emmd5, c->emmd5, MD5_DIGEST_LENGTH))
		{
			cs_log_dump_dbg(D_EMM, c->emmd5, MD5_DIGEST_LENGTH, "found emmcache match");
			return c;
		}
	}
	return NULL;
}

int32_t clean_stale_emm_cache_and_stat(uchar *emmd5, int64_t gone)
{
	struct timeb now;
	cs_ftime(&now);
	int32_t count = 0;
	
	struct s_emmcache *c;
	LL_ITER it;

	if(!emm_cache)
		{ emm_cache = ll_create("emm cache"); }

	it = ll_iter_create(emm_cache);
	while((c = ll_iter_next(&it)))
	{ 
		
		if(comp_timeb(&now, &c->lastseen) > gone && memcmp(c->emmd5, emmd5, MD5_DIGEST_LENGTH)) // clean older than gone ms and dont clean if its the current emm!
		{	
			struct s_reader *rdr;
			LL_ITER rdr_itr = ll_iter_create(configured_readers);
			while((rdr = ll_iter_next(&rdr_itr)))
			{
				if(rdr->emmstat)
				{
					remove_emm_stat(rdr, c->emmd5); // clean stale entry from stats
					count++;
				}
			}
			ll_iter_remove_data(&it); // clean stale entry from emmcache
		}
	}
	return count;
}

int32_t emm_edit_cache(uchar *emmd5, EMM_PACKET *ep, bool add)
{
	struct s_emmcache *c;
	LL_ITER it;
	int32_t count = 0;

	if(!emm_cache)
		{ emm_cache = ll_create("emm cache"); }

	it = ll_iter_create(emm_cache);
	while((c = ll_iter_next(&it)))
	{
		if(!memcmp(emmd5, c->emmd5, MD5_DIGEST_LENGTH))
		{
			if(add)
			{
				return 0; //already added
			}
			ll_iter_remove_data(&it);
			count++;
		}
	}

	if(add)
	{
		if(!cs_malloc(&c, sizeof(struct s_emmcache)))
			{ return count; }
		memcpy(c->emmd5, emmd5, MD5_DIGEST_LENGTH);
		c->type = ep->type;
		c->len = ep->emm[2];
		cs_ftime(&c->firstseen);
		c->lastseen = c->firstseen;
		memcpy(c->emm, ep->emm, c->len);
		ll_append(emm_cache, c);
#ifdef WITH_DEBUG
		cs_log_dump_dbg(D_EMM, c->emmd5, MD5_DIGEST_LENGTH, "added emm to cache:");
#endif
		count++;
	}

	return count;
}
int32_t remove_emm_stat(struct s_reader *rdr, uchar *emmd5)
{
	int32_t count = 0;
	if(rdr && rdr->emmstat)
	{
		cs_writelock(&rdr->emmstat_lock);
		struct s_emmstat *c;
		LL_ITER itr = ll_iter_create(rdr->emmstat);
		while((c = ll_iter_next(&itr)))
		{
			if(!memcmp(emmd5, c->emmd5, MD5_DIGEST_LENGTH))
			{
				ll_iter_remove_data(&itr);
				count++;
				break;
			}
		}

		cs_writeunlock(&rdr->emmstat_lock);
	}
	return count;
}

struct s_emmstat *get_emm_stat(struct s_reader *rdr, uchar *emmd5, uchar emmtype)
{
	if(!rdr->cachemm) return NULL;
	
	struct s_emmstat *c;
	LL_ITER it;

	if(!rdr->emmstat)
		{ rdr->emmstat = ll_create("emm stat"); }

	it = ll_iter_create(rdr->emmstat);
	while((c = ll_iter_next(&it)))
	{ 
		if(!memcmp(emmd5, c->emmd5, MD5_DIGEST_LENGTH))
		{
			cs_log_dump_dbg(D_EMM, c->emmd5, MD5_DIGEST_LENGTH, "found emmstat match (reader:%s, count:%d)", rdr->label, c->count);
			return c;
		}
	}
	
	if(cs_malloc(&c, sizeof(struct s_emmstat)))
	{
		memcpy(c->emmd5, emmd5, MD5_DIGEST_LENGTH);
		c->type = emmtype;
		ll_append(rdr->emmstat, c);
		cs_log_dump_dbg(D_EMM, c->emmd5, MD5_DIGEST_LENGTH, "added emmstat (reader:%s, count:%d)", rdr->label, c->count);
	}
	return c;
}
