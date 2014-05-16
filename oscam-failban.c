#include "globals.h"
#include "oscam-net.h"
#include "oscam-string.h"
#include "oscam-time.h"

static int32_t cs_check_v(IN_ADDR_T ip, int32_t port, int32_t add, char *info, int32_t acosc_penalty_duration)
{
	int32_t result = 0;
	bool acosc_enabled = false;

#ifdef CS_ANTICASC
	if(cfg.acosc_enabled) 
		acosc_enabled = true;
#endif

	if(!(cfg.failbantime || acosc_enabled))
		{ return 0; }

	if(!cfg.v_list)
		{ cfg.v_list = ll_create("v_list"); }

	struct timeb (now);
	cs_ftime(&now);
	LL_ITER itr = ll_iter_create(cfg.v_list);
	V_BAN *v_ban_entry;
	int32_t ftime = cfg.failbantime * 60 * 1000;

	//run over all banned entries to do housekeeping:
	while((v_ban_entry = ll_iter_next(&itr)))
	{
		// housekeeping:
		int32_t gone = comp_timeb(&now, &v_ban_entry->v_time);
		if(((gone >= ftime) && !v_ban_entry->acosc_entry) || (v_ban_entry->acosc_entry && ((gone/1000) >= v_ban_entry->acosc_penalty_dur))) // entry out of time->remove
		{
			NULLFREE(v_ban_entry->info);
			ll_iter_remove_data(&itr);
			continue;
		}

		if(IP_EQUAL(ip, v_ban_entry->v_ip) && port == v_ban_entry->v_port)
		{
			result = 1;
			if(!info)
				{ info = v_ban_entry->info; }
			else if(!v_ban_entry->info)
			{
				v_ban_entry->info = cs_strdup(info);
			}

			if(!add)
			{
				if(v_ban_entry->v_count >= cfg.failbancount)
				{
					if(!v_ban_entry->acosc_entry)
                    	{ cs_debug_mask(D_TRACE, "failban: banned ip %s:%d - %ld seconds left%s%s", cs_inet_ntoa(v_ban_entry->v_ip), v_ban_entry->v_port, (ftime - gone)/1000, info ? ", info: " : "", info ? info : ""); }
					else
						{ cs_debug_mask(D_TRACE, "failban: banned ip %s:%d - %ld seconds left%s%s", cs_inet_ntoa(v_ban_entry->v_ip), v_ban_entry->v_port, (v_ban_entry->acosc_penalty_dur - (gone/1000)), info?", info: ":"", info?info:""); }

				}
				else
				{
					cs_debug_mask(D_TRACE, "failban: ip %s:%d chance %d of %d%s%s",
								  cs_inet_ntoa(v_ban_entry->v_ip), v_ban_entry->v_port,
								  v_ban_entry->v_count, cfg.failbancount, info ? ", info: " : "", info ? info : "");
					v_ban_entry->v_count++;
				}
			}
			else
			{
				cs_debug_mask(D_TRACE, "failban: banned ip %s:%d - already exist in list%s%s",
							  cs_inet_ntoa(v_ban_entry->v_ip), v_ban_entry->v_port, info ? ", info: " : "", info ? info : "");
			}
		}
	}

	if(add && !result)
	{
		if(cs_malloc(&v_ban_entry, sizeof(V_BAN)))
		{
			cs_ftime(&v_ban_entry->v_time);
			v_ban_entry->v_ip = ip;
			v_ban_entry->v_port = port;
			v_ban_entry->v_count = 1;
			v_ban_entry->acosc_entry = false;
			v_ban_entry->acosc_penalty_dur = 0;
			if(acosc_penalty_duration > 0)
			{
				v_ban_entry->v_count = cfg.failbancount +1; // set it to a higher level 
				v_ban_entry->acosc_entry = true;
				v_ban_entry->acosc_penalty_dur = acosc_penalty_duration;
			}
			if(info)
				{ v_ban_entry->info = cs_strdup(info); }
			ll_iter_insert(&itr, v_ban_entry);
			cs_debug_mask(D_TRACE, "failban: ban ip %s:%d with timestamp %ld%s%s",
						  cs_inet_ntoa(v_ban_entry->v_ip), v_ban_entry->v_port, v_ban_entry->v_time.time,
						  info ? ", info: " : "", info ? info : "");
		}
	}

	return result;
}

int32_t cs_check_violation(IN_ADDR_T ip, int32_t port)
{
	return cs_check_v(ip, port, 0, NULL, 0);
}

int32_t cs_add_violation_by_ip(IN_ADDR_T ip, int32_t port, char *info)
{
	return cs_check_v(ip, port, 1, info, 0);
}

int32_t cs_add_violation_by_ip_acosc(IN_ADDR_T ip, int32_t port, char *info, int32_t acosc_penalty_duration)
{
	return cs_check_v(ip, port, 1, info, acosc_penalty_duration);
}

void cs_add_violation(struct s_client *cl, char *info)
{
	struct s_module *module = get_module(cl);
	cs_add_violation_by_ip(cl->ip, module->ptab.ports[cl->port_idx].s_port, info);
}

void cs_add_violation_acosc(struct s_client *cl, char *info, int32_t acosc_penalty_duration)
{
	struct s_module *module = get_module(cl);
	cs_add_violation_by_ip_acosc(cl->ip, module->ptab.ports[cl->port_idx].s_port, info, acosc_penalty_duration);
}
