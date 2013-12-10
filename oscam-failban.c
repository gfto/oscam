#include "globals.h"
#include "oscam-net.h"
#include "oscam-string.h"
#include "oscam-time.h"

static int32_t cs_check_v(IN_ADDR_T ip, int32_t port, int32_t add, char *info)
{
	int32_t result = 0;

	if(!cfg.failbantime)
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
		if(gone >= ftime) // entry out of time->remove
		{
			free(v_ban_entry->info);
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
					cs_debug_mask(D_TRACE, "failban: banned ip %s:%d - %d seconds left%s%s",
								  cs_inet_ntoa(v_ban_entry->v_ip), v_ban_entry->v_port,
								  ((ftime - gone)/1000), info ? ", info: " : "", info ? info : "");
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
	return cs_check_v(ip, port, 0, NULL);
}

int32_t cs_add_violation_by_ip(IN_ADDR_T ip, int32_t port, char *info)
{
	return cs_check_v(ip, port, 1, info);
}

void cs_add_violation(struct s_client *cl, char *info)
{
	struct s_module *module = get_module(cl);
	cs_add_violation_by_ip(cl->ip, module->ptab.ports[cl->port_idx].s_port, info);
}
