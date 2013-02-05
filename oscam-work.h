#ifndef OSCAM_WORK_H_
#define OSCAM_WORK_H_

enum actions {
	// Reader action
	ACTION_READER_IDLE         = 1,
	ACTION_READER_REMOTE       = 2,
	ACTION_READER_RESET        = 4,
	ACTION_READER_ECM_REQUEST  = 5,
	ACTION_READER_EMM          = 6,
	ACTION_READER_CARDINFO     = 7,
	ACTION_READER_INIT         = 8,
	ACTION_READER_RESTART      = 9,
	ACTION_READER_RESET_FAST   = 10,
	ACTION_READER_CHECK_HEALTH = 11,
	// Client actions
	ACTION_CLIENT_UDP          = 22,
	ACTION_CLIENT_TCP          = 23,
	ACTION_CLIENT_ECM_ANSWER   = 24,
	ACTION_CLIENT_KILL         = 25,
	ACTION_CLIENT_INIT         = 26,
	ACTION_CLIENT_IDLE         = 27,
#ifdef CS_CACHEEX
	ACTION_CACHE_PUSH_OUT      = 28,
#endif
};

#define ACTION_CLIENT_FIRST 20 // This just marks where client actions start

int32_t add_job(struct s_client *cl, enum actions action, void *ptr, int32_t len);
void free_joblist(struct s_client *cl);

#endif
