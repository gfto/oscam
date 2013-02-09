#ifndef OSCAM_WORK_H_
#define OSCAM_WORK_H_

enum actions {
	// Reader action
	ACTION_READER_IDLE         = 1,		// wr01
	ACTION_READER_REMOTE       = 2,		// wr02
	ACTION_READER_RESET        = 4,		// wr04
	ACTION_READER_ECM_REQUEST  = 5,		// wr05
	ACTION_READER_EMM          = 6,		// wr06
	ACTION_READER_CARDINFO     = 7,		// wr07
	ACTION_READER_INIT         = 8,		// wr08
	ACTION_READER_RESTART      = 9,		// wr09
	ACTION_READER_RESET_FAST   = 10,	// wr10
	ACTION_READER_CHECK_HEALTH = 11,	// wr11
	// Client actions
	ACTION_CLIENT_UDP          = 22,	// wc22
	ACTION_CLIENT_TCP          = 23,	// wc23
	ACTION_CLIENT_ECM_ANSWER   = 24,	// wc24
	ACTION_CLIENT_KILL         = 25,	// wc25
	ACTION_CLIENT_INIT         = 26,	// wc26
	ACTION_CLIENT_IDLE         = 27,	// wc27
#ifdef CS_CACHEEX
	ACTION_CACHE_PUSH_OUT      = 28,	// wc28
#endif
	ACTION_CLIENT_SEND_MSG     = 29,	// wc29
};

#define ACTION_CLIENT_FIRST 20 // This just marks where client actions start

int32_t add_job(struct s_client *cl, enum actions action, void *ptr, int32_t len);
void free_joblist(struct s_client *cl);

#endif
