#include "globals.h"
//#include "module-datastruct-llist.h"
#include "module-datastruct-llist.h"

#define DEFAULT_REOPEN_SECONDS 900
#define DEFAULT_MIN_ECM_COUNT 5
#define DEFAULT_MAX_ECM_COUNT 500
#define DEFAULT_NBEST 1
#define DEFAULT_NFB 1

static pthread_mutex_t stat_busy;

void init_stat();

READER_STAT *get_stat(struct s_reader *rdr, ushort caid, ulong prid, ushort srvid);

int remove_stat(struct s_reader *rdr, ushort caid, ulong prid, ushort srvid);

void calc_stat(READER_STAT *stat);

void add_stat(struct s_reader *rdr, ushort caid, ulong prid, ushort srvid, int time, int rc);

int get_best_reader(ECM_REQUEST *er);

void clear_reader_stat(struct s_reader *rdr);
