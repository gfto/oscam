#include "globals.h"
#include "module-datastruct-llist.h"

void init_stat();

void load_stat_from_file();

void save_stat_to_file();

READER_STAT *get_stat(struct s_reader *rdr, ushort caid, ulong prid, ushort srvid);

int remove_stat(struct s_reader *rdr, ushort caid, ulong prid, ushort srvid);

void calc_stat(READER_STAT *stat);

void add_stat(struct s_reader *rdr, ECM_REQUEST *er, int time, int rc);

int get_best_reader(ECM_REQUEST *er);

void clear_reader_stat(struct s_reader *rdr);

void clear_all_stat();

void housekeeping_stat(int force);
