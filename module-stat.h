#include "globals.h"

#ifdef WITH_LB
#include "module-datastruct-llist.h"

void init_stat();

void load_stat_from_file();

void save_stat_to_file();

READER_STAT *get_stat(struct s_reader *rdr, uint16_t caid, uint32_t prid, uint16_t srvid, int16_t ecmlen);

int32_t remove_stat(struct s_reader *rdr, uint16_t caid, uint32_t prid, uint16_t srvid, int16_t ecmlen);

void calc_stat(READER_STAT *stat);

void add_stat(struct s_reader *rdr, ECM_REQUEST *er, int32_t time, int32_t rc);

int32_t get_best_reader(ECM_REQUEST *er);

void clear_reader_stat(struct s_reader *rdr);

void clear_all_stat();

void housekeeping_stat(int32_t force);

void sort_stat(struct s_reader *rdr, int32_t reverse);

#endif
