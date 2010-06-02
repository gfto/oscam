#include "globals.h"
#include "module-obj-llist.h"

LLIST *reader_stat[CS_MAXREADER];
extern struct s_reader *reader;

READER_STAT *get_stat(int ridx, ushort caid, ulong prid, ushort srvid);

int remove_stat(int ridx, ushort caid, ulong prid, ushort srvid);

void calc_stat(READER_STAT *stat);

void add_stat(int ridx, ushort caid, ulong prid, ushort srvid, int time, int rc);

void add_reader_stat(ADD_READER_STAT *stat);

int get_best_reader(ushort caid, ulong prid, ushort srvid);
