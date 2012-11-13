#ifndef _CSCTAPI_IFD_DB2COM_H_
#define _CSCTAPI_IFD_DB2COM_H_

bool detect_db2com_reader(struct s_reader *reader);
int32_t db2com_init(struct s_reader *reader);
int32_t db2com_get_status(struct s_reader * reader, int32_t *status);

#endif
