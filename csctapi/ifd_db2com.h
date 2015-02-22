#ifndef _CSCTAPI_IFD_DB2COM_H_
#define _CSCTAPI_IFD_DB2COM_H_

#ifdef CARDREADER_DB2COM
bool detect_db2com_reader(struct s_reader *reader);
extern struct s_cardreader cardreader_db2com;
#else
static inline bool detect_db2com_reader(struct s_reader *UNUSED(reader)) { return false; }
static struct s_cardreader cardreader_db2com;
#endif

#endif
