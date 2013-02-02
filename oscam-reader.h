#ifndef _OSCAM_READER_H_
#define _OSCAM_READER_H_

char *reader_get_type_desc(struct s_reader * rdr, int32_t extended);
void hexserial_to_newcamd(uchar *source, uchar *dest, uint16_t caid);
void newcamd_to_hexserial(uchar *source, uchar *dest, uint16_t caid);
struct s_reader *get_reader_by_label(char *lbl);
bool hexserialset(struct s_reader *rdr);
void cs_card_info(void);
int32_t reader_init(struct s_reader *reader);
void remove_reader_from_active(struct s_reader *rdr);
int32_t restart_cardreader(struct s_reader *rdr, int32_t restart);
void init_cardreader(void);

#endif
