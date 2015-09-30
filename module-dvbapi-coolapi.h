#ifndef _MODULE_COOLAPI_H_
#define _MODULE_COOLAPI_H_

int32_t coolapi_set_filter(int32_t fd, int32_t num, int32_t pid, uchar *flt, uchar *mask, int32_t type);
int32_t coolapi_remove_filter(int32_t fd, int32_t num);
int32_t coolapi_open_device(int32_t demux_index, int32_t demux_id);
int32_t coolapi_close_device(int32_t fd);
int32_t coolapi_write_cw(int32_t mask, uint16_t *STREAMpids, int32_t count, ca_descr_t *ca_descr);
int32_t coolapi_get_filter_num(int32_t fd);

#endif
