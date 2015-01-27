#ifndef MODULE_CAMD35_H_
#define MODULE_CAMD35_H_

int32_t camd35_send(struct s_client *cl, uchar *buf, int32_t buflen);
int32_t camd35_send_without_timeout(struct s_client *cl, uchar *buf, int32_t buflen);
int32_t camd35_tcp_connect(struct s_client *cl);

#endif
