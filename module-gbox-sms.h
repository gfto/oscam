#ifndef MODULE_GBOX_SMS_H_
#define MODULE_GBOX_SMS_H_

#ifdef MODULE_GBOX

#if defined(__CYGWIN__)
#define FILE_GSMS_TXT           "C:/tmp/gsms.txt"
#define FILE_GSMS_MSG           "C:/tmp/gsms.log"
#define FILE_OSD_MSG            "C:/tmp/osd.msg"
#define FILE_GSMS_ACK           "C:/tmp/gsms.ack"
#define FILE_GSMS_NACK          "C:/tmp/gsms.nack"
#else
#define FILE_GSMS_TXT           "/tmp/gsms.txt"
#define FILE_GSMS_MSG           "/tmp/gsms.log"
#define FILE_OSD_MSG            "/tmp/osd.msg"
#define FILE_GSMS_ACK           "/tmp/gsms.ack"
#define FILE_GSMS_NACK          "/tmp/gsms.nack"
#endif

void gbox_init_send_gsms(void);
void write_gsms_msg (struct s_client *cli, uchar *gsms, uint16_t type, uint16_t UNUSED(msglen));
void gbox_send_gsms_ack(struct s_client *cli, uint8_t gsms_prot);
void write_gsms_ack (struct s_client *cli, uint8_t gsms_prot);
void gsms_unavail(void);
#endif

#endif
