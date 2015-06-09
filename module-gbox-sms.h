#ifndef MODULE_GBOX_SMS_H_
#define MODULE_GBOX_SMS_H_

#ifdef MODULE_GBOX

#define FILE_GSMS_TXT           "gsms.txt"
#define FILE_GSMS_MSG           "gsms.log"
#define FILE_OSD_MSG            "gsms.osd"
#define FILE_GSMS_ACK           "gsms.ack"
#define FILE_GSMS_NACK          "gsms.nack"

void gbox_init_send_gsms(void);
void write_gsms_msg (struct s_client *cli, uchar *gsms, uint16_t type, uint16_t UNUSED(msglen));
void gbox_send_gsms_ack(struct s_client *cli, uint8_t gsms_prot);
void write_gsms_ack (struct s_client *cli, uint8_t gsms_prot);
void gsms_unavail(void);
void start_sms_sender(void);
void stop_sms_sender(void);

#endif

#endif
