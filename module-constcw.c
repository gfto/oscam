//FIXME Not checked on threadsafety yet; after checking please remove this line
#include "globals.h"
#ifdef MODULE_CONSTCW
#include "oscam-client.h"
#include "oscam-ecm.h"
#include "oscam-net.h"
#include "oscam-string.h"

#include "openssl/aes.h"

#define OFFSET_MKEY1 4
#define OFFSET_MKEY2 56
#define OFFSET_EXPIRE_MKEY1 36
#define OFFSET_EXPIRE_MKEY2 88

#define OFFSET_CWKEY1 33
#define OFFSET_CWKEY2 49

#define touInt16(__data) (((&__data)[1] << 8) | __data)

static int32_t pserver;

unsigned long parse_ts(uchar * data) {
struct tm t;
time_t t_of_day;
t.tm_year = touInt16(data[0]) - 1900; //2014-1900
t.tm_mon = touInt16(data[2]) - 1; // Month, 0 - jan
t.tm_mday = touInt16(data[4]); // Day of the month
t.tm_hour = touInt16(data[6]);
t.tm_min = touInt16(data[8]);
t.tm_sec = touInt16(data[10]);
t.tm_isdst = -1; // Is DST on? 1 = yes, 0 = no, -1 = unknown
t_of_day = mktime(&t);

return (unsigned long) t_of_day;
}

int32_t constcw_file_available(void) {
    FILE *fp;

    fp = fopen(cur_client()->reader->device, "r");
    if (!fp) {
        return (0);
    }
    fclose(fp);
    return (1);
}

int32_t constcw_analyse_file(uchar * dcw, uchar * ECM) {
    FILE *fp;
    uchar token[108];
    uchar * mkey;
    uint32_t t = 0;
    AES_KEY aesmkey;
    uchar table = ECM[0];
    uint16_t channel = (ECM[18] << 8) + ECM[19];
    unsigned long time_now, time_mkey1, time_mkey2;
    fp = fopen(cur_client()->reader->device, "r");
    if (!fp) {
        cs_log("[CONSTKB] Could not open file");
        return (0);
    }
    cs_log("[CONSTKB] Find control word for Channel %d table 0x%02X", channel,
            table);

    fseek(fp, 4, SEEK_SET);
    while (fread(token, 108, 1, fp)) {
        if ((uint16_t) ((token[t + 1] << 8) + token[t]) == channel) {
            cs_log("[CONSTKB] Master keys found for Channel: %d", channel);
            time_now = (unsigned long)time(NULL);
            time_mkey1 = parse_ts(token + OFFSET_EXPIRE_MKEY1);
                        
            if (difftime(time_mkey1, time_now) > 0) { // Check expire date mkey 1
                cs_log("[CONSTKB] Master key 1 selected");
                mkey = token + OFFSET_MKEY1;
            } else {                
                time_mkey2 = parse_ts(token + OFFSET_EXPIRE_MKEY2);        
                if (difftime(time_mkey2, time_now) > 0) { // Check expire date mkey 2
                    cs_log("[CONSTKB] Master key 2 selected");
                    if(difftime(time_mkey2, time_now) < 86400) {
                        cs_log("[CONSTKB] Warning: Master keys for Channel: %d will expire in %lu seconds", channel, (unsigned long)difftime(time_mkey2, time_now));
                    }
                    mkey = token + OFFSET_MKEY2;
                } else {
                    cs_log("[CONSTKB] Keyblock is to old");
                    return 0;
                }
            }
            AES_set_decrypt_key(mkey, 128, &aesmkey);

            for (t = 0; t < 48; t += 16) {
                AES_ecb_encrypt(&ECM[24 + t], &ECM[24 + t], &aesmkey,
                AES_DECRYPT);
            }
            if (memcmp(&ECM[24], "CEB", 3) == 0) {
                cs_log("[CONSTKB] ECM decrypt check passed");
            } else {
                cs_log(
                        "[CONSTKB] ECM decrypt failed, wrong master key or unknown format");
                fclose(fp);
                return 0;
            }
            if (table == 0x80) {
                for (t = 0; t < 16; t++) {
                    dcw[t] = ECM[t + OFFSET_CWKEY1];
                }
            }
            else {
                for (t = 0; t < 16; t++) {
                    dcw[t] = ECM[t + OFFSET_CWKEY2];
                }
            }
            fclose(fp);
            return 1;
        }
    }
    cs_log("[CONSTKB] No Master key found for channel: %d, cannot decrypt ECM",
            channel);
    fclose(fp);
    return 0;
}
//************************************************************************************************************************
//* client/server common functions
//************************************************************************************************************************
static int32_t constcw_recv(struct s_client *client, uchar *buf, int32_t l) {
    int32_t ret;

    if (!client->udp_fd) {
        return (-9);
    }
    ret = read(client->udp_fd, buf, l);
    if (ret < 1) {
        return (-1);
    }
    client->last = time(NULL);
    return (ret);
}

//************************************************************************************************************************
//*       client functions
//************************************************************************************************************************
int32_t constcw_client_init(struct s_client *client) {
    int32_t fdp[2];
    FILE *fp;
    uint32_t tokens;
    uchar channels[4];

    client->pfd = 0;
    if (socketpair(PF_LOCAL, SOCK_STREAM, 0, fdp)) {
        cs_log("[CONSTKB] Socket creation failed (%s)", strerror(errno));
        return 1;
    }
    client->udp_fd = fdp[0];
    pserver = fdp[1];

    memset((char *) &client->udp_sa, 0, sizeof(client->udp_sa));
    SIN_GET_FAMILY(client->udp_sa) = AF_INET;

    cs_log("[CONSTKB] local reader: %s (file: %s)", client->reader->label,
            client->reader->device);

    client->pfd = client->udp_fd;

    fp = fopen(cur_client()->reader->device, "r");
    if (!fp) {
        return (1);
    }

    if (fread(channels, 4, 1, fp) < 1) {
        cs_log("[CONSTKB] Unable to read from file");
        fclose(fp);
        return 1;
    }
    tokens = (channels[3] << 24) + (channels[2] << 16) + (channels[1] << 8)
            + channels[0];

    cs_log("[CONSTKB] Channels expected in block: %d", tokens);

    client->reader->tcp_connected = 2;
    client->reader->card_status = CARD_INSERTED;

    fclose(fp);
    return (0);
}

static int32_t constcw_send_ecm(struct s_client *client, ECM_REQUEST *er,
        uchar *UNUSED(msgbuf)) {
    time_t t;
    struct s_reader *rdr = client->reader;
    uchar cw[16];

    t = time(NULL);
    // Check if DCW exist in the files
    if (constcw_analyse_file(cw, er->ecm) == 0) {
        write_ecm_answer(rdr, er, E_NOTFOUND, (E1_READER << 4 | E2_SID), NULL,
        NULL);
    } else {
        write_ecm_answer(rdr, er, E_FOUND, 0, cw, NULL);
    }

    client->last = t;
    rdr->last_g = t;
    return (0);
}

static int32_t constcw_recv_chk(struct s_client *UNUSED(client),
        uchar *UNUSED(dcw), int32_t *rc, uchar *UNUSED(buf), int32_t UNUSED(n)) {
    *rc = 0;
    return (-1);
}

void module_constcw(struct s_module *ph) {
    ph->desc = "CONSTKB";
    ph->type = MOD_NO_CONN;
    ph->listenertype = LIS_CONSTCW;
    ph->recv = constcw_recv;

    ph->c_init = constcw_client_init;
    ph->c_recv_chk = constcw_recv_chk;
    ph->c_send_ecm = constcw_send_ecm;
    ph->num = R_CONSTCW;
}
#endif